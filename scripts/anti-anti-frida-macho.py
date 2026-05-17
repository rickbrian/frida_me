#!/usr/bin/env python3
"""
iOS Stealth Frida - Mach-O Binary Post-Processor

安全原则：
  - 精确替换已知的检测目标字符串（线程名、文件路径、导出符号）
  - 上下文感知的 frida/FRIDA 全局替换：跳过 D-Bus 接口名等协议关键字符串
  - 绝不反转 GLib 内部类型名
"""
import sys
import os


def patch(data: bytearray, old: bytes, new: bytes, tag: str = "") -> int:
    assert len(old) == len(new), f"length mismatch: {len(old)} vs {len(new)}"
    count = 0
    pos = 0
    while True:
        idx = data.find(old, pos)
        if idx == -1:
            break
        data[idx : idx + len(old)] = new
        pos = idx + len(new)
        count += 1
    if count > 0:
        label = tag or old.decode("utf-8", errors="replace")
        print(f"    {label} → {new.decode('utf-8', errors='replace')} ({count}x)")
    return count


def smart_patch_frida(data: bytearray) -> int:
    """
    Replace 'frida' with 'fs179' ONLY when NOT part of protocol-critical strings.
    Skips: re.frida.* / com.frida.* / D-Bus interfaces / GLib internals.
    """
    target = b"frida"
    replacement = b"fs179"
    skip_count = 0
    replace_count = 0
    pos = 0

    while True:
        idx = data.find(target, pos)
        if idx == -1:
            break

        skip = False

        # Check prefix context (bytes before 'frida')
        prefix = bytes(data[max(0, idx - 10):idx])

        # D-Bus interface: "re.frida.XXX" — DO NOT touch
        if prefix.endswith(b"re."):
            skip = True
        # Mach service: "com.frida.XXX" — DO NOT touch
        elif prefix.endswith(b"com."):
            skip = True

        # Check suffix context (bytes after 'frida')
        suffix = bytes(data[idx + 5:idx + 25])

        # frida:rpc — already base64'd in source, shouldn't be here,
        # but if it is, don't touch
        if suffix.startswith(b":rpc"):
            skip = True
        # frida_agent_main — handled separately
        if suffix.startswith(b"_agent_main"):
            skip = True

        if skip:
            skip_count += 1
            pos = idx + 5
        else:
            data[idx:idx + 5] = replacement
            replace_count += 1
            pos = idx + 5

    if replace_count > 0:
        print(f"    frida→fs179 (contextual: {replace_count} replaced, {skip_count} protected)")
    return replace_count


def smart_patch_FRIDA(data: bytearray) -> int:
    """Same as above but for uppercase FRIDA."""
    target = b"FRIDA"
    replacement = b"FS179"
    count = 0
    pos = 0

    while True:
        idx = data.find(target, pos)
        if idx == -1:
            break

        # FRIDA in env vars like FRIDA_VERBOSE etc — safe to replace
        # FRIDA in error messages — safe to replace
        # No known protocol-critical uppercase FRIDA strings
        data[idx:idx + 5] = replacement
        count += 1
        pos = idx + 5

    if count > 0:
        print(f"    FRIDA→FS179 ({count}x)")
    return count


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <binary> [binary2 ...]")
        sys.exit(1)

    for filepath in sys.argv[1:]:
        if not os.path.isfile(filepath):
            print(f"[!] Not found: {filepath}")
            continue
        process_binary(filepath)


def process_binary(filepath):
    print(f"\n[*] Patching: {filepath}")
    with open(filepath, "rb") as f:
        data = bytearray(f.read())

    total = 0

    # ── 1. 线程名 ──

    total += patch(data, b"gum-js-loop\x00", b"RunLoopMain\x00", "gum-js-loop(12)")
    total += patch(data, b"gmain\x00", b"GCDwk\x00", "gmain(6)")
    total += patch(data, b"gdbus\x00", b"IOSvc\x00", "gdbus(6)")
    total += patch(data, b"pool-frida\x00", b"pool-cfrun\x00", "pool-frida(11)")

    # ── 2. 文件路径 / 进程名 ──

    total += patch(data, b"frida-server\x00", b"fs179-server\x00", "frida-server(13)")
    total += patch(data, b"frida-agent.dylib", b"fs179-agent.dylib", "frida-agent.dylib(17)")
    total += patch(data, b"frida-helper\x00", b"fs179-helper\x00", "frida-helper(13)")
    total += patch(data, b"frida-1.0", b"fs179-1.0", "frida-1.0(9)")

    # ── 3. 导出符号 ──

    total += patch(data, b"frida_agent_main", b"fs179_agent_main", "frida_agent_main(16)")

    # ── 4. 可识别内部字符串（同长度中性替换，不反转） ──

    total += patch(data, b"FridaScriptEngine", b"NativeJSRuntime\x00\x00", "FridaScriptEngine(17)")
    total += patch(data, b"GumScript", b"JsEngine", "GumScript→JsEngine(9)")

    # ── 5. 上下文感知的全局 frida/FRIDA 替换 ──
    #    跳过 D-Bus 接口名 (re.frida.*) 和 Mach 服务名 (com.frida.*)
    #    这些是客户端-服务端通信必需的，改了就断

    total += smart_patch_frida(data)
    total += smart_patch_FRIDA(data)

    with open(filepath, "wb") as f:
        f.write(data)

    print(f"[*] Done: {total} patches applied to {os.path.basename(filepath)}")


if __name__ == "__main__":
    main()
