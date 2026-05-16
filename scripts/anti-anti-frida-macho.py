#!/usr/bin/env python3
"""
iOS Stealth Frida - Mach-O Binary Post-Processor

对编译产物做同长度字节替换，消除 frida 特征字符串。
不需要 LIEF / install_name_tool，纯 Python 原始字节操作。
替换后需 codesign 重签。
"""
import sys
import os
import random
import string


def rand_str(n, charset=string.ascii_lowercase):
    return "".join(random.choice(charset) for _ in range(n))


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
    r5 = "fs179"
    r5u = "FS179"

    # ── 1. 线程名（source 级已改，这里兜底 GLib 内部残留） ──

    total += patch(data, b"gum-js-loop", b"AUXSessWork", "gum-js-loop(11)")

    total += patch(data, b"gmain\x00", b"GCDwk\x00", "gmain(null-term)")
    total += patch(data, b"gdbus\x00", b"IOSvc\x00", "gdbus(null-term)")

    # pool-frida 已通过 prgname 改掉，兜底
    total += patch(data, b"pool-frida\x00", b"pool-cfrun\x00", "pool-frida(11)")

    # ── 2. 文件名 / 路径名 ──

    total += patch(data, b"frida-server", b"fs179-server", "frida-server(12)")
    total += patch(data, b"frida-agent",  b"fs179-agent",  "frida-agent(11)")
    total += patch(data, b"frida-helper", b"fs179-helper", "frida-helper(12)")

    # ── 3. 符号名风格 ──

    total += patch(data, b"frida_agent", b"fs179_agent", "frida_agent(11)")
    total += patch(data, b"frida_server", b"fs179_server", "frida_server(12)")

    # ── 4. Bundle ID / 服务标识 ──

    total += patch(data, b"re.frida.server", b"re.apple.srvagd", "re.frida.server(15)")
    total += patch(data, b"com.frida.Agent", b"com.apple.Aqent", "com.frida.Agent(15)")

    # ── 5. 可识别字符串 → 反转（同长度，不破坏功能） ──

    reverse_targets = [
        b"FridaScriptEngine",
        b"GLib-GIO",
        b"GDBusProxy",
        b"GumScript",
    ]
    for t in reverse_targets:
        total += patch(data, t, t[::-1], f"reverse({t.decode()})")

    # ── 6. 剩余 frida / FRIDA 关键字 ──
    #    放在最后，避免覆盖上面已处理的精确匹配

    total += patch(data, b"frida", r5.encode(), f"frida→{r5}")
    total += patch(data, b"FRIDA", r5u.encode(), f"FRIDA→{r5u}")

    with open(filepath, "wb") as f:
        f.write(data)

    print(f"[*] Done: {total} patches applied to {os.path.basename(filepath)}")


if __name__ == "__main__":
    main()
