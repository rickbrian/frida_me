#!/usr/bin/env python3
"""
iOS Stealth Frida - Mach-O Binary Post-Processor

对编译产物做同长度字节替换，消除 frida 特征字符串。
不需要 LIEF / install_name_tool，纯 Python 原始字节操作。
替换后需 codesign 重签。

安全原则：
  - 只替换会被 app 检测到的"外部可见"字符串（进程名、线程名、文件路径、端口名等）
  - 绝不动 D-Bus 接口名、RPC 协议字符串、GLib 内部类型名
  - 绝不做全局 frida → xxx 盲替换，否则会破坏客户端-服务端通信
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

    # ═══════════════════════════════════════════════════════════════
    # 1. 线程名 — app 可以通过 proc_pidinfo / thread_info 枚举
    #    这些是"外部可见"的，必须替换
    # ═══════════════════════════════════════════════════════════════

    total += patch(data, b"gum-js-loop\x00", b"CFRunLoopRun\x00", "gum-js-loop(12)")
    total += patch(data, b"gmain\x00", b"GCDwk\x00", "gmain(null-term)")
    total += patch(data, b"gdbus\x00", b"IOSvc\x00", "gdbus(null-term)")
    total += patch(data, b"pool-frida\x00", b"pool-cfrun\x00", "pool-frida(11)")

    # ═══════════════════════════════════════════════════════════════
    # 2. 进程名 / 文件路径 — app 可以通过 sysctl / proc 枚举
    #    这些只改"用于显示/检测"的字符串，不改 D-Bus 接口
    # ═══════════════════════════════════════════════════════════════

    total += patch(data, b"frida-server\x00", b"fs179-server\x00", "frida-server(null)")
    total += patch(data, b"frida-agent.dylib", b"fs179-agent.dylib", "frida-agent.dylib(17)")
    total += patch(data, b"frida-helper\x00", b"fs179-helper\x00", "frida-helper(null)")

    # 编译产物中硬编码的库搜索路径
    total += patch(data, b"frida-1.0", b"fs179-1.0", "frida-1.0(dir)")

    # ═══════════════════════════════════════════════════════════════
    # 3. 符号导出名 — app 可以 dlsym 检测
    # ═══════════════════════════════════════════════════════════════

    total += patch(data, b"frida_agent_main", b"fs179_agent_main", "frida_agent_main(16)")

    # ═══════════════════════════════════════════════════════════════
    # 以下字符串 **绝对不能动**，否则破坏通信：
    #   - re.frida.HostSession (D-Bus interface, 客户端按此名连接)
    #   - re.frida.AgentSession
    #   - re.frida.Portal
    #   - re.frida.TransportBroker
    #   - com.frida.Agent (Mach service)
    #   - frida:rpc (已在源码层 base64 混淆，二进制里没有明文)
    #   - GLib-GIO, GDBusProxy 等 GLib 内部类型名
    #   - FRIDA_*, frida_* 内部符号（客户端需要匹配）
    #
    # 不做全局 frida → fs179 盲替换！
    # ═══════════════════════════════════════════════════════════════

    with open(filepath, "wb") as f:
        f.write(data)

    print(f"[*] Done: {total} patches applied to {os.path.basename(filepath)}")


if __name__ == "__main__":
    main()
