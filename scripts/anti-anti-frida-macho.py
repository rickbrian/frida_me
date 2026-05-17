#!/usr/bin/env python3
"""
iOS Stealth Frida - Mach-O Binary Post-Processor

基于源码分析的精确替换策略：
  ✅ 线程名 — 被检测 app 可通过 thread_info 发现
  ✅ 文件路径/进程名 — 被检测 app 可通过 fs/procfs 发现
  ✅ 导出符号 frida_agent_main — 保持 server↔agent 一致即可
  ❌ D-Bus 接口名 (re.frida.*) — 客户端硬编码，改了断通信
  ❌ D-Bus 对象路径 (/re/frida/*) — 同上
  ❌ GObject 类型名 (FridaScriptEngine, GumScript) — 影响类型系统
  ❌ 全局 frida→fs179 — 太多协议内部字符串，无法安全枚举
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

    # ── 1. 线程名（app 可通过 thread_info/task_threads 枚举发现） ──

    total += patch(data, b"gum-js-loop\x00", b"RunLoopMain\x00", "gum-js-loop(12)")
    total += patch(data, b"gmain\x00", b"GCDwk\x00", "gmain(6)")
    total += patch(data, b"gdbus\x00", b"IOSvc\x00", "gdbus(6)")
    total += patch(data, b"pool-frida\x00", b"pool-cfrun\x00", "pool-frida(11)")
    total += patch(data, b"frida-main-loop\x00", b"CFRunLoopThread\x00", "frida-main-loop(16)")

    # ── 2. 文件路径 / 进程名（app 可通过 fs/procfs/dyld 发现） ──

    total += patch(data, b"frida-server\x00", b"fs179-server\x00", "frida-server(13)")
    total += patch(data, b"frida-agent.dylib", b"fs179-agent.dylib", "frida-agent.dylib(17)")
    total += patch(data, b"frida-helper\x00", b"fs179-helper\x00", "frida-helper(13)")
    total += patch(data, b"frida-1.0", b"fs179-1.0", "frida-1.0(9)")

    # ── 3. 导出符号（server 用 dlsym 查找 agent 入口点） ──
    #    server 和 agent.dylib 都会被本脚本处理，保持一致

    total += patch(data, b"frida_agent_main", b"fs179_agent_main", "frida_agent_main(16)")

    # ── 不做的事（源码分析依据） ──
    #
    # D-Bus 接口名 "re.frida.HostSession17" 等:
    #   → [DBus (name=...)] 是 Vala 编译期注解，客户端 frida-core
    #     硬编码相同字符串，单改服务端 GDBus 接口匹配失败
    #
    # D-Bus ObjectPath "/re/frida/HostSession" 等:
    #   → 同上，客户端 get_proxy 使用相同路径
    #
    # ServerGuid "6769746875622e636f6d2f6672696461":
    #   → D-Bus peer-to-peer 认证握手必需
    #
    # GObject 类型名 "FridaScriptEngine" / "GumScript":
    #   → g_type_register_static 注册名，改了影响 GLib 类型系统
    #
    # 全局 frida→fs179:
    #   → Frida 内部有大量 frida_ 前缀的函数指针、属性名、quark
    #     用于 D-Bus 方法分发，无法安全枚举所有保护项
    #
    # 以上字符串仅存在于 server/agent 进程内存中
    # iOS 沙盒机制阻止 app 扫描其他进程内存

    with open(filepath, "wb") as f:
        f.write(data)

    print(f"[*] Done: {total} patches applied to {os.path.basename(filepath)}")


if __name__ == "__main__":
    main()
