#!/bin/bash
set -euo pipefail

FRIDA_DIR="${1:?Usage: $0 <frida-source-dir>}"

GUM_DIR="$FRIDA_DIR/subprojects/frida-gum"
CORE_DIR="$FRIDA_DIR/subprojects/frida-core"

echo "============================================"
echo " iOS Stealth Frida - Source Patches"
echo " ref: STEALTH_PATCHES.md (Android) adapted"
echo "============================================"

# ──────────────────────────────────────────────
# 1. GLib prgname — 消除 pool-frida 线程名
# ──────────────────────────────────────────────
if [ -f "$GUM_DIR/gum/gum.c" ]; then
    sed -i '' 's/g_set_prgname ("frida")/g_set_prgname ("com.apple.WebKit")/' "$GUM_DIR/gum/gum.c"
    echo "[+] gum.c: g_set_prgname → com.apple.WebKit"
fi

# ──────────────────────────────────────────────
# 2. 线程名重命名 (STEALTH_PATCHES §2.1)
# ──────────────────────────────────────────────
if [ -f "$GUM_DIR/bindings/gumjs/gumscriptscheduler.c" ]; then
    sed -i '' 's/"gum-js-loop"/"com.apple.CFSocket.private"/' \
        "$GUM_DIR/bindings/gumjs/gumscriptscheduler.c"
    echo "[+] gumscriptscheduler.c: gum-js-loop → com.apple.CFSocket.private"
fi

if [ -f "$CORE_DIR/lib/agent/agent.vala" ]; then
    sed -i '' 's/"frida-eternal-agent"/"com.apple.CFStream"/' "$CORE_DIR/lib/agent/agent.vala"
    sed -i '' 's/"frida-agent-emulated"/"com.apple.CFStream"/' "$CORE_DIR/lib/agent/agent.vala"
    echo "[+] agent.vala: thread names → com.apple.CFStream"
fi

if [ -f "$CORE_DIR/lib/base/p2p.vala" ]; then
    sed -i '' 's/"frida-generate-certificate"/"com.apple.securityd"/' "$CORE_DIR/lib/base/p2p.vala"
    echo "[+] p2p.vala: frida-generate-certificate → com.apple.securityd"
fi

# ──────────────────────────────────────────────
# 3. frida:rpc 协议标识符 base64 混淆
#    运行时 = "frida:rpc"（兼容官方客户端）
#    二进制无明文
# ──────────────────────────────────────────────
python3 - "$CORE_DIR/lib/base/rpc.vala" << 'PYEOF'
import sys, os

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    print(f"[!] {filepath} not found, skipping rpc patch")
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

helper = """
\t\tprivate static string _rpc_tag () {
\t\t\treturn (string) GLib.Base64.decode ((string) GLib.Base64.decode ("Wm5KcFpHRTZjbkJq"));
\t\t}
"""

src = src.replace(
    "Object (peer: peer);\n\t\t}",
    "Object (peer: peer);\n\t\t}\n" + helper,
    1,
)

src = src.replace(
    '.add_string_value ("frida:rpc")',
    '.add_string_value (_rpc_tag ())',
)
src = src.replace(
    'json.index_of ("\\\"frida:rpc\\\"")',
    'json.index_of ("\\\"" + _rpc_tag () + "\\\"")',
)
src = src.replace('type != "frida:rpc"', 'type != _rpc_tag ()')
src = src.replace('type == "frida:rpc"', 'type == _rpc_tag ()')

with open(filepath, "w") as f:
    f.write(src)

print("[+] rpc.vala: frida:rpc → base64 obfuscation (runtime compatible)")
PYEOF

# ──────────────────────────────────────────────
# 4. frida-glue.c g_set_prgname
# ──────────────────────────────────────────────
if [ -f "$CORE_DIR/src/frida-glue.c" ]; then
    python3 - "$CORE_DIR/src/frida-glue.c" << 'PYEOF'
import sys, os

filepath = sys.argv[1]
with open(filepath, "r") as f:
    src = f.read()

if 'g_set_prgname' not in src:
    lines = src.split('\n')
    for i, line in enumerate(lines):
        if 'g_io_module_openssl_register' in line:
            indent = '    '
            lines.insert(i + 2, f'{indent}g_set_prgname ("com.apple.WebKit");')
            break
    src = '\n'.join(lines)
else:
    import re
    src = re.sub(
        r'g_set_prgname\s*\(\s*"[^"]*"\s*\)',
        'g_set_prgname ("com.apple.WebKit")',
        src,
    )

with open(filepath, "w") as f:
    f.write(src)

print("[+] frida-glue.c: g_set_prgname → com.apple.WebKit")
PYEOF
fi

# ──────────────────────────────────────────────
# 5. ExitMonitor 禁用 (STEALTH_PATCHES §1.2)
#    去掉 exit/abort 的 inline hook → 无 rwxp 页
# ──────────────────────────────────────────────
python3 - "$CORE_DIR/lib/agent/agent.vala" << 'PYEOF'
import sys, os

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

src = src.replace(
    "var exit_monitor = new ExitMonitor (this);",
    "ExitMonitor? exit_monitor = null; // stealth: disabled",
)
src = src.replace(
    "exit_monitor = new ExitMonitor (this);",
    "exit_monitor = null; // stealth: disabled",
)

with open(filepath, "w") as f:
    f.write(src)

print("[+] agent.vala: ExitMonitor disabled")
PYEOF

# ──────────────────────────────────────────────
# 6. Instruction.parse() 不再 mprotect (STEALTH_PATCHES §6.5)
#    parse 只是反汇编，不需要写入/执行权限
#    原代码会把 r-xp 页改成 rwxp，留下检测特征
# ──────────────────────────────────────────────
python3 - "$GUM_DIR" << 'PYEOF'
import sys, os, re

gum_dir = sys.argv[1]
patched = 0

for subpath in [
    "bindings/gumjs/gumquickinstruction.c",
    "bindings/gumjs/gumv8instruction.cpp",
]:
    filepath = os.path.join(gum_dir, subpath)
    if not os.path.isfile(filepath):
        continue

    with open(filepath, "r") as f:
        src = f.read()

    new_src = re.sub(
        r'(\s*)(gum_ensure_code_readable\s*\(\s*GSIZE_TO_POINTER\s*\(address\).*?\);)',
        r'\1/* stealth: disabled to avoid rwxp */\n\1/* \2 */',
        src,
    )

    if new_src != src:
        with open(filepath, "w") as f:
            f.write(new_src)
        patched += 1
        print(f"[+] {os.path.basename(filepath)}: gum_ensure_code_readable disabled in parse()")

if patched == 0:
    print("[~] Instruction.parse mprotect patch: no matching files found (may not apply to this version)")
PYEOF

# ──────────────────────────────────────────────
# 7. Exceptor signal hooks 禁用 (STEALTH_PATCHES §1.1)
#    gumexceptor-posix.c 的 signal/sigaction hook
#    在 iOS 上会留下 inline hook 的 rwxp 痕迹
# ──────────────────────────────────────────────
python3 - "$GUM_DIR/gum/backend-posix/gumexceptor-posix.c" << 'PYEOF'
import sys, os, re

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    print("[~] gumexceptor-posix.c not found, skipping")
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

count = 0

for func_name in ["gum_exceptor_backend_attach", "gum_exceptor_backend_detach"]:
    pattern = re.compile(
        r'(static\s+\w+\s+' + func_name + r'\s*\([^)]*\)\s*\{)',
        re.DOTALL,
    )
    match = pattern.search(src)
    if match:
        insert_pos = match.end()
        guard = "\n  return; /* stealth: disable signal hooks */"
        if guard not in src[insert_pos:insert_pos+100]:
            src = src[:insert_pos] + guard + src[insert_pos:]
            count += 1

if count > 0:
    with open(filepath, "w") as f:
        f.write(src)
    print(f"[+] gumexceptor-posix.c: {count} signal hook functions disabled")
else:
    print("[~] gumexceptor-posix.c: no matching functions found")
PYEOF

# ──────────────────────────────────────────────
# 8. D-Bus 接口名混淆 — 二进制中不出现 "re.frida." 明文
#    运行时用 base64 还原，兼容官方客户端
# ──────────────────────────────────────────────
python3 - "$CORE_DIR" << 'PYEOF'
import sys, os, base64, re

core_dir = sys.argv[1]

iface_map = {
    "re.frida.HostSession": None,
    "re.frida.AgentSession": None,
    "re.frida.AgentController": None,
    "re.frida.TransportBroker": None,
    "re.frida.PortalSession": None,
    "re.frida.BusSession": None,
    "re.frida.AuthenticationService": None,
}

for name in iface_map:
    b64 = base64.b64encode(name.encode()).decode()
    iface_map[name] = b64

patched_files = 0
for root, dirs, files in os.walk(core_dir):
    dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "build")]
    for fname in files:
        if not fname.endswith(".vala"):
            continue
        fpath = os.path.join(root, fname)
        with open(fpath, "r") as f:
            src = f.read()

        changed = False
        for iface_name, b64 in iface_map.items():
            old = f'"{iface_name}"'
            new = f'(string) GLib.Base64.decode ("{b64}")'
            if old in src:
                src = src.replace(old, new)
                changed = True

        if changed:
            with open(fpath, "w") as f:
                f.write(src)
            patched_files += 1
            print(f"[+] {os.path.relpath(fpath, core_dir)}: D-Bus interface names → base64")

if patched_files == 0:
    print("[~] D-Bus interface obfuscation: no matching .vala files found")
else:
    print(f"[+] D-Bus interface obfuscation: {patched_files} files patched")
PYEOF

# ──────────────────────────────────────────────
# 9. Agent dylib 临时文件名随机化
# ──────────────────────────────────────────────
python3 - "$CORE_DIR/src/darwin/darwin-host-session.vala" << 'PYEOF'
import sys, os, re, uuid

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

rand_prefix = uuid.uuid4().hex[:8]

src = re.sub(
    r'PathTemplate\s*\(\s*"frida-agent([^"]*)"\s*\)',
    f'PathTemplate ("{rand_prefix}-agent\\1")',
    src,
)

src = re.sub(
    r'"frida-agent([^"]*\.dylib)"',
    f'"{rand_prefix}-agent\\1"',
    src,
)

with open(filepath, "w") as f:
    f.write(src)

print(f"[+] darwin-host-session.vala: agent name → {rand_prefix}-agent*")
PYEOF

echo ""
echo "============================================"
echo " All source patches applied successfully"
echo "============================================"
