#!/bin/bash
set -euo pipefail

FRIDA_DIR="${1:?Usage: $0 <frida-source-dir>}"

GUM_DIR="$FRIDA_DIR/subprojects/frida-gum"
CORE_DIR="$FRIDA_DIR/subprojects/frida-core"

echo "============================================"
echo " iOS Stealth Frida - Source Patches"
echo "============================================"

# ──────────────────────────────────────────────
# 1. frida-gum: g_set_prgname("frida") 改名
#    GLib pool worker 默认名 = pool-<prgname>
#    改后 pool worker = pool-com.apple.WebKit
# ──────────────────────────────────────────────
if [ -f "$GUM_DIR/gum/gum.c" ]; then
    sed -i '' 's/g_set_prgname ("frida")/g_set_prgname ("com.apple.WebKit")/' "$GUM_DIR/gum/gum.c"
    echo "[+] gum.c: g_set_prgname → com.apple.WebKit"
fi

# ──────────────────────────────────────────────
# 2. frida-gum: gum-js-loop 线程名
# ──────────────────────────────────────────────
if [ -f "$GUM_DIR/bindings/gumjs/gumscriptscheduler.c" ]; then
    sed -i '' 's/"gum-js-loop"/"com.apple.CFSocket.private"/' \
        "$GUM_DIR/bindings/gumjs/gumscriptscheduler.c"
    echo "[+] gumscriptscheduler.c: gum-js-loop → com.apple.CFSocket.private"
fi

# ──────────────────────────────────────────────
# 3. frida-core: frida:rpc 协议标识符 base64 混淆
#    运行时仍然是 "frida:rpc"（兼容官方客户端）
#    但二进制文件里不含 "frida:rpc" 明文
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
# 4. frida-core: agent.vala 线程名
# ──────────────────────────────────────────────
if [ -f "$CORE_DIR/lib/agent/agent.vala" ]; then
    sed -i '' 's/"frida-eternal-agent"/"com.apple.CFStream"/' "$CORE_DIR/lib/agent/agent.vala"
    sed -i '' 's/"frida-agent-emulated"/"com.apple.CFStream"/' "$CORE_DIR/lib/agent/agent.vala"
    echo "[+] agent.vala: thread names → com.apple.CFStream"
fi

# ──────────────────────────────────────────────
# 5. frida-core: p2p.vala 线程名
# ──────────────────────────────────────────────
if [ -f "$CORE_DIR/lib/base/p2p.vala" ]; then
    sed -i '' 's/"frida-generate-certificate"/"com.apple.securityd"/' "$CORE_DIR/lib/base/p2p.vala"
    echo "[+] p2p.vala: frida-generate-certificate → com.apple.securityd"
fi

# ──────────────────────────────────────────────
# 6. frida_agent_main 符号名 → main
#    覆盖所有平台的 host-session + agent-container
# ──────────────────────────────────────────────
for f in \
    "$CORE_DIR/src/agent-container.vala" \
    "$CORE_DIR/src/darwin/darwin-host-session.vala" \
    "$CORE_DIR/src/linux/linux-host-session.vala" \
    "$CORE_DIR/src/freebsd/freebsd-host-session.vala" \
    "$CORE_DIR/src/qnx/qnx-host-session.vala" \
    "$CORE_DIR/src/windows/windows-host-session.vala" \
    "$CORE_DIR/tests/test-agent.vala" \
    "$CORE_DIR/tests/test-injector.vala"; do
    if [ -f "$f" ]; then
        sed -i '' 's/"frida_agent_main"/"main"/' "$f"
        echo "[+] $(basename "$f"): frida_agent_main → main"
    fi
done

# ──────────────────────────────────────────────
# 7. frida-core: frida-glue.c g_set_prgname
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
# 8. frida-core: 禁用 ExitMonitor（去掉 exit/abort 的 inline hook）
#    在 iOS 上这些 hook 会在 maps 里留下 rwxp 段
# ──────────────────────────────────────────────
python3 - "$CORE_DIR/lib/agent/agent.vala" << 'PYEOF'
import sys, os, re

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

src = src.replace(
    "var exit_monitor = new ExitMonitor (this);",
    "ExitMonitor? exit_monitor = null; // disabled for stealth",
)
src = src.replace(
    "exit_monitor = new ExitMonitor (this);",
    "exit_monitor = null; // disabled for stealth",
)

with open(filepath, "w") as f:
    f.write(src)

print("[+] agent.vala: ExitMonitor disabled (no rwxp from exit/abort hooks)")
PYEOF

# ──────────────────────────────────────────────
# 9. Darwin 专用: 随机化 agent dylib 的 memfd/temp 名称
#    darwin-host-session.vala 中 agent 描述符的名称模板
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
