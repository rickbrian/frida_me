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
\t\t\treturn (string) GLib.Base64.decode ("ZnJpZGE6cnBjAA==");
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
# 4. frida-glue.c — g_set_prgname + 主循环线程名
# ──────────────────────────────────────────────
if [ -f "$CORE_DIR/src/frida-glue.c" ]; then
    python3 - "$CORE_DIR/src/frida-glue.c" << 'PYEOF'
import sys, os, re

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
    src = re.sub(
        r'g_set_prgname\s*\(\s*"[^"]*"\s*\)',
        'g_set_prgname ("com.apple.WebKit")',
        src,
    )

src = src.replace('"frida-main-loop"', '"com.apple.runloop"')

with open(filepath, "w") as f:
    f.write(src)

print("[+] frida-glue.c: g_set_prgname → com.apple.WebKit")
print("[+] frida-glue.c: frida-main-loop → com.apple.runloop")
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
#    Android 端已验证可行：iOS app 同样几乎不重装 signal handler
#    禁用后消除 signal/sigaction inline hook 的 rwxp 检测特征
#    理论风险：Stalker 在目标重装 signal handler 时可能失效
#    实际：几乎不会发生，检测风险 > 理论风险
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
        guard = "\n  return; /* stealth: disable signal hooks — rwxp trace */"
        if guard not in src[insert_pos:insert_pos+100]:
            src = src[:insert_pos] + guard + src[insert_pos:]
            count += 1

if count > 0:
    with open(filepath, "w") as f:
        f.write(src)
    print(f"[+] gumexceptor-posix.c: {count} signal hook functions disabled (Android §1.1)")
else:
    print("[~] gumexceptor-posix.c: no matching functions found")
PYEOF

# ──────────────────────────────────────────────
# 8. (不做) D-Bus 接口名混淆
#    [DBus (name = "re.frida.HostSession17")] 是 Vala 编译期注解
#    客户端硬编码相同接口名，单改服务端 → GDBus 匹配失败
# ──────────────────────────────────────────────

# ──────────────────────────────────────────────
# 8.5 Stalker arm64 ctx 分配 ASLR fix (STEALTH_PATCHES §6)
#     gum_exec_ctx_new 中 gum_memory_allocate(NULL, ctx_size, ...)
#     ASLR 可能把 ctx 放在附近无足够空隙的地址
#     后续 gum_memory_allocate_near 分 slab 全部失败
#     修复：先 reserve 大块找到好的 hole，再在中心分配
# ──────────────────────────────────────────────
python3 - "$GUM_DIR/gum/backend-arm64/gumstalker-arm64.c" << 'PYEOF'
import sys, os, re

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    print("[~] gumstalker-arm64.c not found, skipping Stalker ASLR fix")
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

old_pattern = re.compile(
    r'(ctx\s*=\s*(?:\([^)]*\)\s*)?)gum_memory_allocate\s*\(\s*NULL\s*,\s*stalker->ctx_size\s*,'
    r'\s*stalker->page_size\s*,\s*'
    r'stalker->is_rwx_supported\s*\?\s*GUM_PAGE_RWX\s*:\s*GUM_PAGE_RW\s*\)',
    re.DOTALL,
)

match = old_pattern.search(src)
if match:
    cast_prefix = match.group(1) or "ctx = "
    replacement = """{cast_prefix}({type_cast}gum_stalker_aslr_alloc (stalker))""".format(
        cast_prefix=cast_prefix,
        type_cast="",
    )

    helper_func = r"""
/* stealth: ASLR-aware ctx allocation (STEALTH_PATCHES §6) */
static gpointer
gum_stalker_aslr_alloc (GumStalker * stalker)
{
  gpointer base;

  base = gum_memory_allocate (NULL, G_MAXINT32, stalker->page_size,
      GUM_PAGE_RW);
  gum_memory_free (base, G_MAXINT32);

  return gum_memory_allocate (
      (guint8 *) base + G_MAXINT32 / 2,
      stalker->ctx_size,
      stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);
}

"""

    func_decl = "static gpointer gum_stalker_aslr_alloc (GumStalker * stalker);\n"

    src = src[:match.start()] + replacement + src[match.end():]

    run_main_loop_pos = src.find("\nstatic gpointer\ngum_exec_ctx_new")
    if run_main_loop_pos == -1:
        run_main_loop_pos = src.find("static GumExecCtx *\ngum_exec_ctx_new")
    if run_main_loop_pos != -1:
        src = src[:run_main_loop_pos] + "\n" + helper_func + src[run_main_loop_pos:]

    first_static = src.find("static void gum_stalker_")
    if first_static != -1:
        line_start = src.rfind("\n", 0, first_static) + 1
        src = src[:line_start] + func_decl + src[line_start:]

    with open(filepath, "w") as f:
        f.write(src)
    print("[+] gumstalker-arm64.c: Stalker ASLR fix applied (§6)")
else:
    print("[~] gumstalker-arm64.c: allocation pattern not found (may already be fixed)")
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

# ──────────────────────────────────────────────
# 10. server.vala — 临时目录名 + Darwin 主线程名
#     源码: DEFAULT_DIRECTORY = "re.frida.server"
#           → 在 /tmp 或 /var 下创建目录，文件系统可检测
#     源码: "frida-server-main-loop" Darwin 主线程名
# ──────────────────────────────────────────────
if [ -f "$CORE_DIR/server/server.vala" ]; then
    python3 - "$CORE_DIR/server/server.vala" << 'PYEOF'
import sys, os

filepath = sys.argv[1]
with open(filepath, "r") as f:
    src = f.read()

changed = False

old_dir = 'DEFAULT_DIRECTORY = "re.frida.server"'
new_dir = 'DEFAULT_DIRECTORY = "com.apple.instruments"'
if old_dir in src:
    src = src.replace(old_dir, new_dir)
    changed = True
    print("[+] server.vala: DEFAULT_DIRECTORY → com.apple.instruments")

old_thread = '"frida-server-main-loop"'
new_thread = '"com.apple.dt.instruments"'
if old_thread in src:
    src = src.replace(old_thread, new_thread)
    changed = True
    print("[+] server.vala: frida-server-main-loop → com.apple.dt.instruments")

if changed:
    with open(filepath, "w") as f:
        f.write(src)
else:
    print("[~] server.vala: no matching strings found")
PYEOF
fi

# ──────────────────────────────────────────────
# 11. __FRIDA_DATA / __FRIDA_TEXT segment 重命名 (IOS §10)
#     gumdarwingrafter.c 在 graft 时给 Mach-O 添加 __FRIDA_TEXT%u / __FRIDA_DATA%u segment
#     guminterceptor-arm64.c 在运行时用 g_str_has_prefix("__FRIDA_DATA") 识别
#     两端同步改为 __GUM_TEXT%u / __GUM_DATA%u
# ──────────────────────────────────────────────
python3 - "$GUM_DIR" << 'PYEOF'
import sys, os

gum_dir = sys.argv[1]
count = 0

grafter = os.path.join(gum_dir, "gum", "gumdarwingrafter.c")
if os.path.isfile(grafter):
    with open(grafter, "r") as f:
        src = f.read()
    src = src.replace('g_str_has_prefix (segment->name, "__FRIDA_")', 'g_str_has_prefix (segment->name, "__GUM_")')
    src = src.replace('"__FRIDA_TEXT%u"', '"__GUM_TEXT%u"')
    src = src.replace('"__FRIDA_DATA%u"', '"__GUM_DATA%u"')
    with open(grafter, "w") as f:
        f.write(src)
    count += 1
    print("[+] gumdarwingrafter.c: __FRIDA_TEXT/DATA → __GUM_TEXT/DATA")

interceptor = os.path.join(gum_dir, "gum", "backend-arm64", "guminterceptor-arm64.c")
if os.path.isfile(interceptor):
    with open(interceptor, "r") as f:
        src = f.read()
    src = src.replace('g_str_has_prefix (sc->segname, "__FRIDA_DATA")', 'g_str_has_prefix (sc->segname, "__GUM_DATA")')
    with open(interceptor, "w") as f:
        f.write(src)
    count += 1
    print("[+] guminterceptor-arm64.c: __FRIDA_DATA → __GUM_DATA")

if count == 0:
    print("[~] __FRIDA segment rename: no matching files found")
PYEOF

# ──────────────────────────────────────────────
# 12. STUN SOFTWARE 属性隐藏 (IOS §11)
#     session.vala: agent.set_software ("Frida") → 空字符串
#     libnice STUN 协议的 SOFTWARE 属性会泄露 "Frida" 到网络流量
# ──────────────────────────────────────────────
if [ -f "$CORE_DIR/lib/base/session.vala" ]; then
    python3 - "$CORE_DIR/lib/base/session.vala" << 'PYEOF'
import sys, os

filepath = sys.argv[1]
with open(filepath, "r") as f:
    src = f.read()

old = 'agent.set_software ("Frida")'
new = 'agent.set_software ("")'
if old in src:
    src = src.replace(old, new)
    with open(filepath, "w") as f:
        f.write(src)
    print("[+] session.vala: STUN SOFTWARE attribute cleared (was 'Frida')")
else:
    print("[~] session.vala: set_software pattern not found")
PYEOF
fi

# ──────────────────────────────────────────────
# 13. pages_per_batch 随机化 (IOS §12)
#     gumcodeallocator.c: pages_per_batch = 7 是 Frida 固定特征
#     正常 app 几乎不会有 7 页一批的匿名 r-x 映射
#     随机化为 5~13 的奇数，打破特征指纹
# ──────────────────────────────────────────────
python3 - "$GUM_DIR/gum/gumcodeallocator.c" << 'PYEOF'
import sys, os, random

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    print("[~] gumcodeallocator.c not found, skipping")
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

old = "allocator->pages_per_batch = 7;"
if old in src:
    new_val = random.choice([5, 9, 11, 13])
    new = f"allocator->pages_per_batch = {new_val};"
    src = src.replace(old, new)
    with open(filepath, "w") as f:
        f.write(src)
    print(f"[+] gumcodeallocator.c: pages_per_batch = {new_val} (was 7)")
else:
    print("[~] gumcodeallocator.c: pages_per_batch pattern not found")
PYEOF

# ──────────────────────────────────────────────
# 14. frida-error-quark 字符串混淆 (IOS §13)
#     xpc.vala 中硬编码 "frida-error-quark" — 明文在二进制中可搜
#     改为 base64 解码
# ──────────────────────────────────────────────
python3 - "$CORE_DIR/lib/base/xpc.vala" << 'PYEOF'
import sys, os

filepath = sys.argv[1]
if not os.path.isfile(filepath):
    print("[~] xpc.vala not found, skipping")
    sys.exit(0)

with open(filepath, "r") as f:
    src = f.read()

old = 'Quark.from_string ("frida-error-quark")'
new = 'Quark.from_string ((string) GLib.Base64.decode ("ZnJpZGEtZXJyb3ItcXVhcmsA"))'
if old in src:
    src = src.replace(old, new)
    with open(filepath, "w") as f:
        f.write(src)
    print("[+] xpc.vala: frida-error-quark → base64 obfuscation")
else:
    print("[~] xpc.vala: frida-error-quark pattern not found")
PYEOF

echo ""
echo "============================================"
echo " All source patches applied successfully"
echo "============================================"
