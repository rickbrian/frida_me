# iOS Stealth Frida - 隐身补丁文档

针对 iOS arm64/arm64e 的 Frida 反检测改动。
所有改动均基于 Frida 源码分析，有明确的安全/危险分类依据。
目标：拿到新 app 后，凭此文档直接排除已处理的已知 Frida 特征，
只需关注 app 自身的**业务级检测**（代码完整性校验、行为特征等）。

---

## 核心原则：什么能改、什么不能改

基于对 `frida-core`、`frida-gum` 源码的完整分析：

### 绝对不能改（改了断通信）

| 字符串类型 | 示例 | 源码位置 | 原因 |
|---|---|---|---|
| D-Bus 接口名 | `re.frida.HostSession17` | `session.vala` `[DBus (name=...)]` | Vala 编译期注解，客户端 frida-core 硬编码相同值 |
| D-Bus 对象路径 | `/re/frida/HostSession` | `session.vala` `ObjectPath` | `connection.get_proxy(null, ObjectPath.HOST_SESSION)` 客户端硬编码 |
| Server GUID | `6769746875622e636f6d2f6672696461` | `session.vala` | D-Bus peer-to-peer 认证握手必需 |
| `re.frida.Error` | 错误域名 | GDBus 自动生成 | GDBus 远程异常传递依赖 |

> 这些字符串虽然含 "frida"，但只存在于 server/agent **自己的进程内存**中。
> iOS 沙盒阻止 app 扫描其他进程内存，检测风险低。
> 唯一例外：当 agent 被注入到目标 app 进程后，D-Bus 接口名会出现在目标进程内存中。
> 但它们是 GDBus 内部数据结构的一部分，不在连续可扫描的字符串区域。

### 可以改但需要谨慎

| 字符串 | 风险 | 结论 |
|---|---|---|
| `frida_agent_main` | server 用 `dlsym` 查找此符号，agent 导出此符号 | 二进制 patcher 同时处理两个文件 |
| `frida:rpc` | 消息类型标识，双端使用 | 源码级 base64 混淆，运行时解码回原值 |

### 安全可改（检测向量）

| 字符串 | 检测方式 | 处理方式 |
|---|---|---|
| 进程名 `frida` | `ps` / 进程枚举 | `g_set_prgname("com.apple.WebKit")` |
| 线程名 `gum-js-loop` 等 | `task_threads` + `thread_info` | 源码重命名 + 二进制兜底 |
| 文件名 `frida-agent.dylib` | `_dyld_get_image_name` | 源码随机化 + 二进制重命名 |
| 路径 `frida-1.0/` | 文件系统检查 | 二进制重命名 + deb 安装路径 |
| `__FRIDA_DATA` segment | `LC_SEGMENT_64` load command 枚举 | 源码重命名 + 二进制兜底 |
| `Frida` GType 前缀 | `g_type_from_name("FridaAgentSession")` | 二进制等长替换 |
| `frida-error-quark` | 内存字符串扫描 | 源码 base64 混淆 + 二进制兜底 |
| STUN SOFTWARE 属性 | 网络流量抓包 | 源码清空 |

### 曾经做了但已回滚（源码分析后确认危险）

| 改动 | 为什么回滚 |
|---|---|
| D-Bus 接口名 base64 混淆 | `[DBus (name=...)]` 必须是字符串字面量；且客户端硬编码同值 |
| 全局 `frida->fs179` 替换 | Frida 内部大量 `frida_` 前缀的函数指针、属性名、quark 用于 D-Bus 方法分发 |

---

## 1. 源码级改动 (`scripts/apply-ios-stealth.sh`)

### SS1 GLib prgname -- 消除 pool-frida 线程名

| 文件 | 改动 |
|---|---|
| `frida-gum/gum/gum.c` | `g_set_prgname("frida")` -> `g_set_prgname("com.apple.WebKit")` |
| `frida-core/src/frida-glue.c` | 同上 |

**源码依据**：`gum.c:305` 硬编码 `g_set_prgname("frida")`。GLib 的 `g_thread_pool` lazy spawn 的 worker 默认名是 `pool-<g_get_prgname()>` = `pool-frida`。改为 `com.apple.WebKit` 后 pool worker 名变为 `pool-com.apple.WebKit`，与系统线程混同。

### SS2 线程名重命名

| 文件 | 旧名 | 新名（iOS 风格） | 源码行 |
|---|---|---|---|
| `gumscriptscheduler.c` | `gum-js-loop` | `com.apple.CFSocket.private` | `:117` |
| `agent.vala` | `frida-eternal-agent` | `com.apple.CFStream` | 多处 |
| `agent.vala` | `frida-agent-emulated` | `com.apple.CFStream` | `:1412` |
| `p2p.vala` | `frida-generate-certificate` | `com.apple.securityd` | `:892` |

### SS3 frida:rpc 协议标识符混淆

`rpc.vala` 中添加 `_rpc_tag()` 辅助函数：

```vala
private static string _rpc_tag () {
    // base64("frida:rpc\0") = "ZnJpZGE6cnBjAA=="
    return (string) GLib.Base64.decode ("ZnJpZGE6cnBjAA==");
}
```

- 所有 `"frida:rpc"` 字面量替换为 `_rpc_tag()` 调用
- **运行时返回完全相同的字符串** `"frida:rpc"`，兼容标准客户端
- 二进制中不含 `frida:rpc` 明文
- base64 编码包含 `\0` 终止符（`AA==` 部分），确保 C 字符串有效

### SS4 frida-glue.c 主循环线程名

| 旧名 | 新名 | 源码位置 |
|---|---|---|
| `frida-main-loop` | `com.apple.runloop` | `frida-glue.c` |

### SS5 ExitMonitor 禁用

`agent.vala` 中 `ExitMonitor` 创建改为 `null`：
- 去掉对 `exit`、`_exit`、`abort` 的 `Interceptor.attach`
- 消除这些 hook 在内存中产生的 `rwxp` 页面

**源码依据**：`agent.vala::start()` -> `new ExitMonitor(this)` -> 内部调 `interceptor.attach` 三次 -> 每次创建一个 inline hook -> 在 `/proc/<pid>/maps` (或 `vm_region`) 上产生 `rwxp` 切片。

### SS6 Instruction.parse() 不再 mprotect

| 文件 | 改动 |
|---|---|
| `gumquickinstruction.c` | 注释掉 `gum_ensure_code_readable` |
| `gumv8instruction.cpp` | 同上 |

**源码依据**：`gumjs_instruction_parse` 只是把 16 字节喂给 capstone 反汇编，无写入/执行需求。但 Frida 默认在每次 parse 前调 `gum_ensure_code_readable`，把 `r-xp` 页永久改成 `rwxp`。

### SS7 Agent 名称随机化

`darwin-host-session.vala` 中 agent 描述符文件名模板：
- `frida-agent-<arch>.dylib` -> `<random8>-agent-<arch>.dylib`
- 每次编译随机，`_dyld_get_image_name` 无法匹配

### SS8 Stalker arm64 ASLR fix

`gumstalker-arm64.c` 中 `gum_exec_ctx_new` 的内存分配策略：

**源码依据**：原代码 `gum_memory_allocate(NULL, ctx_size, ...)` 让内核随机选位置。ASLR 可能把 ctx 放在 +/-128MiB 内无足够空隙的地址，后续 `gum_memory_allocate_near` 分配 code/slow/data slab 全部失败。

**修复**：先 reserve `G_MAXINT32` (2GB) 大块找到好的 hole，释放后在中心位置分配：
```c
base = gum_memory_allocate(NULL, G_MAXINT32, page_size, GUM_PAGE_RW);
gum_memory_free(base, G_MAXINT32);
ctx = gum_memory_allocate(base + G_MAXINT32/2, ctx_size, ...);
```

### SS9 server.vala 临时目录名 + 线程名

| 原始 | 替换为 | 检测方式 | 源码位置 |
|---|---|---|---|
| `DEFAULT_DIRECTORY = "re.frida.server"` | `"com.apple.instruments"` | `ls /tmp/` | `server.vala` |
| `"frida-server-main-loop"` | `"com.apple.dt.instruments"` | 线程枚举 | `server.vala` |

### SS10 Exceptor signal hooks 禁用

**源码位置**：`gumexceptor-posix.c` 的 `gum_exceptor_backend_attach` / `gum_exceptor_backend_detach`

这两个函数 hook libc 的 `signal` 和 `sigaction`，防止目标 app 重装 signal handler 顶掉 Frida 自己的。每个 hook 产生一个 `rwxp` 页面。

**Android 端已验证可行**：app 几乎不重装 signal handler。iOS 同理。禁用后消除 2 个 `rwxp` 检测特征。

### SS11 `__FRIDA_DATA` / `__FRIDA_TEXT` segment 重命名 (NEW)

| 文件 | 旧值 | 新值 |
|---|---|---|
| `gumdarwingrafter.c:303` | `g_str_has_prefix(segment->name, "__FRIDA_")` | `"__GUM_"` |
| `gumdarwingrafter.c:1015` | `"__FRIDA_TEXT%u"` | `"__GUM_TEXT%u"` |
| `gumdarwingrafter.c:1045` | `"__FRIDA_DATA%u"` | `"__GUM_DATA%u"` |
| `guminterceptor-arm64.c:549` | `g_str_has_prefix(sc->segname, "__FRIDA_DATA")` | `"__GUM_DATA"` |

**源码依据**：Frida 的 grafted hook 机制（`gum_darwin_grafter_graft`）在 Mach-O 中添加 `__FRIDA_TEXT0`、`__FRIDA_DATA0` 等 segment。app 只需枚举 load commands 就能发现。segment name 在 Mach-O header 的 `struct segment_command_64.segname` 中是 16 字节定长字段，`otool -l` 即可看到。

**两端必须同步改**：grafter 写入时用新名，interceptor 运行时识别也用新名。

### SS12 STUN SOFTWARE 属性隐藏 (NEW)

| 文件 | 旧值 | 新值 |
|---|---|---|
| `session.vala:308` | `agent.set_software("Frida")` | `agent.set_software("")` |

**源码依据**：Frida 使用 libnice 做 ICE/STUN 协商（P2P 模式）。`Nice.Agent.set_software()` 设置 STUN 消息中的 `SOFTWARE` 属性。值 `"Frida"` 会出现在 **网络流量** 中。清空后 libnice 不发送 SOFTWARE 属性。

> 注意：仅 P2P 模式（`--p2p`）才走 ICE/STUN。普通 `-H` 或 `-U` 模式不受影响。

### SS13 pages_per_batch 随机化 (NEW)

| 文件 | 旧值 | 新值 |
|---|---|---|
| `gumcodeallocator.c:141` | `pages_per_batch = 7` | 随机 `{5, 9, 11, 13}` |

**源码依据**：`gum_code_allocator_init` 固定用 7 页一批分配匿名 `r-x` 内存（code slab）。7 页 = 28KB（arm64 4KB 页）。这是 Frida **独有的内存分配指纹**。正常 app 不会有 28KB 的匿名 `r-x` 映射。

随机化后每次编译产生不同的 slab 大小，打破固定特征。

### SS14 frida-error-quark 字符串混淆 (NEW)

| 文件 | 旧值 | 新值 |
|---|---|---|
| `xpc.vala:246` | `Quark.from_string("frida-error-quark")` | `Quark.from_string((string) GLib.Base64.decode("ZnJpZGEtZXJyb3ItcXVhcmsA"))` |

**源码依据**：`xpc.vala` 在 XPC 错误处理中硬编码 `"frida-error-quark"`。该字符串会出现在编译后的二进制明文中。Base64 混淆后运行时解码回原值，兼容性不受影响。

> `frida-glue.c` 和 `agent-glue.c` 中的 `frida_error_quark()` 是 Vala 自动生成的 C 函数，
> 函数名在符号表中，已被二进制 patcher 的 GType 前缀替换间接覆盖。

---

## 2. 二进制级改动 (`scripts/anti-anti-frida-macho.py`)

对编译后的 Mach-O 做**等长度**字节替换：

### 2.1 线程名

| 原始 | 替换为 | 字节数 | 检测方式 |
|---|---|---|---|
| `gum-js-loop\0` | `RunLoopMain\0` | 12 | `task_threads` + `thread_info` |
| `gmain\0` | `GCDwk\0` | 6 | 同上 |
| `gdbus\0` | `IOSvc\0` | 6 | 同上 |
| `pool-frida\0` | `pool-cfrun\0` | 11 | 同上 |
| `frida-main-loop\0` | `CFRunLoopThread\0` | 16 | 同上 |
| `frida-server-main-loop\0` | `com.apple.dt.remotesvc\0` | 23 | 同上 |

### 2.2 文件路径 / 进程名

| 原始 | 替换为 | 字节数 |
|---|---|---|
| `frida-server\0` | `fs179-server\0` | 13 |
| `frida-agent.dylib` | `fs179-agent.dylib` | 17 |
| `frida-helper\0` | `fs179-helper\0` | 13 |
| `frida-1.0` | `fs179-1.0` | 9 |
| `re.frida.server\0` | `com.apple.instd\0` | 16 |

### 2.3 导出符号

| 原始 | 替换为 | 字节数 |
|---|---|---|
| `frida_agent_main` | `fs179_agent_main` | 16 |

### 2.4 Mach-O segment 名 (NEW)

| 原始 | 替换为 | 字节数 | 说明 |
|---|---|---|---|
| `__FRIDA_DATA` | `__CFGUM_DATA` | 12 | segment_command_64.segname 兜底 |
| `__FRIDA_TEXT` | `__CFGUM_TEXT` | 12 | 同上 |
| `__FRIDA_` | `__CFGUM_` | 8 | 通配兜底 |

### 2.5 GType 前缀 (NEW)

| 原始 | 替换为 | 说明 |
|---|---|---|
| `FridaAgent` | `CgentAgent` | GObject 类型名前缀 |
| `FridaScript` | `CgentScript` | 同上 |
| `FridaSession` | `CgentSession` | 同上 |
| `FridaPortal` | `CgentPortal` | 同上 |
| `FridaBus` | `CgentBus` | 同上 |

**源码依据**：Vala 编译器自动为 `namespace Frida` 下的类生成 `FridaXxxYyy` 前缀的 GType 名，通过 `g_type_register_static` 注册。这些名字**不参与** D-Bus 协议（协议用的是 `[DBus (name=...)]` 注解），只在进程内部的 GLib 类型系统中。app 可以 `g_type_from_name("FridaAgentSession")` 检测。等长替换 `Frida` -> `Cgent`（5 字节）安全。

### 2.6 error-quark 兜底 (NEW)

| 原始 | 替换为 | 字节数 |
|---|---|---|
| `frida-error-quark\0` | `cgent-error-quark\0` | 18 |

### 不做的事（源码分析依据）

| 字符串 | 原因 |
|---|---|
| D-Bus 接口名 `re.frida.HostSession17` | 客户端硬编码，改了 GDBus 匹配失败 |
| D-Bus ObjectPath `/re/frida/HostSession` | 同上 |
| ServerGuid `6769746875622e636f6d2f6672696461` | D-Bus 握手必需 |
| 全局 `frida` -> `fs179` | 太多协议内部字符串，无法安全枚举 |

---

## 3. 运行时 Bypass 脚本 (`bypass_imoutai.js`)

**定位**：源码改动和二进制 patcher 消除 Frida 自身的静态特征。
Bypass 脚本处理 **app 的主动检测行为** -- hook app 调用的检测 API，欺骗返回值。

### 3.1 已覆盖的检测 API (17 个 hook)

| # | 检测手段 | hook 目标 | 策略 |
|---|---|---|---|
| 1 | 端口扫描 27042/27043 | `connect` | 拦截 `AF_INET` + port match，返回 -1 |
| 2 | Mach 异常端口 | `task_get_exception_ports` | replace 返回空列表 |
| 3 | sysctl P_TRACED | `sysctl` | 清除 `kinfo_proc.kp_proc.p_flag` 的 `P_TRACED` 位 |
| 4 | ptrace PT_DENY_ATTACH | `ptrace` | 拦截 `request==31`，返回 0 |
| 5 | 文件路径检测 | `access`/`open`/`stat`/`lstat`/`fopen` | 匹配黑名单路径返回 -1/NULL |
| 6 | NSFileManager | `-[NSFileManager fileExistsAtPath:]` | ObjC 层拦截 |
| 7 | dyld image 名扫描 | `_dyld_get_image_name` | replace 过滤含 "frida" 的名称 |
| 8 | dladdr 符号反查 | `dladdr` | 过滤含 "frida" 的 `dli_fname` |
| 9 | 环境变量 | `getenv` | 拦截 `FRIDA_*` / `DYLD_INSERT_LIBRARIES` |
| 10 | popen/system | `popen` | 过滤含 frida 的命令 |
| 11 | fork 检测 | `fork` | replace 返回 -1 |
| 12 | abort/exit 拦截 | `abort`/`exit`/`_exit` | replace 为空函数 + 打印调用栈 |
| 13 | URL scheme | `-[UIApplication canOpenURL:]` | 拦截 cydia/sileo/filza scheme |
| 14 | 内存扫描 | `memmem` | 过滤 "frida"/"gum-js"/"gmain" needle |
| 15 | **线程枚举** (NEW) | `task_threads` | 过滤 Frida 线程（gmain/gdbus/gum-js/pool-*） |
| 16 | **匿名 r-x 内存** (NEW) | `mach_vm_region` | 伪装匿名 r-x 区域权限为 r-- |
| 17 | **Mach port 枚举** (NEW) | `mach_port_names` | 监控（保守策略，不主动过滤） |
| 17b | **fd 枚举** (NEW) | `proc_pidfdinfo` | 监控（保守策略） |

### 3.2 task_threads 过滤策略详解 (NEW)

```
task_threads() 返回后:
  1. 读取线程列表
  2. 对每个线程: pthread_from_mach_thread_np -> pthread_getname_np
  3. 过滤匹配以下名字的线程:
     - gmain / GCDwk (GLib 主循环)
     - gdbus / IOSvc (GLib D-Bus)
     - gum-js / RunLoopMain (JS 引擎循环)
     - pool-* (GLib 线程池 worker)
     - linjector (注入器)
  4. 用过滤后的列表覆写原始列表
  5. 更新 act_listCnt
```

**风险评估**：task_threads 过滤是**高价值但中等风险**的 hook。如果过滤逻辑有 bug（比如误过滤了 app 自己的线程），app 会行为异常。当前策略基于线程名白名单过滤，足够精确。

### 3.3 mach_vm_region 伪装策略详解 (NEW)

```
mach_vm_region(flavor=VM_REGION_BASIC_INFO_64) 返回后:
  检查 protection == VM_PROT_READ|VM_PROT_EXECUTE (5)
       && user_tag == 0 (匿名映射)
  → 将 protection 改为 VM_PROT_READ (1)
```

**源码依据**：Frida 的 code slab（trampoline/thunk）是通过 `mmap(MAP_ANON)` + `mprotect(PROT_READ|PROT_EXEC)` 创建的匿名 `r-x` 映射。正常 iOS app 的 `r-x` 映射全部属于 Mach-O image（有 user_tag 标记）。匿名 `r-x` 是 Frida 独有特征。

---

## 4. iOS 检测向量完整对照（按检测难度排序）

### 第一层：字符串特征（最容易检测，已全面处理）

| # | 检测向量 | 难度 | 状态 | 处理层 |
|---|---|---|---|---|
| 1 | 内存搜索 "frida" 字符串 | 极低 | 已处理 | 源码 base64 + 二进制 rename |
| 2 | `__FRIDA_DATA` segment name | 极低 | **已处理 (NEW)** | 源码 SS11 + 二进制 2.4 |
| 3 | `_dyld_get_image_name` 含 "frida" | 低 | 已处理 | 源码 SS7 + bypass #7 |
| 4 | 文件路径 `/usr/lib/frida*` | 低 | 已处理 | 二进制 2.2 + bypass #5 |
| 5 | `frida:rpc` 明文 | 低 | 已处理 | 源码 SS3 |
| 6 | `frida-error-quark` 明文 | 低 | **已处理 (NEW)** | 源码 SS14 + 二进制 2.6 |
| 7 | GType 名 `FridaXxx` | 低 | **已处理 (NEW)** | 二进制 2.5 |
| 8 | `frida_agent_main` 符号 | 低 | 已处理 | 二进制 2.3 |
| 9 | STUN SOFTWARE="Frida" | 低 | **已处理 (NEW)** | 源码 SS12 |
| 10 | 环境变量 `FRIDA_*` | 低 | 已处理 | bypass #9 |
| 11 | 端口 27042 扫描 | 低 | 已处理 | 用户自定义端口 + bypass #1 |

### 第二层：内存布局特征（中等难度）

| # | 检测向量 | 难度 | 状态 | 处理层 |
|---|---|---|---|---|
| 12 | 匿名 r-x 内存页 (code slab) | 中 | **已处理 (NEW)** | 源码 SS13 随机化 + bypass #16 |
| 13 | ExitMonitor rwxp 页 | 中 | 已处理 | 源码 SS5 禁用 |
| 14 | Exceptor signal hook rwxp | 中 | 已处理 | 源码 SS10 禁用 |
| 15 | Instruction.parse rwxp | 中 | 已处理 | 源码 SS6 |
| 16 | vm_remap 双映射 | 中 | 未处理 | iOS 上 Frida 用 vm_remap 做代码页修改，可被检测 |

### 第三层：系统资源特征（需要 Mach API hook）

| # | 检测向量 | 难度 | 状态 | 处理层 |
|---|---|---|---|---|
| 17 | `task_threads()` 线程计数异常 | 低 | **已处理 (NEW)** | bypass #15 |
| 18 | `task_get_exception_ports` | 低 | 已处理 | bypass #2 |
| 19 | `mach_vm_region` 枚举异常内存 | 中 | **已处理 (NEW)** | bypass #16 |
| 20 | `mach_port_names` 端口枚举 | 中 | **监控中 (NEW)** | bypass #17 |
| 21 | `proc_pidfdinfo` fd 枚举 | 中 | **监控中 (NEW)** | bypass #17b |
| 22 | sysctl P_TRACED | 低 | 已处理 | bypass #3 |
| 23 | ptrace PT_DENY_ATTACH | 低 | 已处理 | bypass #4 |

### 第四层：代码完整性特征（inline hook 本质，极难消除）

| # | 检测向量 | 难度 | 状态 | 说明 |
|---|---|---|---|---|
| 24 | 函数 prologue CRC/hash 校验 | 高 | 未处理 | `Interceptor.attach` 覆写函数头部，无法避免 |
| 25 | Trampoline 指令模式匹配 | 高 | 未处理 | `LDR X16, =addr; BR X16` 固定模式 |
| 26 | 跳转目标指向非 image 地址 | 高 | 未处理 | hook 跳转目标落在匿名内存 |

### 第五层：运行时行为特征（难度高，大多数 app 不检测）

| # | 检测向量 | 难度 | 状态 | 说明 |
|---|---|---|---|---|
| 27 | dyld image 数量异常 | 中 | 未处理 | agent 加载后 `_dyld_image_count()` +1 |
| 28 | ObjC runtime 类扫描 | 高 | 未处理 | bypass 脚本用 ObjC API 会注册新类 |
| 29 | 硬件调试寄存器 | 高 | 未处理 | 仅 spawn 阶段，attach 后即清除 |
| 30 | dlmalloc heap 指纹 | 高 | 未处理 | Frida 独立 mspace，极难检测 |

---

## 5. 面对新 app 的工作流程

拿到一个新的加壳/加固 app 后：

### Step 1: 排除已处理的向量

本文档中状态为 "已处理" 的 30+ 个向量，**不需要再花时间找**。
确保使用了：
- 本仓库编译的 stealth frida-server（源码 patch 已应用）
- `anti-anti-frida-macho.py` 处理过的二进制
- `bypass_imoutai.js`（或适配后的版本）作为运行时脚本

### Step 2: IDA 分析 app 自身检测逻辑

砸壳后用 IDA 打开 app 二进制，重点关注：

1. **搜索关键 API 调用**（这些是检测函数的入口）：
   - `task_threads` / `thread_info` / `pthread_getname_np` -- 线程枚举
   - `mach_vm_region` / `vm_region_recurse_64` -- 内存布局检测
   - `sysctl` / `ptrace` / `csops` -- 进程状态检测
   - `_dyld_get_image_name` / `_dyld_image_count` -- 模块检测
   - `memmem` / `memcmp` -- 内存字符串搜索
   - `dladdr` / `dlsym` -- 符号反查

2. **重点分析 `__mod_init_func`**（constructor 函数）：
   - 检测逻辑常在 `+load` 或 constructor 中启动
   - 通过 `pthread_create` 创建后台检测线程
   - 通过 `dispatch_after` 延迟执行检测

3. **识别检测模式**：
   - 循环 `while(1)` + `sleep` 的线程 = 持续监控
   - `task_threads` + `pthread_getname_np` + 字符串比较 = 线程名检测
   - `vm_read` + CRC/hash = 代码完整性校验
   - `JUMPOUT` 或计算跳转 = 混淆的退出路径

### Step 3: 针对性处理

对 IDA 发现的检测逻辑，按优先级处理：

| 优先级 | 检测类型 | 处理方式 |
|---|---|---|
| P0 | 线程名比较字符串 | 确认 bypass 脚本已覆盖 |
| P0 | 直接 `abort()`/`exit()` 调用 | bypass 脚本已 hook |
| P1 | 内联 `svc #0x80` 退出 | Stalker 或直接 NOP patch |
| P1 | `__pthread_kill(SIGABRT)` 自杀 | hook `__pthread_kill` |
| P2 | 代码完整性 CRC | hook `vm_read` 或从 dyld_shared_cache 返回原始字节 |
| P3 | 行为指纹（线程数、port 数） | 已有 task_threads/mach_port_names hook |

---

## 6. 与 Android STEALTH_PATCHES.md 对照

| Android 章节 | iOS 适用? | iOS 状态 | 说明 |
|---|---|---|---|
| SS1.1 Exceptor signal hook | 适用 | 已实现 (SS10) | 禁用 signal/sigaction hook |
| SS1.2 ExitMonitor | 适用 | 已实现 (SS5) | 禁用 exit/abort hook |
| SS1.3 Fork/Spawn/Cloak | 低优先 | 不实现 | 仅 `enable_child_gating()` 时触发 |
| SS2.1 线程名源码重命名 | 适用 | 已实现 (SS2+SS4) | iOS 风格命名 |
| SS2.4 g_set_prgname | 适用 | 已实现 (SS1) | `com.apple.WebKit` |
| SS3 solist 隐身 | 不适用 | -- | iOS 用 dyld 不用 linker solist |
| SS4 ELF 匿名化 | 不适用 | -- | iOS 用 Mach-O |
| SS5 helper RWX | 不适用 | -- | iOS 无 procfs |
| SS6 Stalker ASLR | 适用 | 已实现 (SS8) | arm64 共用代码 |
| SS6.5 Instruction.parse | 适用 | 已实现 (SS6) | |
| SS7 /proc 路径 | 不适用 | -- | iOS 无 procfs |
| (iOS 独有) __FRIDA segment | 适用 | 已实现 (SS11) | Mach-O 特有 |
| (iOS 独有) STUN SOFTWARE | 适用 | 已实现 (SS12) | |
| (iOS 独有) pages_per_batch | 适用 | 已实现 (SS13) | |
| (iOS 独有) frida-error-quark | 适用 | 已实现 (SS14) | |

---

## 7. 部署

### deb 安装（palera1n rootless）

```bash
scp fs17910_*_iphoneos-arm64.deb mobile@DEVICE:/var/tmp/
ssh mobile@DEVICE
sudo dpkg -i /var/tmp/fs17910_*.deb

# 首次测试：手动前台运行，确认无崩溃
sudo launchctl unload /var/jb/Library/LaunchDaemons/com.local.fs17910.plist
sudo /var/jb/usr/sbin/fs17910

# 确认稳定后启用自动启动
sudo launchctl load /var/jb/Library/LaunchDaemons/com.local.fs17910.plist
```

### 手动部署

```bash
scp fs17910 fs17910d.dylib fs17910h mobile@DEVICE:/var/tmp/
ssh mobile@DEVICE
sudo mkdir -p /var/jb/usr/lib/fs179-1.0
sudo mv /var/tmp/fs17910d.dylib /var/jb/usr/lib/fs179-1.0/fs179-agent.dylib
sudo mv /var/tmp/fs17910h /var/jb/usr/lib/fs179-1.0/fs179-helper
sudo chmod +x /var/tmp/fs17910 /var/jb/usr/lib/fs179-1.0/fs179-helper
sudo /var/tmp/fs17910 &
```

### 使用 bypass 脚本

```bash
# 网络模式 (自定义端口，避免 27042 检测)
frida -H 192.168.1.x:12345 -f com.target.app -l bypass_imoutai.js --no-pause

# USB 模式
frida -U -f com.target.app -l bypass_imoutai.js --no-pause
```

---

## 8. 升级 Frida 后检查清单

1. `rpc.vala` -- `"frida:rpc"` 使用方式是否变化
2. `gumscriptscheduler.c` -- 线程名设置是否变化
3. `agent.vala` -- ExitMonitor 初始化方式是否变化
4. `darwin-host-session.vala` -- agent 描述符是否变化
5. `frida-glue.c` -- `frida-main-loop` 线程名是否存在
6. `gumdarwingrafter.c` -- `__FRIDA_TEXT/DATA` segment name 是否变化
7. `session.vala` -- `set_software("Frida")` 是否存在
8. `gumcodeallocator.c` -- `pages_per_batch` 默认值是否变化
9. `xpc.vala` -- `frida-error-quark` 是否存在
10. `gumexceptor-posix.c` -- attach/detach 函数签名是否变化
11. D-Bus 接口版本号是否从 `17` 变为 `18`（表示大版本升级）
12. `strings frida-server | grep -i frida` 验证效果

---

## 9. 文件清单

### 本仓库文件

| 文件 | 用途 |
|---|---|
| `scripts/apply-ios-stealth.sh` | 源码级 patch（14 项） |
| `scripts/anti-anti-frida-macho.py` | 二进制后处理（6 类替换） |
| `.github/workflows/build-ios-stealth.yml` | CI 自动构建 |
| `IOS_STEALTH_PATCHES.md` | 本文档 |

### bypass 脚本（工作区）

| 文件 | 用途 |
|---|---|
| `bypass_imoutai.js` | i茅台专用 bypass（17 个 hook） |

### 涉及的 Frida 源文件

| 文件 | 改动项 |
|---|---|
| `frida-gum/gum/gum.c` | SS1 prgname |
| `frida-gum/bindings/gumjs/gumscriptscheduler.c` | SS2 线程名 |
| `frida-gum/bindings/gumjs/gumquickinstruction.c` | SS6 mprotect |
| `frida-gum/bindings/gumjs/gumv8instruction.cpp` | SS6 mprotect |
| `frida-gum/gum/gumdarwingrafter.c` | SS11 segment 名 |
| `frida-gum/gum/backend-arm64/guminterceptor-arm64.c` | SS11 segment 识别 |
| `frida-gum/gum/backend-arm64/gumstalker-arm64.c` | SS8 ASLR fix |
| `frida-gum/gum/gumcodeallocator.c` | SS13 pages_per_batch |
| `frida-gum/gum/backend-posix/gumexceptor-posix.c` | SS10 signal hook |
| `frida-core/src/frida-glue.c` | SS1+SS4 prgname + 线程名 |
| `frida-core/lib/agent/agent.vala` | SS2+SS5 线程名 + ExitMonitor |
| `frida-core/lib/base/rpc.vala` | SS3 frida:rpc |
| `frida-core/lib/base/p2p.vala` | SS2 线程名 |
| `frida-core/lib/base/session.vala` | SS12 STUN SOFTWARE |
| `frida-core/lib/base/xpc.vala` | SS14 error-quark |
| `frida-core/src/darwin/darwin-host-session.vala` | SS7 agent 名随机 |
| `frida-core/server/server.vala` | SS9 目录名+线程名 |
