# Frida 隐身补丁 (Android arm64)

针对当前 Frida 主线（`subprojects/frida-gum`、`subprojects/frida-core`）的反检测改动。
目标平台 **Android arm64**，定位 **frida-server / frida-agent.so**。
设计目标是 frida 升级 submodule 后按本文档逐项 cherry-pick 即可恢复隐身能力。

约定：所有 frida-gum 侧的改动统一以 **`FRIDA_STEALTH`** 宏开关，
`subprojects/frida-gum/meson.build` 在 Linux 主机族下默认
`add_project_arguments('-DFRIDA_STEALTH=1', ...)`，
关掉只需把 `=1` 改成 `=0` 重编。

---

## 1. 默认 libc inline hook 全部关闭

### 1.1 frida-gum 三处 registry（FRIDA_STEALTH 宏包裹）

| 文件 | 函数 | 被 hook 的符号 | 用途 |
|---|---|---|---|
| `gum/backend-linux/gumthreadregistry-linux.c` | `_gum_thread_registry_activate` | `pthread_create`、C11 变体、`pthread_exit`、`pthread_setname_np` | 维护 `Process.enumerateThreads()` 实时表 |
| `gum/backend-elf/gummoduleregistry-elf.c` | `_gum_module_registry_activate` | bionic linker 的 `r_brk` / RTLD notifier trap | 监听 dlopen/dlclose 模块增删 |
| `gum/backend-posix/gumexceptor-posix.c` | `gum_exceptor_backend_attach` / `_detach` | libc `signal`、`sigaction` | 防止目标重装 signal handler 顶掉 frida 自己的 |

副作用与补救：
* module registry 缓存会陈旧 → 新增私有 API `_gum_module_registry_resync()`
  （`gum/gummoduleregistry-priv.h` 声明，`gum/backend-elf/gummoduleregistry-elf.c` 实现），
  `gum_module_registry_enumerate_modules` 每次枚举前调用一次（多走一次 `dl_iterate_phdr`）。
* thread registry 不感知新线程 → `gum_process_enumerate_threads` 在 Linux 上走
  `/proc/self/task` 实时遍历，不依赖 registry 缓存，无影响。
* signal/sigaction 不再护盘 → MemoryAccessMonitor / Stalker 在目标重装信号处理时会失效，
  Android app 几乎不重装这些信号，实际无影响。

### 1.2 frida-core ExitMonitor 默认 off

`subprojects/frida-core/lib/payload/exit-monitor.vala:38-46` 在 agent `start()` 时
无条件 `interceptor.attach` 三个 libc 函数：`exit`、`_exit`、`abort`。
每个 attach 在 `/proc/<pid>/maps` 上留一段 `rwxp` 1 页，把 `r-xp .text` 切成多段。

修改：`agent.vala::start()` 默认 `bool enable_exit_monitor = false`，
新增 `exit-monitor:on` 参数允许显式启用。
代价：进程退出时不再有 graceful `Script.unload`。

### 1.3 仅条件触发的 hook（默认不出现）

| 模块 | 文件 | hook 目标 | 触发条件 |
|---|---|---|---|
| ForkMonitor | `lib/payload/fork-monitor.vala` | `fork` / `vfork` / 安卓 zygote `selinux_android_setcontext` / `android_os_Process_setArgV0` | JS 调 `enable_child_gating()` |
| SpawnMonitor | `lib/payload/spawn-monitor.vala` | `execve` | 同上 |
| FileDescriptorGuard | `lib/payload/fd-guard.vala` | `close` | 同上 |
| Cloaker (Thread/FD List) | `lib/payload/cloak.vala` | `opendir` / `closedir` / `readdir*` | 同上 |
| ThreadSuspendMonitor / UnwindSitter | `lib/payload/{thread-suspend-monitor,unwind-sitter}.vala` | mach API / dyld API | 仅 Darwin，Android 不编译 |

如果用户脚本主动 `Interceptor.attach` 任何 libc 函数会自己产生切片。
当前**不在 user-space 做 VMA 合并**，由内核侧负责在 `/proc/<pid>/maps` 上隐藏 rwxp gap。

---

## 2. 线程名隐身

### 2.1 源码层重命名

| 文件 | 旧名 | 新名 |
|---|---|---|
| `subprojects/frida-gum/bindings/gumjs/gumscriptscheduler.c:117` | `gum-js-loop` | `Thread-Pool` |
| `subprojects/frida-core/lib/agent/agent.vala`（4 处） | `frida-eternal-agent` | `Thread-Worker` |
| `subprojects/frida-core/lib/agent/agent.vala:1412` | `frida-agent-emulated` | `Thread-Worker` |
| `subprojects/frida-core/lib/base/p2p.vala:892` | `frida-generate-certificate` | `Thread-Worker` |

### 2.2 运行时再命名

新增 `subprojects/frida-core/lib/payload/stealth-rename.{c,h}`，
导出 `int frida_stealth_rename_threads(void)`：

1. 遍历 `/proc/self/task` 收集 `(tid, name)` 对，name 从
   `/proc/self/task/<tid>/status` 第一行 `Name:` 字段取。
2. **按 tid 升序排序**，每行得到 1-based 序号 N。
3. 命中下面任一即改名：
   - 精确：`gmain`、`Thread-Pool`、`Thread-Worker`、`gum-js-loop`、
     `frida-eternal-agent`、`frida-agent-emulated`、
     `frida-generate-certificate`、`gdbus`、`dconf worker`
   - 前缀：`pool-`、`gum-`、`frida-`
4. 改名为 `Thread-<N>`（`java.lang.Thread.nextThreadNum()` 默认格式），
   通过 `open("/proc/self/task/<tid>/comm", O_WRONLY)` + `write` 直接写。

最终 `/proc/<pid>/task/*/comm` 形态：`Thread-1` / `Thread-2` / ... 与目标 app
自有线程交错，无 frida 字样。

### 2.3 调用点

`agent.vala::start()` 协程末尾（agent 全部后台线程已启动）调用一次。
之后用户脚本里 `Script.load()` 后可以再调一次。

### 2.4 GLib pool worker 名字 (`pool-frida` 透出)

`subprojects/frida-gum/gum/gum.c:305` 在 `gum_init` 里硬写
`g_set_prgname ("frida")`。后续 GLib 的 `g_thread_pool` 按需 spawn 的
worker 默认名是 **`pool-<g_get_prgname()>` = `pool-frida`**。

这种 worker 是 GLib lazy 拉起的：来 job 才 spawn、做完闲一会就退出。
**它的出生窗口完全不在 `rename_threads` 的扫描时机内**，启动时调一次
根本捕不到。

修改：把 `g_set_prgname ("frida")` 用 `#if !FRIDA_STEALTH` 包住。
关掉这个调用后，GLib 走 auto-detect 从 `/proc/self/comm` 读取，结果就是
host app 的名字（比如 `com.zhenxi.hu`），pool worker 变成
`pool-com.zhenxi.hu`，跟 app 自带的 GLib worker 完全一致。

兜底：`stealth-rename.c` 的 `exact_table` 仍然把 `pool-frida` 列入精确
匹配 —— 万一别处又把 prgname 设回 `"frida"`，下次 `rename_threads`
扫到也能改掉。

---

## 3. solist / link_map 隐身

新增 `subprojects/frida-core/lib/payload/stealth-hide.{c,h}`，导出：

```c
void frida_stealth_hide_self_from_linker (const void * any_addr_inside_module);
```

### 3.1 ELF 符号解析（自带）

不走 gum，纯 `libc + dlfcn + mmap` 实现 —— stealth-hide 在 agent 入口处运行，
早于 gum / glib 初始化。

`/proc/self/maps` 定位（`frida_elf_img_locate`）：
- **只匹配 `r-xp` 的 linker64 行**。任何被加载执行的 ELF 必有且仅有一段 `r-xp`。
  *不可以同时接受 `r--p`*：进程里可能存在别的 `r--p` 文件映射占用同一路径
  （例如 §4 改之前 gum 自己的 `GumElfModule` 会长期持着一份），命中错的就
  `load_base` 全错 —— 数据地址飘到文件副本里读出 raw `.symtab` 字节，函数地址
  落在 r--p 段（无 X 权限）BLR 进去 `SEGV_ACCERR`。
- `load_base = mapping_start - mapping_offset`：对 PIE 的 text 段恒等于真实
  load base，因为 phdr[2] 的 `p_vaddr == p_offset`。

ELF 解析（`frida_elf_img_open`）：
- mmap linker64 文件，函数返回前 `munmap`（success / bail 两条路径都释放）。
- **bias 取第一个 PT_LOAD program header 的 `p_vaddr - p_offset`** —— PIE 上是 0。
  不依赖 section header 顺序，否则碰上 `.data` PROGBITS 在 section table 排到
  `.text` 之前的布局会算错。
- section header 仅用来按名字找 `.symtab` / `.strtab`。

符号查找（`frida_elf_img_find`）：
- linear scan `.symtab`，过滤 `STT_FUNC | STT_OBJECT` 且 `st_size > 0`。
- `addr = load_base + st_value - bias`。
- 32 MiB sanity bound：addr 落在 `[load_base, load_base + 32 MiB)` 之外
  直接返回 0，不 deref 垃圾。

覆盖以下符号：

| 符号 | 类型 | 必需 | 用途 |
|---|---|---|---|
| `__dl__ZL6solist` | `soinfo*` | ✅ | solist 链头 |
| `__dl__r_debug` (或 `_r_debug`) | `r_debug` | ✅ | r_debug 全局 |
| `__dl__ZL6sonext` | `soinfo**` | best | sonext 全局地址 |
| `__dl__ZL12r_debug_tail` | `link_map**` | best | r_debug.r_map tail 私有游标 |
| `__dl__ZN18ProtectedDataGuardC2Ev` | ctor | best | linker 写锁 RAII |
| `__dl__ZN18ProtectedDataGuardD2Ev` | dtor | best | 同上 |
| `__dl__ZN20LinkerBlockAllocator4freeEPv` | `LinkerBlockAllocator::free` | best | 归还 soinfo block |
| `__dl__ZL18g_soinfo_allocator` | `LinkerBlockAllocator*` | best | soinfo allocator 实例 |
| `__dl__ZL21g_module_load_counter` | `uint64_t*` | best | dlopen 计数 |
| `__dl__ZL23g_module_unload_counter` | `uint64_t*` | best | dlclose 计数 |

`best` 项缺失就跳过对应步骤，degrade gracefully。

### 3.2 soinfo 字段偏移（Android 10+ arm64 写死）

参考 AOSP `bionic/linker/linker_soinfo.h`：

```
0x00  phdr
0x08  phnum
0x10  base       ← 用这个匹配 dladdr 的 dli_fbase
0x18  size
0x20  dynamic
0x28  next       ← 用这个走 solist + 改 prev->next
```

对于 32-bit ARM（`__work_around_b_24465209__` 触发），偏移会不同；当前不支持。

### 3.3 完整步骤

```
hide_self_from_linker(addr):
    load_symbols()
    want_base = dladdr(addr).dli_fbase   ← 必须在 unlink 前拿（dladdr 走 solist）

    unlink_link_map(want_base):
        ProtectedDataGuard {
            r_state = RT_DELETE
            prev->l_next = next; next->l_prev = prev
            if cur 是 tail 且拿到 r_debug_tail: *r_debug_tail = prev
            cur->l_next = cur->l_prev = NULL    ← 打成孤岛
            r_state = RT_CONSISTENT
        }

    unlink_solist(want_base):
        ProtectedDataGuard {
            prev->next = cur->next
            if cur 是 tail: *sonext = prev
            allocator_free(g_soinfo_allocator, cur)   ← 归还 block，避免空洞
        }

    reset_counters(1, 0):
        *g_module_load_counter -= 1               ← 抹去 dlopen 的 +1
```

关键防御点：
* **匹配走 base 不走 name** —— frida agent 通过 `dlopen("/proc/self/fd/N", ...)`
  加载，`link_map.l_name` 是 `/proc/self/fd/N`，不带 `frida-agent.so` 字样；
  按 base 比对避开这个问题。
* **摘 link_map tail 必须同步 r_debug_tail** —— 否则后续 dlopen 的新 so 挂到
  幽灵 cur 后面，从 r_map 正向遍历会丢掉之后所有 so。
* **摘完清 cur->l_next/l_prev** —— 防别处缓存指针顺着回到主链。
* **不走 `soinfo_free` / `soinfo_unload`** —— 它们触发 `~soinfo` 改动其他
  soinfo 的依赖链，观测到会 SEGV frida JS 线程。直接调
  `LinkerBlockAllocator::free` 只回收 block，副作用最小。
* **`g_module_load_counter` 必须减回去** —— dlopen 把它 +1 了，不抹会被
  读这个 counter 的反检测代码看到差 1。

### 3.4 隐身后的可观察行为

| 检测路径 | 状态 |
|---|---|
| `dl_iterate_phdr()` | 不再报告 frida-agent ✅ |
| `dlopen(name, RTLD_NOLOAD)` | 找不到 frida-agent ✅ |
| `_r_debug.r_map` 链表正向遍历 | 没有 frida-agent ✅ |
| solist 链表正向遍历（`solist_get_head`） | 没有 frida-agent ✅ |
| `LinkerBlockAllocator` 计数 | 与 solist 长度一致 ✅ |
| `g_module_load_counter` | 与 zygote 一致 ✅ |
| `/proc/<pid>/maps` 文件层 | 还有 `/memfd:frida-agent-64.so` 行 → 由内核侧处理 |

### 3.5 调用点

`agent.vala::create_and_run` 在 `cached_agent_range.base_address` 设好后立刻
调用，**早于任何后台线程 spawn**。

---

## 4. ELF 模块映射匿名化（gum 侧）

`subprojects/frida-gum/gum/gumelfmodule.c` 默认走 `g_mapped_file_new()` 把
模块文件 mmap 进来给后续的 ELF 解析读。`g_mapped_file_get_bytes` 拿到的
`GBytes` 内部仍然持着底层 mmap，`g_mapped_file_unref` 只释放包装、不释放
底层 —— 那段 `r--p` 文件映射跟随 `GumElfModule` 对象活整个进程生命周期，
在 `/proc/self/maps` 上挂着模块路径。最显眼的就是 `linker64` ——
`grep linker64 /proc/<pid>/maps` 会看到一条孤立的 `r--p offset=0` 多出来。
这条孤立映射就是 §3.1 提到的、必须用 r-xp 过滤掉的那条。

修改：在 POSIX 平台用 `open + fstat + mmap(MAP_ANONYMOUS) + read` 替代，
把文件内容灌进一段普通匿名映射。`/proc/self/maps` 上对应行没有路径，也
没有 `[anon:...]` 标签（不调 `prctl(PR_SET_VMA_ANON_NAME, ...)`），跟
任意一段 RW 分配看起来一样。

```c
#ifdef G_OS_UNIX
self->file_bytes = gum_load_file_into_buffer (self->source_path);
#else
GMappedFile * file = g_mapped_file_new (...);  /* 非 POSIX 兜底 */
...
#endif
```

`gum_load_file_into_buffer` 实现：`mmap(MAP_PRIVATE | MAP_ANONYMOUS)` 一段
RW 区 → `read()` 灌满 → `mprotect` 降到 RO → 包成 `GBytes`，destroy 回调里
`munmap` 释放。

副作用：
- 整文件 eager 进 RAM，不再 lazy paging；不再跨进程共享 page cache。
  典型 .so 几百 KB ~ 几 MB 级，可接受。
- `gum_cloak_add_range` 仍然挂着，`Process.enumerateRanges()` 内部枚举
  行为不变。

不走 `FRIDA_STEALTH` 宏 —— 改动对功能透明、无回退入口需求。

---

## 5. 注入残留（shellcode）由内核侧负责

Frida 在目标进程里**唯一**的"注入残留"是 helper 通过 ptrace 一次性 `mmap` 出来的
**anon rwx region**（包含 bootstrapper.c shellcode + loader.c shellcode + 上下文 + libc API 表 + loader 线程栈）。
来源：`src/linux/frida-helper-backend.vala:1062-1117`。

helper 在 IMMEDIATE 模式下做的就是 `munmap(allocation_base, allocation_size)`
一刀切（同文件 1397-1399）。**RESIDENT/eternal 模式下 helper 不做这一刀**。

| 隐身职责分工 | |
|---|---|
| helper anon rwx allocation（shellcode + loader stack） | **内核侧** 在 `/proc/<pid>/maps` / `smaps` 上隐藏 |
| frida-agent.so 的 link_map / soinfo | agent 本仓库 §3 |
| frida-agent.so 的 file-backed maps 行 | **内核侧** 在 maps 输出上过滤 |
| Interceptor / Stalker / JIT 的 anon rwx | **内核侧** |
| 线程名 | agent 本仓库 §2 |
| 默认 libc inline hook | agent 本仓库 §1 |

不在 user-space 做 shellcode munmap：能 munmap 的只有 helper allocation_base 那一块，
其他 anon rwx 都是 agent 运行时基础设施（不能动）。引入 timer 轮询 loader 线程死活
也带来额外崩溃面。在内核侧处理可见性更干净。

---

## 6. Stalker arm64 ctx 分配修复（frida-gum issue #793）

`subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c::gum_exec_ctx_new`：

ASLR 偶尔把 ctx 分到一个 ±128MiB 内没足够空隙的地址，后续
`gum_memory_allocate_near` 分 code/slow/data slab 全部失败。

修改：先 reserve 一段 `INT32_MAX` 的 RW 大块（让内核挑 hole 中心），立即 free，
再在原中心位置做正常 ctx 分配。

```c
base = gum_memory_allocate (NULL, INT32_MAX, stalker->page_size, GUM_PAGE_RW);
gum_memory_free (base, INT32_MAX);
base = gum_memory_allocate (base + INT32_MAX / 2, stalker->ctx_size,
    stalker->page_size,
    stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);
```

---

## 6.5 `Instruction.parse()` 不再 mprotect 目标页

### 背景

`subprojects/frida-gum/gum/gummemory.c::gum_ensure_code_readable`
在 Android API ≥ 29 上会把命中的代码页 `mprotect` 成 **`GUM_PAGE_RWX`**，
并把成功改过的页加进 `gum_softened_code_pages` 哈希表，**永不还原**。

调用链（仅列 JS API 层，gum 内部 Stalker / Interceptor / Relocator 走另一套
路径，那里改权限是必要的）：

| 文件 | 函数 | JS API |
|---|---|---|
| `bindings/gumjs/gumquickinstruction.c::gumjs_instruction_parse` | parse | `Instruction.parse(ptr)` |
| `bindings/gumjs/gumv8instruction.cpp::gumjs_instruction_parse` | parse | 同上（V8 runtime） |

`Instruction.parse()` 只是把 16 字节喂给 capstone 反汇编，**没有任何写入或
执行需求**。但 frida 高版本默认在每次 parse 之前都过一遍
`gum_ensure_code_readable`，结果是用户用脚本 `Instruction.parse(ptr)` 扫一段
target `.text` 的时候，对应那一页就从 `r-xp` 永久变成 `rwxp` ——
`/proc/<pid>/maps` 上凭空多出一段 `rwxp` 文件映射，跟 §1 关掉的 ExitMonitor
留下的 rwxp gap 是同等级的检测特征。

### 修改

`bindings/gumjs/gumquickinstruction.c:231` 与
`bindings/gumjs/gumv8instruction.cpp:296` 的 `gum_ensure_code_readable`
调用用 `#if !FRIDA_STEALTH` 包住：

```c
#if !FRIDA_STEALTH
  gum_ensure_code_readable (GSIZE_TO_POINTER (address), max_instruction_size);
#endif
```

### 副作用

执行专用映射（execute-only，PROT_EXEC 但无 PROT_READ）下 parse 会失败 ——
capstone 读不到字节。Android API 29+ bionic 自身的 linker / libc 不用 XO，
普通 app `.text` 都是 `r-xp`，实测新旧版本均无回归。如果用户脚本要 parse
某个特意做了 XO 的内存（极少见），需要自己先 `Memory.protect()` 加 `r`。

不影响：

* `Stalker` 走 `gum/backend-arm64/gumstalker-arm64.c::gum_exec_block_translate`
  里的 `gum_ensure_code_readable` —— 它需要把 target text 改可写以便就地 patch
  ldr literal 等指令，那里**不动**。
* `Interceptor.attach` 走 `gum/guminterceptor.c:1940` 的 `gum_ensure_code_readable`
  —— attach 要改 prologue，必须 RWX。**不动**。
* Relocator 走 `gum/arch-arm64/gumarm64relocator.c:417` —— 同理保留。

### 选择保留的调用点

`bindings/gumjs/gumquickmemory.c:345` 和
`bindings/gumjs/gumv8memory.cpp:308` 中的
`Memory.checkCodePointer(ptr)` 也调 `gum_ensure_code_readable(ptr, 1)`。
这是用户主动调用的 stealth-aware API（用来探测一个指针是不是合法可读代码），
**不动** —— 调用方自己负责评估 mprotect 副作用。

---

## 7. /proc 路径清单（留给内核侧）

frida 在 agent 内部读取 / readlink 的 `/proc` 路径。内核侧反检测至少要覆盖：

### 7.1 readlink / readlinkat

| 路径 | 调用方 | 推荐内核行为 |
|---|---|---|
| `/proc/self/exe` | `process-glue.c::frida_try_get_executable_path` | 返回真实进程 exe，无需改 |
| `/proc/self/fd/<N>` | `cloak.vala::file_descriptor_is_proc_self_stat` | agent memfd 对应的 readlink 不返回 `memfd:frida-agent-64.so` |

### 7.2 open + read

| 路径 | 调用方 | 推荐内核行为 |
|---|---|---|
| `/proc/self/maps` | `gum/backend-linux/gumprocess-linux.c:2250` 等多处 | 在 vfs read 路径上过滤掉 frida-agent 行 + 匿名 rwx loader 行 |
| `/proc/self/cmdline` | `fork-monitor.vala`、`gadget.vala`、`gummoduleregistry-linux.c` | 不用改 |
| `/proc/self/auxv` | `gummoduleregistry-linux.c:635` | 不用改 |
| `/proc/self/status` | `gum/backend-linux/gumprocess-linux.c:507` | 不用改（frida 自己读） |
| `/proc/self/task/` (opendir) | `cloak.vala`、`stealth-rename.c` | 不用改 |
| `/proc/self/task/<tid>/comm` | `gum/backend-linux/gumprocess-linux.c:1606`、`stealth-rename.c` | 不用改 |
| `/proc/self/task/<tid>/stat` | `gum/backend-linux/gumprocess-linux.c:1625` | 不用改 |

第三方 anti-cheat 通常会读 `/proc/<pid>/maps` 检测自己进程里的 frida 映射 —— §3 的
solist/link_map 隐身只搞定了 ABI 层，文件层仍需内核侧 hook。

---

## 8. 验证脚本

`stealth-verify.js`（注入到目标进程跑）：
* 走 `_r_debug.r_map` 链
* 走 `solist` 链（用 `solist_get_head()` 拿真正的链头，不要用 `solist_get_somain()`，
  后者从主 EXE 起步会漏掉 EXE 之前的节点如 `__libdl_info`）
* 跨链 diff：哪些 base 仅出现在 r_map / 仅出现在 solist
* sorted-by-node-addr 视图：相邻 soinfo 节点地址差应恒等于 LinkerBlockAllocator 的
  `block_size`（≈0x488 字节）。差 N×block_size 表示中间有 (N-1) 个 block 被泄漏
  没归还 allocator。
* `/proc/self/maps` 兜底 grep `frida` 字样

期望输出：

```
r_map  : 307 / 0 嫌疑 ✅
solist : 307 / 0 嫌疑 ✅
maps   : 0 frida 字样 ✅（依赖内核侧）
仅 r_map 独有: 0   仅 solist 独有: 0
统计: 紧贴=N, 跨 page=M, 被跳过的空闲 slot=0   ← 关键
```

"被跳过的空闲 slot = 0" 表示 §3 的 `LinkerBlockAllocator::free` 调用真的
回收了 block，allocator 计数器与 solist 长度一致。

脚本完整内容见仓库根目录 `stealth-verify.js`（同步随本仓库更新）。

---

## 9. 文件清单

新增：
- `subprojects/frida-core/lib/payload/stealth-rename.h`
- `subprojects/frida-core/lib/payload/stealth-rename.c`
- `subprojects/frida-core/lib/payload/stealth-hide.h`
- `subprojects/frida-core/lib/payload/stealth-hide.c`
- `subprojects/frida-core/lib/payload/stealth.vapi`
- `STEALTH_PATCHES.md`（本文档）
- `stealth-verify.js`（验证脚本，可选）

修改：
- `subprojects/frida-gum/meson.build`：定义 `FRIDA_STEALTH=1`
- `subprojects/frida-gum/gum/backend-linux/gumthreadregistry-linux.c`
- `subprojects/frida-gum/gum/backend-elf/gummoduleregistry-elf.c`
- `subprojects/frida-gum/gum/gummoduleregistry-priv.h`
- `subprojects/frida-gum/gum/gummoduleregistry.c`
- `subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c`
- `subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c`
- `subprojects/frida-gum/gum/gumelfmodule.c`：模块文件改走匿名 buffer（§4）
- `subprojects/frida-gum/bindings/gumjs/gumscriptscheduler.c`
- `subprojects/frida-gum/bindings/gumjs/gumquickinstruction.c`：parse 不再 mprotect（§6.5）
- `subprojects/frida-gum/bindings/gumjs/gumv8instruction.cpp`：parse 不再 mprotect（§6.5）
- `subprojects/frida-core/lib/payload/meson.build`
- `subprojects/frida-core/lib/agent/agent.vala`
- `subprojects/frida-core/lib/base/p2p.vala`

---

## 10. 编译（Android arm64）

### 10.1 一次性环境准备

需要：`gcc`、`g++`、`make`、`cmake`、`ninja`、`python3 ≥ 3.10`、`unzip`、`curl`。
不需要本机 Vala / GLib / pkg-config —— frida configure 会下 prebuilt toolchain。

```bash
# 1) Android NDK r29（frida-core 的 NDK_REQUIRED 写死 29，r27/r28 不行）
mkdir -p ~/android-ndk && cd ~/android-ndk
curl -L -o ndk.zip https://dl.google.com/android/repository/android-ndk-r29-linux.zip
unzip -q ndk.zip && rm ndk.zip
export ANDROID_NDK_ROOT=$HOME/android-ndk/android-ndk-r29

# 2) Linux Node.js ≥ 18（compiler backend 编 TS 用）
cd ~ && curl -L -o node.tar.xz https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.xz
tar xf node.tar.xz && rm node.tar.xz && mv node-v20.18.0-linux-x64 node-linux
export PATH=$HOME/node-linux/bin:$PATH
```

### 10.2 拉子模块

```bash
cd /path/to/frida
git submodule update --init subprojects/frida-gum subprojects/frida-core releng
```

### 10.3 配置 + 编译

```bash
export ANDROID_NDK_ROOT=$HOME/android-ndk/android-ndk-r29
export PATH=$HOME/node-linux/bin:$PATH

./configure \
    --host=android-arm64 \
    --enable-server \
    --disable-frida-tools \
    --disable-frida-python \
    --disable-graft-tool \
    --disable-inject \
    --disable-gadget

make -j$(nproc)
```

第一次 configure 会自动从 `https://build.frida.re/deps/` 下：
* `toolchain-linux-x86_64.tar.xz`（vala-0.58、ninja、glib-mkenums 等）
* `sdk-android-arm64.tar.xz`（GLib、Capstone、QuickJS、V8、libsoup 等的 arm64 静态库）

输出：

| 路径 | 说明 |
|---|---|
| `build/subprojects/frida-core/server/frida-server` | 51 MB ELF aarch64，可直接 push 到 `/data/local/tmp/` |
| `build/subprojects/frida-core/lib/agent/frida-agent.so` | 24 MB，agent；正常会被 server 通过 memfd 注入 |
| `build/subprojects/frida-core/src/frida-data-agent-blob.S.p/frida-agent-arm64.so` | strip 后的 agent，作为 server 资源被嵌入 |

### 10.4 验证 stealth 改动确实在产物里

```bash
NM=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump

# stealth 入口都在 agent.so 里
$NM --syms build/subprojects/frida-core/lib/agent/libfrida-agent-raw.so | grep stealth_
# 期望:
#   frida_stealth_rename_threads
#   frida_stealth_hide_self_from_linker

# 源码层线程名也在
strings build/subprojects/frida-core/lib/agent/frida-agent.so | grep -E '^Thread-(Pool|Worker)$'
# 期望:
#   Thread-Pool
#   Thread-Worker
```

### 10.5 部署到设备

```bash
adb push build/subprojects/frida-core/server/frida-server /data/local/tmp/
adb shell "chmod +x /data/local/tmp/frida-server"
adb shell "su -c '/data/local/tmp/frida-server &'"
```

### 10.6 增量重编

只改 `lib/payload/stealth-*.{c,h}` 直接 `make`，不必重 configure。
改 `meson.build` / `meson.options` / `*.vapi` 才需要 `rm -rf build && ./configure ...`。

---

## 11. 升级 frida 后的回填 checklist

1. `git submodule update --remote subprojects/frida-gum subprojects/frida-core`
2. 把 `subprojects/frida-gum/meson.build` 里的
   `add_project_arguments('-DFRIDA_STEALTH=1', language: languages)` 补回去。
3. 检查以下函数签名 / 行为是否变化，必要时 reapply：
   - `_gum_thread_registry_activate` (gumthreadregistry-linux.c)
   - `_gum_module_registry_activate` (gummoduleregistry-elf.c)
   - `gum_module_registry_enumerate_modules` (gummoduleregistry.c)
   - `gum_exceptor_backend_attach` / `_detach` (gumexceptor-posix.c)
   - `gum_exec_ctx_new` (gumstalker-arm64.c)
   - `gum_script_scheduler_start` (gumscriptscheduler.c)
   - `gum_elf_module_load` 中 `g_mapped_file_new` 的调用（gumelfmodule.c，§4）
   - `gumjs_instruction_parse` 中 `gum_ensure_code_readable` 的调用
     （gumquickinstruction.c / gumv8instruction.cpp，§6.5）
   - `Frida.Agent.Runner.create_and_run` / `start` / `keep_running_eternalized` (agent.vala)
4. 保留 `subprojects/frida-core/lib/payload/meson.build` 里 `payload_sources` 和
   `payload_vala_args` 末尾两段。
5. 关注 bionic 升级：
   - 若 `soinfo` 字段顺序变了 → 检查 `stealth-hide.c` 里 `BIONIC_SOINFO_BASE_OFF` /
     `BIONIC_SOINFO_NEXT_OFF` 是否仍是 0x10 / 0x28。
   - 若 `r_debug` 加了新字段 → 检查 `frida_stealth_unlink_link_map` 中
     `r_state` 写入的兼容性。
   - 若 LinkerBlockAllocator 改名或 mangling 变了 → 更新
     `__dl__ZN20LinkerBlockAllocator4freeEPv` / `__dl__ZL18g_soinfo_allocator` 字符串。
6. 验证：`adb shell "cat /proc/<pid>/maps | grep linker64"` 应该只看到加载段
   （4 行：r--p / r-xp / r--p / rw-p），不再有孤立的 r--p 文件映射。
   若多出一行说明 §4 的 gum 改动没有 reapply。
