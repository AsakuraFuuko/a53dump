# a53dump

[English](README.md) | **简体中文**

dump 出运行在 PS5 A53 协处理器上的 `a53.elf` 镜像。用一条**不需要 host 递交地址**
的 SDBGP 命令实现。

- **许可证**：GPL-3.0-or-later —— 这是**强制**的，不是选择，原因见[致谢](#致谢)。
- **已验证版本**：12.00、13.60。
- **实测结果**：两个版本均为 1,511,744 字节：
  - `12.00`：`sha256 4f3411746d0fd3826c80eefeb4eed1ecea2e632eca377ac015c0d6a6d062f241`
  - `13.60`：`sha256 94cbeb0a72a2a41650fac8d3858261ce6f33e480e3c0e841d72fddd0ddff576f`

---

## 原理

SDBGP 命令 `0x01190201` **不接受** host 递交的地址。它的 handler 从 A53 自己的
调试状态结构里取读窗口：

```c
base = (u8 *)ds + ds->mds_ttyp_buffer_offset;   /* +0x208 */
len  = ds->mds_ttyp_buffer_count                /* +0x220 */
     ? ds->mds_ttyp_buffer_size                 /*   +0x210 */
     : ds->mds_ttyp_buffer_last;                /*   +0x218 */
```

其中三个字段位于 host 可写窗口内，写它们就能把这条命令变成对**任意** EL3 虚拟地址的读：

```
读基址 = DS + offset      /* offset 是 u64，2^64 回绕就是机制本身 */
读长度 = last
```

其余部分与版本无关，已在 4.02 … 7.61 … 12.00 … 13.60 上核对：命令号、MDSR 字段偏移、
`deci5s_memory_arg` 线格式、响应布局（`+0x60` 文本长度、`+0x68` 载荷），以及传输层
发现链（`mp4sc + 0x18` → bushandle `+0x10` → `zcn_bar2`）。

随版本变化的常量放在 *profile* 里：`DS`、`DS_PA`、`IMAGE`、`SIZE`，以及允许被覆盖的
落点区间。见 `src/profile.c`。

---

## 安全模型

handler 会在 `landing = 读基址 + 读长度` 处写一段日志，**破坏该区间**。所以在信任任何
数据之前有三道门：

| 门 | 检查 | 执行时机 |
|---|---|---|
| 1 | `ds` 处 magic == `0xcbb3d18a1aa5daef` | 任何写之前，包括 `base` |
| 2 | `landing` 落在 profile 声明的无害区间内 | arming 之前 |
| 3 | 读到的数据是 ELF（`7f454c46`、`e_machine == 0xb7`、`e_phnum`/`e_phoff` 合理）| 信任结果之前 |

未知的固件版本永远走不到 arming 代码：`a53_profile_resolve()` 返回 `-1`，进程以退出码
2 结束，A53 完全未被触碰。每一处写入都会先回读验证，通过后才发 SDBGP 命令。

溢出量**不是常数**（不同运行实测 `0x8c` 与 `0x46`），因为 `last` 是 A53 自己的日志
游标，arming 到 handler 读取之间它会被推进。所以 `one` 按 profile 声明的 `SIZE` 截断
产物，`dump` 按实测长度推进。

---

## 构建

需要 [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk)，以及已加载、能提供
`kernel_copyin`/`kernel_copyout` 的内核注入。

```bash
make                       # -> a53dump.elf
make SDK=/path/to/sdk
```

## 部署与运行

```bash
PS5=<主机 IP>

curl -sS -T a53dump.elf \
  "ftp://$PS5:2121/data/pldmgr/payloads/a53dump/a53dump.elf"

run() {
    printf '%s\n' "$1" > /tmp/m
    curl -sS -T /tmp/m "ftp://$PS5:2121/data/a53dump.mode"
    curl -sS --ftp-create-dirs -T /dev/null "ftp://$PS5:2121/data/a53dump.log"
    curl -s -X POST -H "Origin: http://$PS5:8084" -H 'X-PLDMGR-Request: 1' \
      "http://$PS5:8084/loadpayload:/data/pldmgr/payloads/a53dump/a53dump.elf"
    sleep 10
    curl -s "ftp://$PS5:2121/data/a53dump.log"
}

run base     # 零写入；必须打印 GATE1 OK
run one      # 整镜像
curl -s "ftp://$PS5:2121/data/a53dump.bin" -o a53_image.bin
run restore  # 必须打印 VERDICT: RESTORED
```

payload 启动时只读一次 mode 文件，换模式需要重新 `loadpayload`。

## 模式

| 模式 | 写 A53 | 用途 |
|---|---|---|
| `version` | 否 | 从主机自己读 release 字符串（`GET_CONF`）|
| `scan` | **否** | 扫 host MDSR 窗口找 magic，输出 `ds_pa` 候选 |
| `base` | **否** | 解析 profile、过第 1 道门、打印 MDSR 字段 |
| `probe` | **否** | 发一次 `0x01190201`，把文本长度与环游标比对 |
| `one` | 是 | arm → 读整镜像 → 还原 → 按 `SIZE` 截断 |
| `elfmeta` | 是 | 读映像之外的 `.shstrtab` 与 section header 表 |
| `dump` | 是 | 分片驱动；仅在 `landing` 落在被读区间**之外**时可用 |
| `restore` | 是 | 还原保存的 MDSR 字段 |

> 12.00 上 `dump` **不能**用于整镜像：分片的落点必然落在尚未读取的区间内部，
> 第 2 道门会拒绝。整镜像请用 `one`。

## 添加一个固件版本

内置表在 `src/profile.c`。新增步骤见 [`docs/ADDING_A_RELEASE.zh-CN.md`](docs/ADDING_A_RELEASE.zh-CN.md)，
简述：

1. `run scan` —— 零写入定位 `DS_PA`
2. 从 EL3 段表（`MM_MDSR`）推 `DS`；第 2 道门会校验它
3. 从启动日志（无歧义）或 `mp4rw` 候选表定位 `IMAGE`/`SIZE`
4. 写 `/data/a53dump.profile`，然后依次跑 `base` → `probe` → `one`
5. 往 `g_builtin` 加一行

**13.60 已完成实机端到端验证**（`one` 与 `elfmeta` 均通过）：新增的地址窗口校验器
（`0x2951C`）不会拒绝 `0x01190201` 读取映像或 ELF 元数据。其他未测试版本仍会直接**拒绝**，而不是猜。

## 产物

| 路径 | 内容 |
|---|---|
| `/data/a53dump.bin` | `one`：整镜像并按 `SIZE` 截断；`dump`：追加 |
| `/data/a53dump.shstrtab.bin` | `elfmeta`：节名字符串表 |
| `/data/a53dump.shdrs.bin` | `elfmeta`：section header 表 |
| `/data/a53dump.log` | 每次运行追加 |
| `/data/a53dump.save` | arming 前的 MDSR 字段 |
| `/data/a53dump.state` | `dump` 的续读游标 |
| `/data/a53dump.profile` | 可选的按版本覆盖 |

`one` 只给**加载映像**。要拼成能 `readelf` 的 ELF，接着跑 `elfmeta`，然后拼装：

```python
import struct
img = open('a53dump.bin', 'rb').read()
sh  = open('a53dump.shstrtab.bin', 'rb').read()
hd  = bytearray(open('a53dump.shdrs.bin', 'rb').read())

SHSTR_OFF = 0x171140          # .shstrtab 的文件偏移，取自 shdr[shstrndx]
SHOFF     = struct.unpack_from('<Q', img, 0x28)[0]

hd[0:64] = b'\0' * 64        # sec[0] 按定义是 SHT_NULL
struct.pack_into('<I', hd, 64, 0)  # sec[1].sh_name：表头部分已丢失

out = bytearray(b'\0' * (SHOFF + len(hd)))
out[0:len(img)] = img
out[SHSTR_OFF:SHSTR_OFF + len(sh)] = sh
out[SHOFF:SHOFF + len(hd)] = hd
open('a53_complete.elf', 'wb').write(bytes(out))
```

`.shstrtab` 的前 `0x8c` 字节是**永久性损伤**，`elfmeta` 会把它置零；受影响的
`sh_name` 会由自检报告出来。两种情况下 `readelf -h` 都无警告。

---

## 致谢

**GPL-3.0-or-later 在这里是强制的，不是选择**：`src/a53_transport.c` 是
[`drakmor/ppr-patch`](https://github.com/drakmor/ppr-patch) 的 `a53_transport.c` 的
**修改衍生物**，上游是 GPL-3.0。以 MIT 发布本项目构成许可证违规，因此整体采用
GPL-3.0-or-later。

- **drakmor/ppr-patch** —— 传输层（`src/a53_transport.c`）。PPR 补丁入口已删除，
  只保留 SDBGP 包路径。
- **astrelsky/mp4rw** —— SDBGP 命令命名、`0x43` 读法思路、
  `0x88100000 / 0x88440000 / 0x8A000000` 镜像基址候选表。

本文使用的通道并非取自上述任一项目：它们都没有把 `mds_ttyp_buffer_offset` 当作
任意 EL3 VA 的基址来驱动。

## 法律

限于自有硬件上的研究与互操作性工作。本项目不含任何 Sony 代码、密钥或固件二进制；
固件布局是通过读取设备自身暴露给 host 的结构推导的。使用本工具产出的 dump 数据
在你所在司法辖区可能受法律限制，作者不分发任何 dump 数据。

使用方式及遵守适用法律、遵守你对主机的任何约定，由你自行负责。
