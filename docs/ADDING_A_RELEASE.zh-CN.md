# 添加一个固件版本

[English](ADDING_A_RELEASE.md) | **简体中文**

除了工具自己能发现的部分，dumper 只需要每个版本的两个值：

| 值 | 含义 |
|---|---|
| `DS` | A53 侧 `mp4_debug_status_t` 的 EL3 VA —— `offset` 加在它上面的基址 |
| `IMAGE` / `SIZE` | 已加载 `a53.elf` 的 EL3 VA，以及它的字节长度 |

其余全部 —— 命令号、MDSR 字段偏移、线格式、响应布局、传输层发现 —— 在所有已核对的
版本（4.02 … 7.61 … 12.00）上都相同，不需要按版本做任何事。

**第 1–3 步不写 A53。只有第 4 步会写。**

---

## 1. 用 `scan` 定位 `DS_PA`（零写入）

MDSR 实例位于紧接 TMR12 之后的 host 可读窗口内。扫描器逐页遍历，寻找 magic：

```bash
run scan
```

12.00 实测：

```
scan window [0x60600000, 0x60800000) for magic1=0xcbb3d18a1aa5daef
HIT ds_pa=0x60700000 off=0x1000 size=0x60000 last=0x9808 count=0
  -> usable core0 candidate
HIT ds_pa=0x60780000 off=0x1000 size=0x60000 last=0x72e3 count=0
  -> usable core1 candidate
VERDICT: SCAN_OK found=2
```

只有以下条件全部成立才算命中，用以滤掉无关数据造成的假阳性：

```
page[0..8)      == 0xcbb3d18a1aa5daef
+0x208 (offset) <= 0x10000
+0x210 (size)   in (0, 0x1000000]
+0x220 (count)  == 0            /* 环未回绕 */
```

dumper 用 `core0`；`core1` 是 IO 侧。

若 `SCAN_EMPTY`，说明窗口挪动了。调整 `src/main.c` 顶部的 `SCAN_LO`/`SCAN_HI`，
或先用一个只读的逐页扫描器确认窗口范围。

## 2. 推出 `DS`

`DS` 是 `offset` 的基址，必须来自 **A53 段表**，不能猜。

12.00 的关系是 `DS = DS_PA + 0x28000000`（`0x60700000` → `0x88700000`）。这个 delta 是
G6 到 host PA 的映射；**能否跨版本稳定未经证实**，所以用下面两种方式之一定下来：

| 路线 | 做法 |
|---|---|
| A —— 有段表 | 从 EL3 启动日志里读 `MM_MDSR` 那一行（12.00：`0x88700000`，mli 19）|
| B —— 无日志 | 先按 `DS = DS_PA + 0x28000000` 填，让门去校验 |

路线 B 是安全的，因为门的顺序是这样设计的：第 1 道门读的是 `ds_pa`，`DS_PA` 错了会
立刻被抓到；第 2 道门用 `DS` 计算落点，`DS` 错了落点就落在所有声明区间之外，**arming
之前**就被拒绝。两种失败模式都不会破坏 A53。

## 3. 定位 `IMAGE` 与 `SIZE`

`SIZE` 必须精确，`one` 用它来截断产物。

| 版本 | `SIZE` |
|---|---|
| 4.02 / 4.03 | `0x1116B8` |
| 4.50 | `0x111100` |
| 5.10 … 7.61 | `0x1212F8` |
| 12.00 | `0x171140` |
| 13.60 | `0x171140` |

`IMAGE` 的来源，按优先级：

1. **EL3 启动日志** —— 直接写明（12.00：`a53.elf @ host PA 0x60100000 /
   G6 0x88100000`）。这是唯一无歧义的来源，能用就用。
2. **mp4rw 候选表** —— `0x88100000`、`0x88440000`、`0x8A000000`。
3. **段表偏移** —— 映像通常在 `DS + 0x28000000 - 0x6000000` 附近
   （12.00：`0x88700000 - 0x6000000 = 0x88100000`）。

**故意不提供** `IMAGE` 的自动 ELF-magic 扫描器：定位它需要读原语，而读原语需要
profile —— 这是个自举闭环。请用启动日志。

## 4. 写 profile 并验证

```bash
cat > /tmp/a53dump.profile <<EOF
DS=0x88700000
DS_PA=0x60700000
IMAGE=0x88100000
SIZE=0x171140
RANGE0=0x88271140 0x88400000
RANGE1=0x885EA0E8 0x88700000
RANGE2=0x88701000 0x88770000
RANGE3=0x88781000 0x887e0000
EOF
curl -sS -T /tmp/a53dump.profile "ftp://$PS5:2121/data/a53dump.profile"
```

整镜像读时，`RANGE*` 必须包含落点 `IMAGE + SIZE`。优先选段表 `pmax` 与 `LIMIT`
之间的空洞 —— A53 自己不用它。退而求其次用日志环（`DS + 0x1000`，`0x60000` 字节）。

然后按顺序过门：

```bash
run base     # 必须打印 GATE1 OK
run probe    # 必须打印 PROBE_OK
run one      # 必须打印 GATE2 OK、GATE3 OK、READ_OK
```

检查产物：

```bash
curl -s "ftp://$PS5:2121/data/a53dump.bin" -o new.bin
xxd -l 64 new.bin          # 7f 45 4c 46 ...
sha256sum new.bin          # 记下来，作为该版本的基线指纹
```

## 5. 往内置表加一行

在 `src/profile.c` 里：

```c
#define R13_0 { 0x88XXXXXXULL, 0x88YYYYYYULL }   /* 第 4 步得到的落点区间 */

...
    { "13.60", 0x88700000ULL, 0x60700000ULL, 0x88100000ULL, 0x1A0000ULL,
      0x885ECD0CULL, 0x88700000ULL, 1, { R13_0 } },
```

**`one` 跑通之前不要加这一行。** `DS` 错了会被第 1 道门抓到，但 `DS` 正确而 `RANGE`
错误的情况下，`one` 会去读它本不该读的内存。

---

## 12.00 之后的已知风险

| 风险 | 证据 | 影响 |
|---|---|---|
| 地址窗口校验器 | 13.60 新增 `0x2951C`，12.00 没有这个函数。它按描述符表校验地址落在哪个窗口。| **13.60 实测无影响**（`one` 与 `elfmeta` 均通过）；后续版本仍需关注 |
| handler 搬家 | `0x01190201` 的 handler：`0x1123E4`（4.02）→ `0x111C60`（5.10）→ `0x111AE0`（7.61）→ `0x111764`（12.00）| **无影响** —— dumper 从不按地址调用 handler |
| 命令表位置 | `0x1221D8`（4.02）→ `0x11F1D8`（7.61）→ `0x11F1E0`（12.00）| **无影响** —— dumper 不读这张表 |

dumper 只依赖 `DS`、`IMAGE`、`SIZE`。其余要么运行时自发现，要么版本无关 ——
这就是为什么加一个版本只要上面五步。
