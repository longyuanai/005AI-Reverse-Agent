# ADR-002: 融合开源逆向分析能力的 Phase-2 架构

**状态**: 已实施  
**日期**: 2026-07-29  
**决策人**: 项目负责人  
**实施人**: Codex

## 1. 背景

005 AI-Reverse-Agent 已具备多架构 Capstone 反汇编、控制流图、轻量符号执行、
反混淆规则骨架、PE/ELF import 提取、imphash、本地 Finding 和 v0.5 envelope。

当前实现适合作为契约与测试骨架，但存在以下工程缺口：

1. PE/ELF import parser 主要面向仓内 fixture，真实恶意样本兼容性不足。
2. XOR/RC4 检测依赖测试 marker，不是真实二进制解码器识别。
3. 反混淆规则已注册，但尚未完整接入 CLI scan 的真实特征流水线。
4. 当前排序 import MD5 与行业通用 pefile imphash 语义不同。
5. 合成的 malware hash 数据只能作为 fixture，不能等同于有来源的威胁情报。

本 ADR 融合 capa、FLOSS、angr、Ghidra、LIEF 与 pefile 的成熟设计，但保持本项目
“Python 轻核心、Windows 兼容、静态分析、不执行样本、v0.5 契约冻结”的边界。

## 2. 参考项目与吸收点

### 2.1 Mandiant capa

吸收：

- “后端提取特征，规则只消费统一特征”的分层架构。
- file / function / basic-block / instruction 四级 scope。
- 可组合规则、规则命中证据、规则版本与命名空间。
- 外部分析后端通过 adapter 接入，不污染核心规则。

不直接复制：

- 不把完整 capa 依赖树放入默认安装。
- 不在本阶段引入动态沙箱报告。

### 2.2 Mandiant FLOSS

吸收：

- 区分 static、stack、tight、decoded strings。
- 先识别解码函数，再尝试恢复字符串。
- 解码结果必须携带函数地址、数据地址、算法和置信度。

不直接复制：

- FLOSS/Vivisect 作为可选 adapter，不进入默认依赖。
- 不以模拟执行替代本项目的静态默认路径。

### 2.3 angr

吸收：

- 架构无关中间特征。
- 对 opaque predicate 使用有界可满足性分析。
- 对间接跳转、状态变量和 CFG 恢复提供深度后端接口。

不直接复制：

- angr 不进入默认 scan。
- 不允许无边界符号执行；必须有函数、路径、步数和时间预算。

### 2.4 Ghidra

吸收：

- headless 分析必须作为独立后端和独立进程。
- 统一导入函数、P-Code、反编译文本和 CFG 的数据交换格式。
- 后端必须支持超时、临时项目清理和资源预算。

本阶段不实施：

- Ghidra/PyGhidra 保持 v1.0+ 候选。
- 默认安装不要求 JDK。

### 2.5 LIEF

吸收：

- PE、ELF、Mach-O 使用统一 Binary/Section/Symbol/Import 抽象。
- parser 与上层分析逻辑隔离。

本阶段不采用为核心依赖：

- LIEF 依赖 native wheel，Windows + Python 3.14 兼容性需单独验证。
- 当前范围只有 PE/ELF/raw，纯 Python 后端风险更低。

### 2.6 pefile

吸收：

- PE import、ordinal、异常结构和资源上限处理。
- 与行业工具兼容的标准 PE imphash。
- malformed PE 产生结构化错误，不导致进程退出。

## 3. 已批准决策

### 3.1 核心依赖

批准新增：

```toml
pefile = "*"
pyelftools = "*"
networkx = "*"
```

正式实施时使用经过验证的最低版本约束，不使用无上限的实际生产配置。

职责：

- `pefile`: PE import、delay import、ordinal 与标准 pe_imphash。
- `pyelftools`: ELF dynamic symbols、relocations、GOT/PLT import。
- `networkx`: SCC、dominators、循环、dispatcher 中心性和 CFG 统计。

现有手写 parser 保留为：

- fixture backend；
- 无可选依赖环境的 minimal fallback；
- 与成熟 backend 进行 differential test 的基准。

### 3.2 双 hash

同时保留两个明确命名、不可混用的 hash。

#### `pe_imphash`

行业兼容算法：

1. 使用 PE import 原始顺序。
2. DLL 名小写，并去除 `.dll`、`.sys`、`.ocx`。
3. 函数名小写。
4. ordinal 使用兼容表解析。
5. `dll.function` 以逗号连接。
6. MD5。

用途：

- 与 pefile、YARA、VirusTotal 等生态兼容。
- 查询有来源的 malware imphash 数据。
- 只有可信数据库精确命中时允许产生 HIGH Finding。

#### `import_set_hash`

当前项目算法：

1. 规范化 `library.function` 并小写。
2. 按字典序排序。
3. 以逗号连接。
4. MD5。

用途：

- 忽略链接顺序的 import 集合相似性。
- patch diff、同源样本聚类和仓内历史兼容。
- 不得以 `imphash` 名称对外输出。

兼容策略：

- 现有 `compute_imphash()` 暂时保留，作为 deprecated legacy alias。
- 新 API 使用 `compute_pe_imphash()` 与 `compute_import_set_hash()`。
- envelope 仅在显式 enrichment 时新增字段，默认输出不变。

## 4. 目标架构

```text
InputGuard
  └─ BinaryLoader
       ├─ PeFileBackend
       ├─ ElfToolsBackend
       ├─ RawBackend
       └─ MinimalFixtureBackend
            ↓
       FeatureIndex
       ├─ file features
       ├─ function features
       ├─ basic-block features
       └─ instruction features
            ↓
       Analysis Services
       ├─ RuleEngine
       ├─ ImportHashService
       ├─ StringRecoveryService
       ├─ CFGAnalysisService
       └─ BoundedSymbolicService
            ↓
       FindingMapper
            ↓
       v0.5 IntegrationGateway envelope
```

核心数据流要求：

- 二进制只解析一次。
- 特征只提取一次，可供多个规则复用。
- 规则不得重新打开文件或直接依赖具体 parser。
- Finding 必须能回溯到规则、算法、地址、证据和 backend。

## 5. 计划目录

```text
src/ai_reverse_agent/
├── backends/
│   ├── base.py
│   ├── pefile_backend.py
│   ├── elftools_backend.py
│   ├── raw_backend.py
│   └── minimal_backend.py
├── features/
│   ├── model.py
│   ├── extractor.py
│   ├── imports.py
│   ├── strings.py
│   ├── cfg.py
│   └── constants.py
├── hashing/
│   ├── pe_imphash.py
│   ├── import_set_hash.py
│   └── models.py
├── deobfuscation/
│   ├── cff.py
│   ├── opaque_pred.py
│   ├── string_xor.py
│   ├── string_rc4.py
│   └── scoring.py
└── integrations/
    ├── capa_backend.py
    ├── floss_backend.py
    ├── angr_backend.py
    └── ghidra_backend.py
```

`integrations/` 中的模块先定义接口；capa/FLOSS/angr/Ghidra 不加入本阶段默认依赖。

## 6. 分阶段实施

### ISSUE 1 · BACKEND-001

- 引入 pefile、pyelftools、networkx。
- 建立 `BinaryLoader` 与 backend protocol。
- PE/ELF 真实 import 提取。
- 与现有 fixture parser 做 differential tests。

### ISSUE 2 · HASH-002

- 新增 `pe_imphash` 与 `import_set_hash`。
- 使用 pefile golden result 验证标准算法。
- 数据库增加 `algorithm`、`version`、`provenance`。
- 合成的 1000 条数据标记 `fixture`，生产扫描不产 HIGH。

### ISSUE 3 · FEATURE-001

- 建立 FeatureIndex 和四级 scope。
- CLI scan 调用真实 RuleEngine。
- entry-point rules 只消费 FeatureIndex。
- 保持默认 envelope 字段和 Finding 顺序兼容。

### ISSUE 4 · DEOBF-002

- XOR：无 marker 的单字节/重复 key 候选恢复与评分。
- RC4：KSA/PRGA 结构识别；无法证明 key/data 时只报算法迹象。
- Opaque predicate：调用现有轻量符号执行做有界求解。
- CFF：结合 SCC、dominance、dispatcher indegree、tiny blocks 和状态变量。

### ISSUE 5 · OPTIONAL-ADAPTERS

- capa adapter：能力规则结果转 Finding。
- FLOSS adapter：真实 decoded/stack/tight strings 转 Finding。
- angr/Ghidra 仅保留接口和能力探测，实际接入另立 v1.0+ issue。

## 7. Finding 与数据库规则

Finding 至少记录：

```json
{
  "rule_id": "reverse.string-xor",
  "backend": "native|floss|capa|angr|ghidra",
  "algorithm": "xor|rc4|pe-imphash-v1|import-set-md5-v1",
  "address": "0x401000",
  "confidence": 0.85,
  "evidence": [],
  "database_version": "..."
}
```

严重性策略：

- `HIGH`: 可信来源数据库的标准 `pe_imphash` 精确命中。
- `MEDIUM`: 多信号 CFF、opaque predicate、可验证字符串解码。
- `LOW/INFO`: 单一启发式、可疑算法结构、import-set 相似性。
- fixture 或无 provenance 数据不得产生生产 HIGH。

## 8. 安全与资源边界

- 不解析超过 100 MiB 的文件。
- 读取完整文件前检查 size 和 magic。
- 不执行样本，不启动 sandbox。
- 解析循环、字符串、section、symbol、relocation 数量都有硬上限。
- 符号执行必须限制函数、路径、步数、内存和时间。
- Ghidra/angr/FLOSS 若启用，必须独立进程、超时、可终止。
- 本地 malware 数据库不联网更新。
- 所有样本必须是自有、公开许可、编译生成或安全 fixture。

## 9. 验收标准

1. 现有测试全部通过。
2. `tests/test_cli_envelope.py` 不修改。
3. 默认 CLI envelope 逐字段保持兼容。
4. PE golden fixture 的 `pe_imphash` 与 pefile 完全一致。
5. 同一 imports 不同顺序：
   - `pe_imphash` 可以不同；
   - `import_set_hash` 必须相同。
6. PE delay/ordinal imports 和 ELF GOT/PLT 至少各有一个 fixture。
7. 无 marker 的 XOR fixture 可以恢复明文。
8. normal corpus 不触发 CFF/opaque/string 误报。
9. 6 架构规范化指令接口保持不变。
10. 超过 100 MiB、错误 magic、损坏 import table 均优雅返回。
11. 新增不少于 30 个测试。
12. Windows 使用绝对 Python 与独立 `--basetemp` 全量通过。

## 10. 后果与折衷

正面：

- 不再重复实现成熟 PE/ELF 边界逻辑。
- hash 语义与行业工具兼容，同时保留现有聚类能力。
- 反混淆规则能真正进入 CLI 扫描链路。
- 重型后端可按需安装，不拖累默认 Windows 环境。

代价：

- 新增三个核心依赖，需要依赖锁定与供应链审计。
- parser backend 输出需要统一建模。
- 双 hash 迁移期间必须维护 legacy alias。
- 真实反混淆需要 corpus 和误报率测试，不能只依赖合成 marker。

## 11. 参考

- https://github.com/mandiant/capa
- https://github.com/mandiant/capa-rules
- https://github.com/mandiant/flare-floss
- https://github.com/angr/angr
- https://github.com/NationalSecurityAgency/ghidra
- https://github.com/lief-project/LIEF
- https://github.com/erocarrera/pefile

---

本 ADR 仅确认架构和依赖方向。收到下一条明确“开始实施”指令前，不修改生产源码、
依赖清单或冻结契约。
