# AI 逆向辅助工具 — 产品技术规范

> 文档版本：v1.1-commercial-baseline ｜ 状态：提议 / 待产品负责人批准
> 适用范围：经授权的二进制逆向、固件分析、CTF、取证和商业代码审计
> 目标：把可验证的静态分析能力封装成 AI Copilot，提高分析师效率，但不替代人工安全结论。
> 商用验收入口：[COMMERCIAL-READINESS.md](COMMERCIAL-READINESS.md)
> 生产架构决策：[ADR-003-commercial-product-architecture.md](ADR-003-commercial-product-architecture.md)

---

## 1. 业务问题

- **学习曲线陡**：熟练 Ghidra/IDA + 各类反编译习惯，至少 2–3 年。
- **重复劳动多**：常见库函数（libc、OpenSSL、stdc++、编译器 runtime）占 30–60% 屏幕。
- **跨语言/跨架构**：x86 / x64 / ARM / MIPS / RISC-V 同时出现，工具割裂。
- **协作困难**：标注、命名、注释主要在分析师本地机器。
- **效率天花板**：纯人工逆向在 CTF / 应急 / 商业审计场景下时间成本高。

**核心命题**：在分析师"看"和"写报告"之间插入 AI Copilot，但不替代分析师的判断。

---

## 2. 产品定位

- **形态**：
  - 本地桌面应用（基于 Ghidra 二次开发 或 自研 UI 嵌入 Ghidra/IDA 插件）
  - 团队协作平台（标注、知识库、报告）
  - CLI + API（批处理、自动化）
- **非目标**：不做通用大模型聊天；不做漏洞扫描器；不做固件提取。
- **核心能力**：**结构化二进制理解 + 知识增强 + 多模态标注**，LLM 不是替代品而是协作方。

---

## 3. 关键能力（MoSCoW）

| 等级 | 能力 | 说明 |
|------|------|------|
| Must | 多架构反汇编/反编译 | x86/x64/ARM/AArch64/MIPS/RISC-V |
| Must | 函数识别与重命名 | 库函数识别（FLIRT + 自研）、变量/参数推断 |
| Must | LLM 解释 | 函数语义总结、关键路径解释、反编译代码注释 |
| Must | LLM 注释注入 | 一键把伪 C 代码加上行内注释 |
| Must | 标注协作 | 函数/地址/块的标注 + 团队共享 |
| Must | 函数签名推断 | 调用约定、参数个数/类型、返回值 |
| Must | 跨函数追踪 | taint 简化版：从 source 到 sink |
| Should | 字符串/常量富化 | 自动识别人类可读字符串、URL、密钥模式 |
| Should | 二进制 diff | 同一函数不同版本的对比与解释 |
| Should | 报告生成 | 自动撰写分析报告 + 关键证据 |
| Should | 离线模式 | 全部本地推理，无外网 |
| Could | 反混淆 | 控制流平坦化、字符串加密、VM 保护 |
| Could | 符号执行联动 | angr / Triton 结果喂给 LLM |
| Won't | 0day 挖掘 | 仅辅助已知漏洞分析 |

---

## 4. 功能架构（历史概念视图）

本节描述产品能力分层，不是当前生产部署拓扑。商用生产架构以 §14 和 ADR-003 为准。

```
┌──────────────────────────────────────────────────────────────────────┐
│            Desktop UI (基于 Ghidra 二次开发 / 自研)                    │
│  反汇编 │ 反编译 │ 函数视图 │ 标注 │ 知识面板 │ 报告 │ Diff            │
└──────────┬───────────────────────────────────────────────────────────┘
           │ Plugin API (Ghidra / IDA Pro / 自研 IR)
┌──────────▼───────────────────────────────────────────────────────────┐
│                    Analysis Orchestrator                              │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │
│  │ Loader │→│ Decoder│→│ IR Lift│→│ Recon  │→│ AI Copilot│→│ Reporter││
│  │ PE/ELF│ │ Bin→IR │ │ to P-  │ │ 库识别 │ │ (LLM)   │ │ MD/PDF │ │
│  │ MachO │ │        │ │ Code/  │ │ 字符串 │ │         │ │        │ │
│  │ U-Boot│ │        │ │ Vex/   │ │ 函数   │ │         │ │        │ │
│  │ WebAsm│ │        │ │ 自研   │ │ 签名   │ │         │ │        │ │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └────────┘  │
└──┬─────────┬─────────┬─────────┬─────────┬─────────┬────────────────┘
   │         │         │         │         │         │
   ▼         ▼         ▼         ▼         ▼         ▼
 File      IR Store   SigDB     LLM GW    Patch DB  Report Store
 System    (Postgres) (FLIRT+   (Claude / (团队     (S3/MinIO)
                     自研)    本地 vLLM)  标注)
```

---

## 5. 模块设计

### 5.1 Loader

- 格式：PE (Windows)、ELF (Linux/Android)、Mach-O (macOS/iOS)、固件裸 binary、WebAssembly。
- 压缩/打包：upx、ASPack、mpress、petite 自动识别（标注不解包）。
- 壳检测：基于入口特征 + 熵分析 + 已知签名。

### 5.2 IR Lift

- 反汇编：Capstone / 自研。
- 反编译：Ghidra decompiler / 自研（基于 IR + 类型推断）。
- 中间表示：P-Code（Ghidra）/ VEX / 自研 SSA 风格 IR（便于 LLM 理解）。
- 函数切分：基于控制流图；call/ret 对齐。

### 5.3 Recon

- 库识别：FLIRT 签名 + 自研签名（IoT / 国产 OS / 商业库）。
- 字符串解码：自动尝试 base64、xor、rc4、zlib 解码展示。
- 函数签名推断：调用约定、参数个数（基于调用者使用 callee 返回值的方式）。
- Taint 简化：源（socket/read/getenv/argv）→ 汇（system/exec/memcpy 大目标）。

### 5.4 AI Copilot（核心）

LLM 四种角色，**所有产出都标注置信度 + 证据**：

1. **Explainer**：解释一个函数做什么；输出 50–200 字 + 关键代码引用。
2. **Commenter**：把伪 C 代码逐行加注释（可一次 200 行内）。
3. **Renamer**：根据上下文建议函数/变量名（团队可一键接受）。
4. **Reverser**：根据一段汇编 + 上下文，反推高级逻辑或加密算法。

**关键约束**：
- 输入：函数伪 C（限长 2K 行）+ 上下文（调用者 / callee / 字符串）+ 团队知识 RAG。
- 输出：必须引用反编译行号；置信度 < 0.6 时显式标"需人工复核"。
- 工具调用：可查 SigDB / 团队标注 / 字符串解码结果 / 自研 IR Query。
- 不可生成"臆造"指令；只能基于实际字节做解释。

### 5.5 标注协作

- 对象：函数、地址、变量、字符串、控制流块、调用关系。
- 字段：语义摘要、命名、关联 CVE、关联威胁、参考资料。
- 共享：团队知识库 + git-like 版本（每次提交可追溯）。
- 权限：分析师 / 审核员 / 只读。

### 5.6 二进制 Diff

- 场景：同函数不同版本（升级分析）、不同架构（跨平台移植）、安全补丁对比。
- 方法：BinDiff（IDA）/ Diaphora（Ghidra）/ 自研 IR diff。
- LLM 二次：自动总结"哪些语义变了，是否引入新风险"。

### 5.7 报告

- 自动生成：
  - 目标概览（架构、编译器、库、关键函数清单）
  - 关键函数解释（Top-N）
  - 漏洞点列表（带证据）
  - 修复/缓解建议
- 模板：CTF write-up、商业审计报告、应急响应报告。
- 签名：内部 CA 签 PDF。

### 5.8 反混淆（高级）

- 控制流平坦化：识别 dispatcher、还原原始块序。
- 字符串加密：自动尝试常见算法 + 熵分析提示。
- OLLVM / Tigress：针对性 pass 识别。
- VM 保护：handler 识别 + 字节码反汇编（自动重写 IR）。
- **重要**：所有反混淆都标记"分析时引入的不确定性"，避免"过度自信"。

---

## 6. 数据与模型

### 6.1 存储

| 用途 | 选型 |
|------|------|
| IR / 标注 | PostgreSQL + JSONB |
| 文件 / 报告 | S3 / MinIO |
| 向量 | pgvector / Qdrant |
| 缓存 | Redis |
| 团队知识 | Git LFS（标注版本化） |

### 6.2 LLM 策略

- **统一入口**：只通过冻结的 `shared-llm-core` router 调用，产品代码不绑定具体厂商。
- **云模型**：由客户策略显式启用，记录 provider/model/version，不把样本全文默认外发。
- **本地化**：通过兼容 provider 接入客户批准的本地推理服务，模型选型另立 ADR。
- **离线模式**：默认可关闭所有云调用；纯静态分析能力不依赖 LLM 可用性。

### 6.3 微调（可选）

- 在反编译代码 ↔ 解释对上做 SFT / DPO。
- 语料来源：公开 CVE 报告、CTF write-up、团队过往报告（脱敏）。
- 评测：函数摘要 BLEU/ROUGE + 人工盲评。

---

## 7. 安全与合规

- **本地优先**：默认所有分析在客户环境完成；外发需显式授权。
- **代码/二进制隐私**：PII / 密钥 / 内部算法在送 LLM 前脱敏。
- **审计**：所有 LLM 调用 + 人工标注 + 报告生成全量日志。
- **责任边界**：自动结论带"需复核"水印；不当工具用于违法用途。
- **ToS**：禁止对未授权目标的逆向分析。

---

## 8. 部署

| 形态 | 适用 |
|------|------|
| 单机桌面（macOS / Windows / Linux） | 分析师日常 |
| 团队版（自托管后端） | 团队协作 |
| 离线 Air-gap | 涉密 / 红队隔离环境 |

---

## 9. 评估指标

| 维度 | 指标 | 目标 |
|------|------|------|
| 效率 | 函数理解时间（典型） | 30 min → 5 min |
| 效率 | 报告撰写时间 | 4h → 30 min |
| 质量 | 库函数识别率 | ≥ 95% |
| 质量 | 函数摘要可接受率（人工） | ≥ 80% |
| 业务 | 团队标注复用率 | ≥ 60% |
| 安全 | 客户代码外泄 | 0 |

---

## 10. 路线图

- **已完成研发基线**：六架构、PE/ELF/raw、Capstone、伪 C、CFG、轻量符号执行、patch diff、加密常量、反混淆、双 import hash、YARA、CLI/Gateway 契约。
- **v1.1 Commercial Alpha**：异步任务、资源限制、真实语料评测、依赖锁定、Windows/Linux CI。
- **v1.2 Private Pilot**：可运行 Web UI、身份认证、RBAC、持久化、审计、离线安装包、备份恢复。
- **v1.3 Commercial GA**：可观测性、升级回滚、签名发布物、运维手册、支持策略和商用验收报告。
- **v2.0 Advanced Analysis**：经单独审批的 Ghidra Headless、团队标注协作和更深层跨函数分析。

版本名称表示验收门禁，不表示当前代码已达到对应级别。每一级必须满足 §14 和
`COMMERCIAL-READINESS.md`，不得仅凭测试数量宣称 GA。

---

## 11. 风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| LLM 误解释（幻觉） | 高 | 必须引用行号 + 置信度阈值 + 人工 gate |
| 二进制外泄 | 高 | 默认离线 + 客户脱敏 + 强审计 |
| 误用（违法逆向） | 中 | ToS + 强水印 + 用例审计 |
| 反混淆技术变化快 | 中 | 插件化 + 季度更新 |
| 商业反编译引擎授权 | 中 | Ghidra + 自研 IR + IDA 适配层 |
| LLM 成本 | 中 | 缓存 + 上下文压缩 + 离线模型 |

---

## 12. 附录：典型工作流

**场景：商业二进制安全审计**

1. 加载目标 PE/ELF，自动识别编译器 (MSVC 14.3) / 链接器 / 库版本。
2. Recon：标注 80% 函数为已知库；剩 20% 标"自定义"进入待分析队列。
3. 分析师选中关键函数 → AI Copilot 解释："该函数接收 4 参数，前两个是 buffer 和 length，后两个未使用；逻辑是把 buffer 按 4 字节 XOR 0x5A5A5A5A 后写回。"
4. LLM 建议命名：`decrypt_inplace(buf, len)`，分析师确认。
5. Taint 追踪发现"用户输入 → decrypt_inplace → exec"的可疑链。
6. 报告自动生成 Top-10 关键函数 + 可疑调用链 + 修复建议。

---

## 13. Phase-2 实施(v0.6+ 改造指令)

> **本文是 Codex 实施 Phase-2 的入口**。路线图 v0.6 之后所有改动以此为准。

### 13.1 Hook A · multi-arch 反混淆(v0.6)

**目标**:在已有反汇编基础上,识别常见混淆模式(CFF / opaque predicates / 字符串加密),从"反汇编"升级到"分析"。

**新增文件**:

```
src/ai_reverse_agent/deobfuscation/
├── __init__.py
├── base.py              # ObfuscationRule 抽象基类(继承 v0.5 §8 Rule)
├── cff.py               # 控制流平坦化:检测 switch dispatcher + 大量顺序跳转
├── opaque_pred.py       # 不透明谓词:检测恒真/恒假分支
├── string_xor.py        # 字符串 XOR 加密
├── string_rc4.py        # 字符串 RC4 加密
└── block_stats.py       # 基础块直方图(baseline 对比)
```

**Rule 形状**(走 v0.5 §8 RuleEngine):

```python
from shared_llm_core.rule_engine import Rule, RuleContext, RuleHit

class ControlFlowFlatteningRule(Rule):
    id = "reverse.control-flow-flatten"
    tactic = "AML.T0048"  # ATLAS: Erode ML Model Integrity(适配二进制层:混淆)
    severity_default = FindingSeverity.MEDIUM

    def match(self, ctx: RuleContext) -> bool:
        func = ctx.function
        blocks = func.basic_blocks
        # CFF 特征:switch dispatcher + 大量连续跳转
        return block_stats.has_switch_dispatcher(blocks)

    def evaluate(self, ctx: RuleContext) -> RuleHit:
        return RuleHit(rule_id=self.id, confidence=0.7, narrative="疑似控制流平坦化")
```

**集成方式**:

- `pyproject.toml` 加 entry_points:`[project.entry-points."longyuanai.reverse_rules"]`
- `src/ai_reverse_agent/analyzer.py` —— 调 `RuleEngine.load_entry_points("longyuanai.reverse_rules")`

**测试要求**:

- `tests/test_cff_detection.py` —— 用 `samples/obfuscated/cff_demo.exe`(已知混淆样本)
- `tests/test_opaque_pred.py` —— `samples/obfuscated/opaque_demo.exe`
- `tests/test_string_xor.py` —— `samples/obfuscated/strings_xor.exe`
- `tests/test_baseline_normal.py` —— `samples/normal/normal_x64.exe` 应**不**触发混淆规则(确保不误报)
- ≥ 1 test per 规则

**commit 计划**(3 commit):

1. `feat(deobfuscation): add ObfuscationRule base + entry_points + block_stats`
2. `feat(deobfuscation): add CFF + opaque predicate + string XOR rules`
3. `test(deobfuscation): add 4 obfuscated fixtures + 1 normal baseline + per-rule tests`

### 13.2 Hook B · IAT / imphash 数据库(v0.7)

**目标**:从 PE/ELF 的 IAT 提取 API 调用,生成 imphash,与已知病毒库 hash 对照。

**新增文件**:

```
src/ai_reverse_agent/iat/
├── __init__.py
├── pe_iat.py            # PE IAT 解析
├── elf_iat.py           # ELF .got/.plt 解析
├── imphash.py           # 兼容入口与 import hash 结果
└── db.py                # 已知 malware imphash(本地 fixture JSON,≥ 1000 样本)
```

**双 hash 契约**:

```python
pe_imphash = pefile_compatible_order_sensitive_md5(pe_imports)
import_set_hash = md5(",".join(sorted(normalize(all_imports))).encode())
```

- `pe_imphash` 与行业 `pefile.PE.get_imphash()` 兼容，保留 PE import table 顺序。
- `import_set_hash` 是本项目跨 PE/ELF 的稳定集合指纹，排序后计算 MD5。
- 两者语义不同，字段、数据库和 YARA 条件不得互换。

**CLI payload 增量**:

```json
{"binary_path": "samples/malware_x64.exe", "enrich": ["imphash", "iat_list"]}
```

**集成方式**:

- `src/ai_reverse_agent/findings.py` —— imphash 命中已知库时产 Finding(`severity=HIGH`,`title="imphash matched known malware X"`)

**测试要求**:

- `tests/test_pe_iat.py` —— `samples/pe/mini_x64_pe.exe` 提取 IAT
- `tests/test_elf_iat.py` —— `samples/elf/mini_x64_elf.bin`
- `tests/test_imphash_algo.py` —— 用已知 imphash fixture 验证算法
- `tests/test_imphash_db_match.py` —— 注入一条已知 hash,assert 命中
- `tests/test_imphash_no_match.py` —— 注入未知 hash,assert 不命中
- **不**联外网 —— 病毒库是本地 `data/malware_imphashes.json`

**commit 计划**(2 commit):

1. `feat(iat): add PE/ELF IAT parser + imphash algorithm + local malware DB fixture`
2. `feat(findings): emit Finding when imphash matches known malware`

### 13.3 Hook C · Ghidra headless 集成(可选)

**方向**:用 Ghidra headless mode(analyzeHeadless)导出 `.xml`,本仓解析 + 标注。
当前只有 capability boundary；实施范围由 GitHub Issue #3 `GHIDRA-001` 管理，外部
Ghidra/Java 依赖未经明确批准不得安装或启动。

### 13.4 Hook D · YARA 规则生成(Phase-3+ 候选)

**状态**:已完成 YARA-001。基于 FeatureIndex 生成确定性规则，PE 使用标准
`pe.imphash()`，ELF/raw 使用字符串与文件大小条件，特征不足时使用精确 SHA-256；
`yara-python` 开发依赖执行真实编译和匹配测试。

### 13.5 不要做的事

- ❌ **不**在 Windows native 路径上跑(Windows 上 capstone 对新 arch 支持不全,**Linux runner 更稳**)
- ❌ **不**解析大文件(> 100MB)—— 必须先取 header 拒绝,`MagicError` 时优雅退出
- ❌ **不**尝试 sandbox 执行(本仓是**静态分析**,执行就是 SOC 仓的活)
- ❌ **不**改 `Finding` schema(共享契约,改了就破 v0.5 冻结)
- ❌ **不**动 `tests/test_cli_envelope.py`(§15 契约测试是冻结基线)
- ❌ **不**联外网(已知 imphash 库用本地 fixture)

### 13.6 验收清单

Codex 完工后跑:

```powershell
& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m pytest tests/ `
  --basetemp=C:/pytest-tmp/005-phase2 `
  -o addopts= `
  -q --tb=short

& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m ai_reverse_agent.cli scan `
  --input '{"binary_path":"samples/mini_binaries/mini_x64_pe.exe","arch":"x64"}' `
  --json
```

当前基线:278 passed;CLI envelope 仍遵守冻结契约。测试数量只表示研发回归，商用发布
还必须满足 §14 和 `COMMERCIAL-READINESS.md`。

---

**Phase-2 最近修订**: 2026-08-01 · Codex 同步双 hash、YARA 和 Ghidra 状态
**下次回看触发**: Commercial Alpha 开工 / GHIDRA-001 获批

---

## 14. 商用技术基线

### 14.1 当前能力边界

截至 2026-08-01，仓库是可工作的静态分析后端，不是完整商业产品：

- 支持 PE、ELF 和 raw binary；Mach-O、WebAssembly、固件拆包不在当前支持范围。
- 支持 x86、x64、ARM、AArch64、MIPS、RISC-V 的静态反汇编。
- 自研伪 C 是轻量表示，不承诺达到 Ghidra、IDA 或 Binary Ninja 的反编译精度。
- 不执行被分析样本，不提供动态调试、沙箱、脱壳执行或 0day 自动挖掘。
- UI 目前只有技术选型与线框，占位仓不能作为可交付界面。
- Ghidra 后端只有 capability boundary；Issue #3 获批前不得启动外部进程。

### 14.2 生产目标架构

```text
Browser / CLI / API client
          |
          v
IntegrationGateway -- Auth/RBAC -- Audit log
          |
          v
Job API -> Durable queue -> Static-analysis worker pool
                              |-- parser/disassembler/decompiler
                              |-- rules/imphash/YARA
                              `-- optional LLM/Ghidra adapters
          |
          +--> PostgreSQL (metadata, findings, annotations, jobs)
          +--> Object storage (encrypted binaries and reports)
          `--> Metrics/logs/traces
```

原则：API 进程不直接执行长任务；样本只进入受限静态 worker；外部适配器默认关闭；
LLM 外发必须经过显式策略；所有结果携带证据、置信度和工具版本。

### 14.3 冻结接口与版本策略

- `shared-llm-core` v0.1 §1–§6 和 v0.5 Finding/envelope 保持冻结。
- 商用字段通过新版本 endpoint 或向后兼容的可选字段扩展，禁止原地改变语义。
- 数据库 schema 使用单向迁移并提供升级前备份和已验证的回滚方案。
- CLI/API 使用语义化版本；弃用至少跨一个次版本并记录迁移说明。
- 每个分析结果记录 engine version、rule version、配置摘要和输入 SHA-256。

### 14.4 安全基线

- 只接受用户自有、授权、靶场或 CTF 样本；产品内展示授权声明。
- 文件大小默认上限 100 MiB；上传、解压、解析、字符串和 CFG 遍历均有独立配额。
- 不使用 shell 拼接命令；外部工具使用参数数组、超时、最小权限和临时目录。
- worker 禁止默认外网、禁止执行样本、限制 CPU/内存/磁盘/进程数。
- 文件、结果和备份静态加密；传输使用 TLS；密钥不得进入仓库或日志。
- 提供 RBAC、租户隔离、审计日志、保留期、删除和导出能力。
- 发布物生成 SBOM，执行依赖漏洞、许可证、secret、SAST 扫描并签名。
- HIGH/CRITICAL 结论必须展示证据与人工复核状态，不允许仅由 LLM 产生。

详细威胁、控制和验收证据见 `COMMERCIAL-READINESS.md`。

### 14.5 质量与性能门禁

商用发布至少满足：

| 维度 | Pilot 门禁 | GA 门禁 |
|------|------------|---------|
| 自动化测试 | 核心路径 unit/integration/e2e 全绿 | 同左，且 Windows/Linux 发布矩阵全绿 |
| 核心代码覆盖率 | ≥ 80%，新增代码 ≥ 85% | ≥ 85%，关键安全模块分支覆盖 ≥ 80% |
| 支持语料成功率 | ≥ 98%，失败必须结构化返回 | ≥ 99.5%，不得使 API/worker 崩溃 |
| HIGH 误报率 | 授权 clean corpus < 2% | < 1% |
| 已知检测集召回率 | ≥ 85% | ≥ 90% |
| 10 MiB 静态扫描 P95 | 基准硬件 ≤ 60 秒 | ≤ 30 秒 |
| 100 MiB 边界 | 拒绝或在配额内完成，无 OOM | 同左并有压力测试证据 |
| 可用性 | 单节点月度 ≥ 99.5% | 团队版月度 ≥ 99.9% |
| 恢复目标 | RPO ≤ 24h，RTO ≤ 4h | RPO ≤ 1h，RTO ≤ 2h |

性能必须记录基准硬件、样本集和版本；没有测量证据时只能标记“目标”，不能标记“达成”。

### 14.6 可观测性与运维

- job、worker、parser、rule、LLM、外部工具均输出结构化日志和关联 ID。
- 指标至少覆盖队列深度、吞吐、P50/P95、超时、崩溃、各规则命中率和误报反馈。
- health 分为 liveness/readiness/dependency，不能用一个 `ok` 掩盖降级依赖。
- 提供备份恢复演练、容量告警、故障手册、升级回滚和数据迁移验证。
- 日志默认不包含原始二进制、反编译全文、凭据或完整用户输入。

### 14.7 商用 Definition of Done

一个商业化 Epic 只有同时满足以下条件才能标记 done：

1. 需求、非目标、威胁和接口已经评审。
2. 每个外部依赖经过批准、固定版本并记录许可证。
3. 单元、集成、端到端、失败路径和 Windows/Linux 测试全部通过。
4. 性能、安全、兼容性目标有可复现证据。
5. 文档、迁移、回滚、监控和运维手册同步完成。
6. 不破坏冻结契约，工作树干净，变更已通过独立 commit 和 PR 审核。
7. 人工验收明确记录“通过”；禁止由实现者仅凭自测自行宣布 GA。

---

**商用基线修订**: 2026-08-01 · Codex 建立 v1.1 商业化技术门禁
**下次评审触发**: COM-DOC-001 合并 / Commercial Alpha 开工
