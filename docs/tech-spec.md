# AI 逆向辅助工具 — Codex 技术方案

> 版本：v0.1 (draft) ｜ 适用范围：二进制逆向、固件分析、CTF / 红队 / 取证 / 商业代码审计
> 目标：把"二进制专家"的能力封装成可协作的 AI Copilot，让 3 年经验的工程师能干 10 年经验的活。

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

## 4. 总体架构

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

- **主力**：Anthropic Claude（Opus 4.8 / Sonnet 5），长上下文 + Tool Use 适合反编译代码块。
- **本地化**：vLLM + Qwen2.5-Coder-32B / DeepSeek-Coder-V3。
- **离线模式**：默认离线是产品价值主张之一。

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

- **v0.1 PoC（2 个月）**：Ghidra 插件 + 1 架构（x64） + Explainer + 标注本地化。
- **v0.3 Beta（4 个月）**：多架构 + Commenter + 团队知识库。
- **v0.6 GA（8 个月）**：Renamer + 二进制 Diff + 报告。
- **v1.0（1 年）**：反混淆 + 离线 LLM 完整支持 + 商业版本。

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
├── imphash.py           # imphash 算法(FBI 标准,MurmurHash3 of sorted imports)
└── db.py                # 已知 malware imphash(本地 fixture JSON,≥ 1000 样本)
```

**imphash 算法**(FBI 格式):

```python
def compute_imphash(imports: list[str]) -> str:
    """
    1. 取 imports + hint names,小写
    2. 按字典序排序
    3. 用 ',' 连接
    4. MD5
    """
    cleaned = sorted(f"{imp.lower()}.{hint.lower()}" for imp, hint in imports)
    return hashlib.md5(",".join(cleaned).encode()).hexdigest()
```

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
- **不**联外网 —— 病毒库是本地 `src/ai_reverse_agent/data/malware_imphashes.json`

**commit 计划**(2 commit):

1. `feat(iat): add PE/ELF IAT parser + imphash algorithm + local malware DB fixture`
2. `feat(findings): emit Finding when imphash matches known malware`

### 13.3 Hook C · Ghidra headless 集成(Phase-3+ 候选,不在本仓本次实施)

**方向**:用 Ghidra headless mode(analyzeHeadless)导出 `.xml`,本仓解析 + 标注。复杂度高,留 v1.0+。

### 13.4 Hook D · YARA 规则生成(Phase-3+ 候选)

**方向**:基于 reverse 发现(混淆模式 + imphash + 关键函数 hash),自动生成 YARA rule。

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
  -m ai_reverse_agent scan --input '{"binary_path":"samples/mini_binaries/mini_x64_pe.exe"}' --json
```

预期:≥ 185 passed(原 167 + Phase-2 新增 18);CLI envelope 仍是 `{"findings": [...], "summary": {...}}`。

---

**最近修订**: 2026-07-25 · Claude 把 PHASE-2.md 合并进 §13
**下次回看触发**: v0.6 启动 / Hook A 启动 / imphash 数据库接入
