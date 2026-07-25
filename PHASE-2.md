# 005AI逆向Agent · Phase-2 计划

> **本仓角色**: AI 二进制逆向 Agent。`capstone` / `radare2` / 自写解析,支持 x86 / x64 / ARM / AArch64 / MIPS / RISC-V 多种架构,产出反汇编/函数识别/安全 Finding。
> **当前状态**: v0.6 §15 CLI Envelope 已实现,S4 worker 4 件套全绿,E 绿。
> **下一阶段**: v0.6+ multi-arch 反混淆 + IAT/API hash 数据库。

---

## 现状摘要(2026-07-25)

| 项 | 状态 |
|----|------|
| v0.1 LLM 集成 | ✅ |
| v0.5 Finding schema | ✅ |
| 6 architectures(x86/x64/ARM/AArch64/MIPS/RISC-V) | ✅ |
| `samples/mini_binaries/mini_x64_pe.exe` test fixture | ✅ |
| CLI 子命令 `scan --input '<json>' --json` | ✅ |
| S4 worker 4 件套 | ✅ PASS |

---

## Phase-2 hooks

### Hook A · multi-arch 反混淆(派活 024-REVERSE-DEOBFUSCATE)

**目标**:在已有反汇编基础上,识别常见混淆模式:
- 控制流平坦化(CFF)
- 不透明谓词(opaque predicates)
- 字符串加密(XOR / RC4)

**派活文档**:`024-REVERSE-DEOBFUSCATE.md`(待起草)

```python
# src/ai_reverse_agent/obfuscation.py
class ObfuscationRule(Rule):
    id = "reverse.control-flow-flatten"

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        # 1. 找大量顺序跳转 + switch dispatcher
        # 2. 计算块直方图
        # 3. 与 baseline 对比
        # 4. 满足阈值 → 标 "疑似 CFF"
        ...
```

- 用 v0.5 §8 RuleEngine
- 每类混淆规则 ≥ 1 个 test

**为什么 Phase-2**:
- 现在只反汇编,不算"分析"
- 真实样本(尤其 malware)基本都混淆

### Hook B · IAT/API hash 数据库

**目标**:从 PE/ELF 的 IAT 提取 API 调用,与已知 hash 对照(imphash)。

**派活文档**:`025-REVERSE-IMPHASH.md`(待起草)

- 提 imphash(Imports Hash,FBI 格式)
- 与病毒库 hash 对照(MalwareBazaar 等离线列表)
- 输出 finding:类似 "此 hash 与已知样本 X 重合"

**为什么 Phase-2**:
- 静态分析常见 hash 是关键步骤
- 与 002 VULN 的 CVE 关联可以联动

### Hook C · Ghidra 集成(可选)

**目标**:Ghidra headless mode 触发,导出 .xml 然后本仓解析。

- Phase-3+ 候选
- 实现复杂,不进 v1.0 主路

### Hook D · 自定义 YARA 规则生成

**目标**:基于 reverse 发现,自动生成 YARA rule。

- Phase-3+ 候选
- 依赖 LLM 评估能力

---

## v1.0 路线图

```
v0.5 已冻结:6 架构反汇编
v0.6: Hook A (反混淆)
v0.7: Hook B (imphash 数据库)
v1.0: Hook C (Ghidra 集成) + Hook D (YARA 生成)
```

---

## 不要做的事

- ❌ 不要在 Windows native 路径上跑(Windows 上 capstone 对新 arch 支持不全,Linux runner 更稳)
- ❌ 不要解析大文件(>100MB)— 必须先取 header 拒绝
- ❌ 不要尝试 sandbox 执行(本仓是静态分析)

---

**最近修订**: 2026-07-25 · Claude 起草 Phase-2 计划
**下次回看触发**: v0.6 启动 / Hook A 启动
