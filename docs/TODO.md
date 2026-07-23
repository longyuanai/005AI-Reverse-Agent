# 005 AI-Reverse-Agent · v0.1 TODO

> **项目状态**: PoC ✅ (45/45 tests passing)
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) (已冻结)
> **派活模板**: [CODEX_INSTRUCTIONS.md](../../CODEX_INSTRUCTIONS.md)

---

## P1 · 本项目 v0.1 任务清单

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| ARCH-001 | 真实架构支持: x86 / x64 / ARM / AArch64 / MIPS / RISC-V | pending | | | |
| DISASM-001 | 接 Capstone 反汇编 | pending | | | |
| DECOMP-001 | 接 Ghidra P-Code 或自研 | pending | | | |
| FLIRT-001 | 库函数识别 (FLIRT 签名) | pending | | | |
| CFLOW-001 | 控制流图可视化 (输出 PNG / DOT) | pending | | | |

---

## 派活模板（复制即可）

发给 Codex 时,把这个模板 + 上面 issue 表里挑的一行 ID 拼起来:

```
[{ISSUE_ID}] 005 AI-Reverse-Agent · {一句话}

## 背景
- 项目: 005 AI-Reverse-Agent
- 路径: E:\001项目\000开发\003AI+网络安全\005AI逆向Agent
- 接口契约: 000shared-llm-core/docs/v0.1-contract.md (已冻结)

## 必须做的事
1. <具体动作 1,含文件路径>
2. <具体动作 2>
3. <具体动作 3>

## 验收
- [ ] pytest 全绿
- [ ] 新增测试 ≥ N 个
- [ ] CLI smoke test 通过 (粘贴输出)
- [ ] 改动文件清单 (git diff --stat)

## 回报格式
**ID**: <ISSUE-ID>
**Files changed**: <列表>
**Tests**: X/X passed
**CLI smoke**: <输出片段>
**Deviations**: <如有,说明原因>
```

---

## 复盘节奏

- 每周一 09:00: 跑 `pytest` 全量,状态写到本表
- 每周五 17:00: review 完成的 issue,标 done
- 每月 1 号: 检查 shared-llm-core 是否有 breaking change
