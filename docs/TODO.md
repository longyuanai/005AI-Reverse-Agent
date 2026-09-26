# 005 AI-Reverse-Agent · v0.1 TODO

> **项目状态**: 核心静态分析基线完成；Commercial Alpha 规划中（278/278 tests passing）
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) (已冻结)
> **派活模板**: [CODEX_INSTRUCTIONS.md](../../CODEX_INSTRUCTIONS.md)

---

## P1 · 本项目 v0.1 任务清单

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| ARCH-001 | 真实架构支持: x86 / x64 / ARM / AArch64 / MIPS / RISC-V | done | 2026-07-24 | 2026-07-24 | PE/ELF 映射 + fake PE/ELF/raw fixtures |
| DISASM-001 | 接 Capstone 反汇编 | done | 2026-07-24 | 2026-07-24 | normalized disasm.py + 六架构 samples/CLI |
| DECOMP-001 | 接 Ghidra P-Code 或自研 | done | 2026-07-24 | 2026-07-24 | 自研伪 C + 函数边界/栈变量 |
| FLIRT-001 | 库函数识别 (FLIRT 签名) | done | 2026-07-24 | 2026-07-24 | 内置 masked 16-byte 签名表 |
| CFLOW-001 | 控制流图可视化 (输出 PNG / DOT) | done | 2026-07-24 | 2026-07-24 | jump/call/ret CFG；DOT + 可选 Graphviz PNG |

## v0.5 · S3

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| SYMBOLIC-001-A | 轻量符号执行 | done | 2026-07-24 | 2026-07-24 | mini solver + optional Z3 backend |
| PATCH-001-A | 二进制 patch diff | done | 2026-07-24 | 2026-07-24 | 函数级 + normalized instruction diff |
| CRYPTO-001-A | 加密常量识别 | done | 2026-07-24 | 2026-07-24 | AES S-box + SHA-1/SHA-256 常量表 |

## v0.6 · S4

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| REV-CLI-001 | ReverseAdapter CLI 契约 | done | 2026-07-24 | 2026-07-24 | scan JSON envelope + adapter subprocess E2E |
| REV-LIVE-001 | 多架构样本 + gateway 联调 | done | 2026-07-24 | 2026-07-24 | x64 PE + ARM/MIPS ELF；gateway :18080 E2E |

## Phase-2 · ADR-002

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| BACKEND-001 | 成熟 PE/ELF/CFG 后端 | done | 2026-07-29 | 2026-07-29 | pefile + pyelftools + NetworkX；保留 minimal fallback |
| HASH-002 | 双 import hash 与数据库 provenance | done | 2026-07-29 | 2026-07-29 | 标准 pe_imphash + import_set_hash；fixture 不产 HIGH |
| FEATURE-001 | 四级 FeatureIndex + RuleEngine | done | 2026-07-29 | 2026-07-29 | 单次解析、特征共享、默认 envelope 兼容 |
| DEOBF-002 | 多信号静态反混淆 | done | 2026-07-29 | 2026-07-29 | markerless XOR、RC4、opaque、NetworkX CFF |
| OPTIONAL-ADAPTERS | 重型后端能力边界 | done | 2026-07-29 | 2026-07-29 | capa/FLOSS capability；angr/Ghidra 延期到 v1.0+ |

## v1.0 · Static signature generation

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| YARA-001 | 基于静态 FeatureIndex 生成 YARA 规则 | done | 2026-08-01 | 2026-08-01 | 标准 pe_imphash、筛选字符串、SHA-256 fallback；yara-python 编译验证 |

> Hook C（Ghidra headless）与 Hook D（YARA 生成）仍按技术方案延期，
> 其中 YARA-001 已获批准并完成；Ghidra 仍未经新 issue 批准不实施。

## 商业化路线图

> 完成定义以 [COMMERCIAL-READINESS.md](COMMERCIAL-READINESS.md) 为准；`planned`
> 不代表依赖已批准。每个 Epic 单独 issue、单独 PR，不允许一次性大改冻结契约。

| ID | 优先级 | 任务 | 状态 | 商用阶段 | 关键验收 |
|----|--------|------|------|----------|----------|
| COM-DOC-001 | P0 | 商用技术、安全与验收基线 | in_progress | Alpha | tech-spec、readiness、ADR-003 评审通过 |
| JOB-001 | P0 | durable job、进度、取消、超时、幂等 | planned | Alpha | worker 崩溃可恢复，API 不执行长任务 |
| EVAL-001 | P0 | 授权 corpus 与准确率/性能基准 | planned | Alpha | clean/detection/malformed/performance 报告 |
| RELEASE-001 | P0 | 依赖锁定、CI 矩阵、SBOM、签名制品 | planned | Alpha | Windows/Linux 构建与 contract suite 全绿 |
| UI-001 | P0 | React Web UI：上传、进度、结果 | planned | Pilot | 三屏 E2E、可访问性、错误/降级状态 |
| AUTH-001 | P0 | 身份、RBAC、租户隔离与审计 | planned | Pilot | 越权测试、审计完整、secret 不入日志 |
| STORAGE-001 | P0 | metadata/object storage 与生命周期 | planned | Pilot | 加密、删除、备份、恢复、迁移回滚 |
| SECURITY-001 | P0 | worker 隔离、资源配额、供应链门禁 | planned | Pilot | no-network/no-exec、fuzz、SAST/secret/dependency scan |
| OBS-001 | P1 | metrics/logs/traces、SLO、告警 | planned | GA | health 分层、告警与故障 runbook |
| REPORT-002 | P1 | 商用报告与证据导出 | planned | GA | JSON/Markdown/PDF 可追溯、可复核 |
| PACKAGE-001 | P0 | Windows/Linux/air-gap 安装升级 | planned | GA | 空环境安装、升级、回滚、卸载 smoke |
| PILOT-001 | P0 | 授权客户试点与发布签字 | planned | GA gate | 验收记录、缺陷闭环、支持边界确认 |
| GHIDRA-001 | P2 | 可选 Ghidra Headless 深度分析 | blocked | v2.0 | Issue #3；等待外部 Ghidra/Java 明确批准 |

当前商业化剩余：COM-DOC-001 完成后还有 12 个 Epic，其中 9 个 P0、2 个 P1、
1 个 P2；只有达到 Pilot/GA 门禁后才能对外宣称商用。

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
