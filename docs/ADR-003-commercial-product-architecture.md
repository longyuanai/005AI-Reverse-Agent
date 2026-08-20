# ADR-003: 商用产品采用 Gateway + durable jobs + isolated static workers

**状态**：提议 / 待产品负责人批准

**日期**：2026-08-01

**作者**：Codex

## 背景

现有仓库已经具备多架构静态分析、规则、报告、CLI envelope 和
IntegrationGateway adapter，但当前执行模型偏同步，UI 只是骨架，缺少商用所需的
任务持久化、资源隔离、身份权限、审计、恢复和可观测性。

二进制是非可信输入。即使产品不执行样本，解析器、反汇编器和可选外部工具仍可能
崩溃、耗尽资源或读取错误路径。因此不能把长时间分析直接放在 Web 请求进程中。

## 决策

采用以下生产架构：

1. 保留 `IntegrationGateway` 作为版本化产品入口和冻结 envelope 的兼容层。
2. Gateway 只负责认证、授权、输入验证、限流和创建 job，不执行长分析。
3. 使用 durable queue 管理 job 状态、租约、取消、重试和死信。
4. 静态分析在独立 worker 中运行，默认无外网、禁止执行样本并设置资源上限。
5. PostgreSQL 保存 metadata、Finding、annotation、job 和 audit；对象存储保存样本与报告。
6. LLM 和 Ghidra 是策略控制的可选 adapter；不可用时保留纯静态结果并明确降级。
7. Web UI 采用已选定的 React + Vite + Tailwind + Monaco，通过 job API 获取进度和结果。
8. 单机版与团队版复用同一领域模型；单机版可以使用嵌入式部署实现，但不能分叉契约。

## 备选方案

### A. 继续同步 CLI/HTTP 执行

优点是实现简单。缺点是请求超时、进程崩溃影响 API、无法可靠取消和恢复，不满足商用。

### B. 每种分析能力拆成独立微服务

隔离彻底，但当前团队和规模下会带来过多部署、版本和网络复杂度。现阶段不采用；先以
模块化 worker pool 交付，达到容量证据后再拆分。

### C. 以 Ghidra 作为唯一分析引擎

分析深度较高，但 Java/Ghidra 体积、启动时间、版本兼容和部署授权会成为所有用户的
硬依赖。现有 Capstone/pefile/pyelftools 管线继续作为默认，Ghidra 保持可选。

## 后果

正面影响：

- API 与非可信解析工作隔离，故障域更清晰。
- job 可追踪、可取消、可恢复，适合 UI 和批量处理。
- 单机、团队、离线部署共享契约和分析代码。
- 可选外部工具不会破坏基础能力。

代价：

- 引入队列、数据库、对象存储、迁移和运维复杂度。
- 需要幂等、租约、重试、清理和孤儿 job 处理。
- 本地开发环境需要轻量 profile，避免强迫所有贡献者运行完整生产栈。

## 不变量

- 不修改冻结的 Finding 和 v0.5 envelope 语义。
- 不执行被分析样本。
- 不静默把二进制、反编译内容或凭据发送到外网。
- 不自动下载 Ghidra、Java、模型或恶意样本数据库。
- 不因商业化删除现有 Windows 兼容测试和 100 MiB 文件边界。

## 验收条件

- JOB-001、AUTH-001、STORAGE-001 和 SECURITY-001 的接口 ADR 完成。
- 可证明 API 进程和分析 worker 是不同故障域。
- worker 崩溃、超时、取消、重复投递和恢复均有自动化测试。
- 单机与团队部署运行相同 contract suite。
- 性能和恢复目标达到 `COMMERCIAL-READINESS.md` 对应阶段门禁。
