# ADR-001: 005-UI 技术栈选型

**状态**: 提议 / 待 Claude 审核

**日期**: 2026-07-25

**作者**: Codex

## 背景

005 reverse agent 输出二进制分析结果（函数列表、调用图、反汇编片段），
需要 Web UI 让安全工程师上传 binary、查看进度、跳转函数。

UI 通过 v0.5 IntegrationGateway 与后端交互。当前阶段只冻结技术方向和
信息架构，不安装依赖，也不实现生产页面。

## 候选

- A. React + Vite + Tailwind + Monaco Editor
- B. Next.js 14 (App Router) + Shadcn/ui + React Flow
- C. SvelteKit + Skeleton + CodeMirror 6

## 决定

选择 **A. React + Vite + Tailwind + Monaco Editor**。

## 理由

1. 005 的数据和扫描能力均由 FastAPI/IntegrationGateway 提供，Vite SPA
   可以静态部署，不需要为服务端渲染和双后端路由承担额外复杂度。
2. Monaco Editor 对大段反汇编、地址跳转、行高亮和只读代码导航支持成熟，
   与安全工程师熟悉的 VS Code 交互一致。
3. React 生态便于后续按需加入 React Flow 或 Cytoscape 展示 CFG，同时
   Tailwind 能快速建立高密度分析工作台，不锁定重量级组件库。

## 后果

- 首屏渲染依赖浏览器加载 JavaScript，不具备 Next.js 的 SSR 优势；本产品是
  登录后的本地分析工具，这一折衷可以接受。
- Monaco 会显著增加前端 bundle，需要使用动态导入、Web Worker 和按需语言
  注册控制体积。
- 候选 A 不自带调用图组件；实现 CFG 页面时需要另行评审 React Flow、
  Cytoscape 或自研 Canvas，避免过早锁定图布局方案。
- 前后端独立部署需要明确 API base URL、CORS 和上传大小限制。
