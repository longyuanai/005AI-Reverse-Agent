# 005 Reverse Agent UI · Wireframe

本草图描述上传、分析进度和结果浏览三个核心屏幕。桌面端优先，窄屏仅保证
上传与状态查看，完整反汇编工作台要求较宽视口。

## 1. 上传

```text
┌──────────────────────────────────────────────────────────────────────┐
│ 005 Reverse Agent                                      API: Connected │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│                ┌────────────────────────────────────┐                │
│                │   Drop PE / ELF / raw binary      │                │
│                │   or click to choose a file       │                │
│                └────────────────────────────────────┘                │
│                                                                      │
│ Architecture  [ Auto / x64 ▼ ]    Endian [ little ▼ ]               │
│ File          firmware.bin · 3.8 MB                                  │
│                                                                      │
│ Privacy: analysis stays on the configured local gateway              │
│                                             [ Start analysis ]       │
└──────────────────────────────────────────────────────────────────────┘
```

关键交互：

- 拖放或文件选择后显示文件名、大小和本地隐私提示。
- PE/ELF 默认自动识别架构；raw binary 必须手动选择。
- 上传前校验大小限制和 gateway 健康状态。

## 2. 进度

```text
┌──────────────────────────────────────────────────────────────────────┐
│ ← Upload      firmware.bin                              [ Cancel ]    │
├──────────────────────────────────────────────────────────────────────┤
│ Analysis progress                                           58%       │
│ ██████████████████████████──────────────────────                    │
│                                                                      │
│ ✓ Container detected        PE32+ / x64                              │
│ ✓ Sections extracted        .text, .rdata, .idata                    │
│ ● Disassembling             1,248 / 2,104 functions                  │
│ ○ Identifying libraries     waiting                                  │
│ ○ Building control flow     waiting                                  │
│ ○ Generating findings       waiting                                  │
│                                                                      │
│ Live log                                                            │
│ 10:42:16  entry point 0x401000 decoded                               │
│ 10:42:17  possible AES constants at 0x42a100                         │
└──────────────────────────────────────────────────────────────────────┘
```

关键交互：

- 通过 SSE 展示阶段状态与日志；断线后显示重新连接入口。
- 取消动作需要二次确认，且不暗示服务端一定能立即终止子进程。
- 完成后自动进入结果页，并保留手动打开按钮。

## 3. 结果

```text
┌──────────────────────────────────────────────────────────────────────┐
│ firmware.bin  x64  PE     2 findings        [ Export ] [ New scan ]  │
├───────────────┬───────────────────────────────────┬──────────────────┤
│ FUNCTIONS     │ DISASSEMBLY                       │ INSPECTOR        │
│ Search…       │ 0x401000  push rbp                │ sub_401000      │
│               │ 0x401001  mov rbp, rsp            │ confidence 95%  │
│ ▸ sub_401000  │ 0x401004  call 0x402080           │                  │
│   parse_cfg   │ 0x401009  test eax, eax            │ Calls           │
│   decrypt     │ 0x40100b  jne 0x401020             │ → parse_cfg     │
│   main        │ ...                               │                  │
│               │                                   │ Finding          │
│               │                                   │ Hardcoded cred   │
├───────────────┴───────────────────────────────────┴──────────────────┤
│ Tabs: [ Disassembly ] [ Pseudo-C ] [ CFG ] [ Findings ] [ Strings ] │
└──────────────────────────────────────────────────────────────────────┘
```

关键交互：

- 左侧函数检索与中间 Monaco 地址跳转保持同步。
- Finding、调用者、被调用者点击后定位到对应地址并高亮证据。
- CFG 是按需加载的独立标签页，避免阻塞首次结果渲染。
- 导出入口提供 JSON、DOT 和 Markdown，保留证据地址与置信度。
