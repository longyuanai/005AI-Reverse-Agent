# Ghidra headless decompiler backend

The Ghidra backend is optional. The default remains the native Capstone path,
so installing this package does not require Ghidra or a JVM.

## Configuration

Set these environment variables in the process that launches the agent:

- `AI_REVERSE_DECOMPILER=ghidra` selects Ghidra first and keeps native as the
  unavailable-environment fallback. `native` is the default; `auto` also tries
  Ghidra first.
- `AI_REVERSE_GHIDRA_HEADLESS` is the full path to `analyzeHeadless` (or its
  Windows launcher). When omitted, the backend searches `PATH` for
  `analyzeHeadless` with `shutil.which`.
- `AI_REVERSE_GHIDRA_TIMEOUT_SECONDS` is a positive number of seconds. It
  defaults to `300`.

Ghidra diagnostics stay outside Findings. Timeout, launch, exit, and schema
errors are reported as typed backend failures without copying raw stderr, which
can contain workstation paths.

## Manual verification on a Ghidra host

These steps are intentionally manual because the 013 development host has no
Ghidra or JVM. Use a synthetic or otherwise approved test binary that Ghidra's
importer recognizes.

```powershell
$env:AI_REVERSE_DECOMPILER = 'ghidra'
$env:AI_REVERSE_GHIDRA_HEADLESS = 'C:\Tools\ghidra\support\analyzeHeadless.bat'
$env:AI_REVERSE_GHIDRA_TIMEOUT_SECONDS = '300'
Get-Command $env:AI_REVERSE_GHIDRA_HEADLESS
$env:PYTHONPATH = (Resolve-Path 'src').Path
& 'C:\Path\To\python.exe' -m ai_reverse_agent.cli decompile `
  'C:\Samples\synthetic.exe' --arch x64 --output 'C:\Temp\synthetic.c'
Get-Content -LiteralPath 'C:\Temp\synthetic.c'
```

Expected result: the command exits successfully and the output contains Ghidra
pseudo-C. For fallback verification, point `AI_REVERSE_GHIDRA_HEADLESS` at a
missing launcher and repeat; the command should complete through native
Capstone instead of aborting the scan.

The automated tests use a recorded exporter line and injected runners. Passing
tests on the 013 host proves parsing, timeout/error handling, and fallback; it
does not claim a real Ghidra execution.
