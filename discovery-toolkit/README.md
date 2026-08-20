# WNetHelper

**Purpose:** Multi-step local discovery and NetBIOS Name Service (NBNS) scanner — collects host profile, session identity, running tasks, services, local group membership, and filesystem entries, plus NBNS host enumeration over a CIDR range.

## Overview

WNetHelper is a stealth variant of SharpNBTScan extended with local discovery modules. It covers 7 Discovery techniques from the evaluation scope using low-profile API approaches that bypass common Sigma process-creation detection rules (no child processes spawned).

Two modules use novel approaches: task listing via performance counter registry (`HKEY_PERFORMANCE_DATA`) instead of standard system information queries, and service enumeration via direct registry read (`CurrentControlSet\Services`) instead of the Service Control Manager API.

The variant renames all internal identifiers, strips offensive-tool console markers, and carries neutral assembly metadata (`Windows Network Helper`, version 2.3.1.0).

## Technique Coverage

| Module | TID | Technique | Approach |
|--------|-----|-----------|---------|
| `[PROFILE]` | T1082 | System Information Discovery | `Environment.*` + WMI `Win32_OperatingSystem` |
| `[SESSION]` | T1033 | System Owner/User Discovery | `WindowsIdentity.GetCurrent()` + group SID translate |
| `[TASKS]` | T1057 | Process Discovery | Performance counter via `HKEY_PERFORMANCE_DATA` (novel) |
| `[SERVICES]` | T1007 | System Service Discovery | Registry `CurrentControlSet\Services` (novel) |
| `[MEMBERS]` | T1069.001 | Permission Groups: Local | WinNT ADSI `DirectoryEntry` |
| `[FILES]` | T1083 | File and Directory Discovery | `Directory.GetFileSystemEntries()` |
| `[HOSTS]` | T1018 | Remote System Discovery | NBNS UDP/137 scan |

## Target context

- **Host / OS / arch:** WS01 (10.12.10.30), Windows 10/11, x64 — requires .NET Framework 4.8
- **Privilege required:** Domain user (TESTLAB\labuser) — no elevation needed

## Usage

```
WNetHelper.exe <cidr>              NBNS scan only (backward compat)
WNetHelper.exe scan <cidr>         NBNS scan with [HOSTS] header
WNetHelper.exe local               Local discovery: PROFILE → SESSION → TASKS → SERVICES → MEMBERS → FILES
WNetHelper.exe all <cidr>          Local discovery + NBNS scan
```

Add `-v` to any command for verbose diagnostic output.

## Source

Source lives under `WNetHelper/WNetHelper/` (VS solution folder inside `discovery-toolkit/`):

| File | Content |
|------|---------|
| `Program.cs` | Entry point, mode dispatch, NBNS UDP scan logic |
| `SysCollector.cs` | 6 collector classes (SystemProfile, SessionInfo, ProcessCounter, ServiceRegistry, GroupMembership, PathEnumerator) + diagnostic helper |
| `PerfCounter.cs` | P/Invoke declarations + performance data struct marshalling for task listing |
| `NBNSResolver.cs` | NBNS packet parser structs and `PacketParser` class |
| `Properties/AssemblyInfo.cs` | Neutral assembly metadata |

## See also

- Build instructions: `Build.md`
- Code flow & ATT&CK mapping: `Flow.md`
- Expansion plan & novelty assessment: `PLAN.md`
