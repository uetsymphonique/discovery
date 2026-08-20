# WNetHelper — Build

**Toolchain:** C# / MSBuild via Visual Studio Build Tools 2022 (must be run from a Visual Studio Developer Command Prompt or with `VsDevCmd.bat` in PATH)

## Build

From `discovery-toolkit\` (directory containing the `.sln`):

```cmd
msbuild WNetHelper\WNetHelper.sln /p:Configuration=Release /p:Platform="Any CPU" /nologo /verbosity:minimal
```

## Options

| Flag | Effect |
|---|---|
| `/p:Configuration=Release` | Optimized build, no debug symbols |
| `/p:Platform="Any CPU"` | Required — the solution does not define a `x64` platform entry for Release |

## Output

- **Artifact:** `discovery-toolkit\WNetHelper\WNetHelper\bin\Release\WNetHelper.exe`
- **Target framework:** .NET Framework 4.8 (present by default on Windows 10 1903+ and Windows Server 2019+)
- **Dev-env verify:** `.\WNetHelper\WNetHelper\bin\Release\WNetHelper.exe` (no args) — prints usage and exits cleanly:
  ```
  Usage: WNetHelper.exe <cidr>
         WNetHelper.exe scan <cidr>
         WNetHelper.exe local
         WNetHelper.exe all <cidr>
    Add -v for verbose output
  ```

## Assembly Dependencies

Added in this expansion (beyond the default BCL references):

| Assembly | Used by | Purpose |
|----------|---------|---------|
| `System.DirectoryServices` | `GroupMembership` (SysCollector.cs) | WinNT ADSI provider for local group enumeration |
| `System.Management` | `SystemProfile` (SysCollector.cs) | WMI `Win32_OperatingSystem` query |

Not imported (by design): `System.ServiceProcess` — service enumeration uses direct registry read instead of SCM API.

## Notes

- **Bitness:** `AnyCPU` console apps default to `Prefer32Bit` — the binary runs as **x86** on x64 hosts (verified: `pointer size=4` on WS01). The performance-counter parser computes `PERF_OBJECT_TYPE`/`PERF_COUNTER_DEFINITION` field offsets from `IntPtr.Size`, so it correctly handles both the 32-bit and 64-bit layouts that `HKEY_PERFORMANCE_DATA` returns depending on the caller's bitness. Do not force x64 unless the target requires it.
- The `.csproj` sets `TargetFrameworkVersion` to `v4.8`. If the build host only has an older SDK, install the .NET Framework 4.8 Developer Pack.
- `DebugSymbols` and `DebugType` are set to `false`/`none` in the Debug configuration. The Release configuration uses `pdbonly` — the `.pdb` file is not deployed to the lab host.
- Do **not** rename or move the output binary before transferring; TONESHELL `put` references the filename as configured in `Setup.md`.
