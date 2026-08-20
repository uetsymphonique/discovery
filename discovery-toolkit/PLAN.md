# WNetHelper — Expansion Plan

Mở rộng WNetHelper từ NBNS-only scanner thành multi-step local discovery tool phủ các Discovery technique trong scope (`detect-technique-list.md`), ưu tiên API approach ít phổ biến hơn standard Seatbelt-class pattern.

---

## EDR Detection Assessment

Nghiên cứu từ internet (CrowdStrike, SentinelOne, MDE, MDI, Sigma, Outflank, GhostPack/Seatbelt).

### Quyết định giữ/bỏ technique theo detection risk

| TID | Technique | Detection Risk | Quyết định | Lý do |
|-----|-----------|---------------|------------|-------|
| T1018 | Remote System Discovery | Low | ✅ Giữ | NBNS UDP/137 — endpoint EDR không flag; network-layer detection hiếm |
| T1082 | System Information Discovery | Very Low | ✅ Giữ | `Environment.*` pure .NET property reads; WMI `Win32_OperatingSystem` quá phổ biến |
| T1033 | System Owner/User Discovery | Very Low | ✅ Giữ | `WindowsIdentity.GetCurrent()` hoàn toàn in-process, invisible |
| T1057 | Process Discovery | Low | ✅ Giữ | EDR log nhưng không alert standalone (FP volume quá cao) |
| T1007 | System Service Discovery | Low–Medium | ✅ Giữ | .NET API tránh Sigma proc_creation rules |
| T1069.001 | Permission Groups Discovery: Local | Medium | ✅ Giữ | WinNT ADSI — Outflank: "optics for defenders into ADSI are limited" |
| T1083 | File and Directory Discovery | Very Low | ✅ Giữ | Standard filesystem API |
| T1087.002 | Account Discovery: Domain Account | **HIGH** | ❌ Loại bỏ | MDI DC sensor layer + CrowdStrike ML + Sigma `win_ldap_recon` |
| T1069.002 | Permission Groups Discovery: Domain | **HIGH** | ❌ Loại bỏ | Cùng LDAP detection surface |

### Lý do loại bỏ LDAP modules

1. **MDI hoạt động ở DC sensor layer** — inspect LDAP traffic trực tiếp, rename binary vô nghĩa
2. **CrowdStrike ML-powered LDAP detection** — 65% TPR / 81.48% precision
3. **Sigma rule `win_ldap_recon`** — deployed trong Splunk/Elastic/FortiSIEM
4. **Bundling LDAP kéo thêm `System.DirectoryServices.Protocols` import** → match Seatbelt-class profile

T1087.002 + T1069.002 sẽ cover bằng LOLBin (`net user /domain`, `net group /domain`) qua xp_cmdshell hoặc TONESHELL shell trong Phase riêng — phù hợp context hơn và test đúng detection surface (command-line rules).

---

## Novelty Assessment

### Vấn đề: Plan gốc = Seatbelt stripped-down

Các .NET API ban đầu (`Process.GetProcesses`, `ServiceController.GetServices`, WinNT ADSI, `WindowsIdentity`, WMI) **là kỹ thuật 5–8 năm tuổi** — chính xác API surface của Seatbelt (GhostPack, 2018). Rename identifiers + bỏ modules không tạo ra sự khác biệt ý nghĩa. Blue team quen .NET offensive tooling nhận ra pattern ngay.

### Cải tiến: thay 2 modules bằng alternative novel

| Module | Approach cũ (Seatbelt-like) | Approach mới (novel) | Novelty | Tại sao khó detect |
|--------|----------------------------|---------------------|---------|---------------------|
| **T1007 `[SERVICES]`** | `ServiceController.GetServices()` — gọi `OpenSCManager` + `EnumServicesStatusEx` | **Registry read** `HKLM\SYSTEM\CurrentControlSet\Services` | **Cao** | Không gọi SCM API → bypass hoàn toàn SCM hooks; có thể phát hiện hidden services (SDDL-modified); không cần `System.ServiceProcess` reference |
| **T1057 `[TASKS]`** | `Process.GetProcesses()` — gọi `NtQuerySystemInformation` | **Performance counter** đọc `HKEY_PERFORMANCE_DATA` | **Cao** | API surface hoàn toàn khác `NtQuerySystemInformation`; đây là cách `perfmon.exe` hoạt động; hầu như zero EDR coverage trên đường này |

### Modules giữ nguyên approach — đã tối ưu

| Module | Approach | Lý do giữ |
|--------|---------|-----------|
| **T1082 `[PROFILE]`** | `Environment.*` + WMI `Win32_OperatingSystem` | Đã very low profile, không có alternative có ý nghĩa |
| **T1033 `[SESSION]`** | `WindowsIdentity.GetCurrent()` + `IsInRole()` | Pure in-process, invisible — không thể tốt hơn |
| **T1069.001 `[MEMBERS]`** | WinNT ADSI `DirectoryEntry` | Vẫn là best approach cho local groups; SAMR alternative không tốt hơn |
| **T1083 `[FILES]`** | `Directory.GetFileSystemEntries()` | Standard API, không có alternative có ý nghĩa |
| **T1018 `[HOSTS]`** | NBNS UDP/137 scan | Existing, đã stealth variant |

### Lợi ích từ việc thay 2 modules

1. **Bỏ `System.ServiceProcess` reference** — import profile nhẹ hơn, ít match Seatbelt signature
2. **Registry + perfcounter = API surface mà EDR không monitor** — genuinely novel detection gap
3. **Registry service enum phát hiện hidden services** — bonus capability mà `ServiceController` không có
4. **Perfcounter process enum qua `HKEY_PERFORMANCE_DATA`** — không gọi `NtQuerySystemInformation`, tránh userland hooks

### Sources — Novelty

- [SANS: Finding Hidden Windows Services](https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services) — registry-based service enum
- [Microsoft: Services Registry Tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) — registry structure
- [freezerdev: Enumerating Processes on Windows](http://freezerdev.blogspot.com/2026/01/enumerating-processes-on-windows.html) — performance counter process enum
- [Microsoft: Collecting Performance Data](https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data) — `HKEY_PERFORMANCE_DATA` API
- [Jonathan Johnson: PLA DCOM Discovery](https://jonny-johnson.medium.com/no-agent-no-problem-discovering-remote-edr-8ca60596559f) — PLA DCOM (considered, not adopted — too complex for current scope)
- [Praetorian: WasmForge](https://www.praetorian.com/blog/wasmforge-csharp-ghostpack-edr-evasion/) — confirms Seatbelt-class tools are burned
- [Palo Alto: Direct Syscall Detection](https://www.paloaltonetworks.com/blog/security-operations/a-deep-dive-into-malicious-direct-syscall-detection/) — direct syscalls now detectable via kernel call stack analysis (not adopted)

### Sources — Detection Assessment

- [CrowdStrike: ML-Powered LDAP Reconnaissance Detections](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-ml-powered-ldap-reconnaissance-detections/)
- [MDI: Security principal reconnaissance (LDAP)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-identity/new-preview-detection-security-principal-reconnaissance-ldap/m-p/3830536)
- [Sigma: win_ldap_recon.yml](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/ldap/win_ldap_recon.yml)
- [Sigma: Suspicious Group/Account Recon via Net.EXE](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_net_groups_and_accounts_recon/)
- [Outflank: AD Recon using ADSI and Reflective DLLs](https://www.outflank.nl/blog/2019/10/20/red-team-tactics-active-directory-recon-using-adsi-and-reflective-dlls/)
- [IBM X-Force: InvisibilityCloak obfuscation](https://www.ibm.com/think/x-force/invisibility-cloak-obfuscate-c-tools-evade-signature-based-detection)

---

## Final scope — 7 modules

| TID | Technique | Module | Approach |
|-----|-----------|--------|---------|
| T1018 | Remote System Discovery | `[HOSTS]` | NBNS UDP/137 scan (existing, unchanged) |
| T1082 | System Information Discovery | `[PROFILE]` | `Environment.*` + WMI `Win32_OperatingSystem` |
| T1033 | System Owner/User Discovery | `[SESSION]` | `WindowsIdentity.GetCurrent()` + `IsInRole()` + group SID translate |
| T1057 | Process Discovery | `[TASKS]` | **Performance counter** via `HKEY_PERFORMANCE_DATA` registry read |
| T1007 | System Service Discovery | `[SERVICES]` | **Registry read** `HKLM\SYSTEM\CurrentControlSet\Services` |
| T1069.001 | Permission Groups Discovery: Local | `[MEMBERS]` | WinNT ADSI `DirectoryEntry` |
| T1083 | File and Directory Discovery | `[FILES]` | `Directory.GetFileSystemEntries()` |

---

## Behaviors

### `[PROFILE]` — T1082

| # | Behavior | API / Method |
|---|---------|-------------|
| P1 | WNetHelper reads hostname, domain, OS version from environment | `Environment.MachineName`, `UserDomainName`, `OSVersion` |
| P2 | WNetHelper WMI queries `Win32_OperatingSystem` for OS caption and build | `ManagementObjectSearcher` |

### `[SESSION]` — T1033

| # | Behavior | API / Method |
|---|---------|-------------|
| S1 | WNetHelper reads current Windows identity (username, auth type) | `WindowsIdentity.GetCurrent()` |
| S2 | WNetHelper checks administrator role membership | `WindowsPrincipal.IsInRole(Administrator)` |
| S3 | WNetHelper enumerates group SIDs and translates to NTAccount names | `identity.Groups`, `Translate()` |

### `[TASKS]` — T1057 (novel approach)

| # | Behavior | API / Method |
|---|---------|-------------|
| T1 | WNetHelper opens `HKEY_PERFORMANCE_DATA` and reads process performance counter block | P/Invoke `RegQueryValueEx(HKEY_PERFORMANCE_DATA, "230", ...)` — counter index 230 = Process object |
| T2 | WNetHelper parses PERF_DATA_BLOCK → PERF_OBJECT_TYPE → PERF_INSTANCE_DEFINITION to extract PID and process name per instance | Struct marshalling on raw counter buffer |

### `[SERVICES]` — T1007 (novel approach)

| # | Behavior | API / Method |
|---|---------|-------------|
| V1 | WNetHelper opens `HKLM\SYSTEM\CurrentControlSet\Services` and enumerates subkeys | `RegistryKey.OpenSubKey()`, `GetSubKeyNames()` |
| V2 | WNetHelper reads `Start`, `Type`, `DisplayName`, `ImagePath` values per service subkey | `RegistryKey.GetValue()` |
| V3 | WNetHelper filters to Win32 services (Type includes 0x10 or 0x20) and formats output | In-process filter — no SCM interaction |

### `[MEMBERS]` — T1069.001

| # | Behavior | API / Method |
|---|---------|-------------|
| M1 | WNetHelper binds to local computer via WinNT provider | `DirectoryEntry("WinNT://<hostname>,computer")` |
| M2 | WNetHelper enumerates local groups | `Children` filtered by `SchemaClassName == "Group"` |
| M3 | WNetHelper enumerates members of each local group | `group.Invoke("Members")` |

### `[FILES]` — T1083

| # | Behavior | API / Method |
|---|---------|-------------|
| F1 | WNetHelper enumerates top-level entries under target paths | `Directory.GetFileSystemEntries()` on `C:\Users\`, `C:\Windows\Temp\`, Desktop, Documents |

### `[HOSTS]` — T1018 (existing, unchanged)

NBNS scan — không thay đổi behavior. Thêm `[HOSTS]` section header khi dùng `scan` hoặc `all` mode.

---

## Command interface

```
WNetHelper.exe <cidr>           backward compat — NBNS scan, no section header
WNetHelper.exe scan <cidr>      NBNS scan với [HOSTS] header
WNetHelper.exe local            [PROFILE] → [SESSION] → [TASKS] → [SERVICES] → [MEMBERS] → [FILES]
WNetHelper.exe all <cidr>       local + scan: 7 sections theo thứ tự trên
```

Thứ tự sections trong `all`:

```
[PROFILE]   T1082    Environment + WMI
[SESSION]   T1033    WindowsIdentity + groups
[TASKS]     T1057    Performance counter (HKEY_PERFORMANCE_DATA)
[SERVICES]  T1007    Registry (CurrentControlSet\Services)
[MEMBERS]   T1069.001  WinNT ADSI
[FILES]     T1083    Directory.GetFileSystemEntries
[HOSTS]     T1018    NBNS UDP/137 scan
```

---

## File changes

| File | Loại | Mô tả |
|------|------|-------|
| `SharpNBTScan/SharpNBTScan/Program.cs` | Sửa | Thêm mode dispatch (`all`/`local`/`scan`); tách NBNS logic thành `RunScan()`; thêm `RunLocal()` |
| `SharpNBTScan/SharpNBTScan/SysCollector.cs` | Tạo mới | 6 collector classes: `SystemProfile`, `SessionInfo`, `ProcessCounter`, `ServiceRegistry`, `GroupMembership`, `PathEnumerator` |
| `SharpNBTScan/SharpNBTScan/PerfCounter.cs` | Tạo mới | P/Invoke declarations + PERF_DATA_BLOCK struct marshalling cho `HKEY_PERFORMANCE_DATA` process enum |
| `SharpNBTScan/SharpNBTScan/SharpNBTScan.csproj` | Sửa | Thêm references: `System.DirectoryServices`, `System.Management`; thêm compile items `SysCollector.cs`, `PerfCounter.cs` |
| `SharpNBTScan/SharpNBTScan/NBNSResolver.cs` | Không đổi | — |
| `README.md` | Sửa | Cập nhật Usage, thêm bảng technique coverage |
| `Flow.md` | Sửa | Thêm behavior rows cho modules mới |
| `Build.md` | Sửa | Ghi chú assembly dependencies (không còn `System.ServiceProcess`) |

---

## Constraints

- Target framework: **.NET Framework 4.8** — không dependency ngoài BCL + standard Windows assemblies
- Toolchain: **MSBuild via VS Build Tools 2022** — giữ nguyên build command
- Backward compat: `WNetHelper.exe <cidr>` vẫn hoạt động như cũ
- Neutral identifiers: giữ naming convention hiện tại (không `[+]`/`[-]`/offensive markers)
- Error isolation: mỗi collector dùng try/catch độc lập
- **Không import `System.ServiceProcess`** — service enum qua registry, giảm import profile
- **Không import `System.DirectoryServices.Protocols`** — chỉ dùng `System.DirectoryServices` (WinNT ADSI cho local groups)
- **Assembly references cuối cùng chỉ thêm 2**: `System.DirectoryServices` (WinNT ADSI), `System.Management` (WMI)

---

## Status

- [x] PerfCounter.cs — P/Invoke + offset-based parsing (BitConverter, không dùng struct marshalling do layout sai); đã fix warm-up retry + bounds check
- [x] Compile + dry-run verify — verified trên lab (WS01): cả 7 modules chạy đúng; TASKS trả 105 processes (x86 offsets, PTR=4) sau fix BitConverter
- [x] SysCollector.cs — viết 6 collector classes (ProcessCounter, ServiceRegistry dùng novel approach) + Diag helper
- [x] Program.cs — thêm mode dispatch + `-v` verbose flag
- [x] SharpNBTScan.csproj — thêm references và compile items
- [x] README.md — cập nhật
- [x] Flow.md — cập nhật
- [x] Build.md — cập nhật
