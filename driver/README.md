# Skidrow Killer — Kernel Minifilter (`skk.sys`) — Phase 1 scaffold

> ⚠️ **This folder is NOT part of the .NET solution or its CI build.** It is a kernel-mode driver
> scaffold and must be built with the **Windows Driver Kit (WDK)**, not `dotnet`. It is **UNVERIFIED**
> — review and test it with **Driver Verifier in a VM** before loading it anywhere real. A faulty kernel
> callback can cause a **BSOD**.

This is the concrete starting point for the kernel real-time engine described in
[`../docs/KERNEL_DRIVER_ARCHITECTURE.md`](../docs/KERNEL_DRIVER_ARCHITECTURE.md).

## What Phase 1 does
- Registers a filesystem **minifilter** (FltMgr) and attaches to volumes.
- Observes `IRP_MJ_CREATE` (file opens/creations) and returns immediately — **monitor-only, fail-open**.
  It does **not** pend or block I/O yet, so it cannot hang or deny file access.
- Proves the driver loads, attaches, and sees file activity (visible via `DbgView`/WinDbg `DbgPrintEx`).

## What it does NOT do yet (Phase 2+)
- No communication port to user mode, no verdict round-trip, no blocking.
- No process-creation / registry callbacks, no self-protection. (See the design doc.)

## Build (developer machine)
1. Install **Visual Studio** + the **WDK** (matching versions) and the **Spectre-mitigated libs**.
2. Create a *Kernel Mode Driver → Filter Driver: Filesystem Minifilter* project, or an empty WDM/KMDF
   driver, and add `skk.c` + `skk.inf` to it (the `.vcxproj` is intentionally not committed because it
   is tightly bound to your installed WDK version — let VS generate it).
3. Build `x64 / Debug`. Output: `skk.sys`, `skk.inf`, `skk.cat`.

## Load for testing (test machine / VM only)
```powershell
# 1. Enable test-signing (the dev driver is not production-signed) and reboot:
bcdedit /set testsigning on

# 2. Install + start the minifilter:
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 .\skk.inf
fltmc load skk

# 3. Watch output in DebugView (Sysinternals) or WinDbg.
# 4. Stop / remove:
fltmc unload skk
```

## Production gate (to actually ship + replace Defender)
- **EV code-signing** + **WHQL / attestation signing** via Microsoft Partner Center.
- **Microsoft Virus Initiative (MVI)** membership → **ELAM** driver + **Windows Security Center**
  registration, after which Windows Defender stands down automatically (the legitimate path).
