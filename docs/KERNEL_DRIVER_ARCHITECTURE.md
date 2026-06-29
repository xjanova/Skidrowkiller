# Skidrow Killer — Kernel-Mode Real-Time Protection Architecture (Design)

> Status: **design / roadmap**. This document describes the kernel component required to move
> Skidrow Killer from a strong *user-mode* scanner to a *real* real-time AV on par with Malwarebytes /
> Defender. It is the single biggest capability gap today: our current real-time guards (FileSystemWatcher,
> WMI `Win32_ProcessStartTrace`, periodic polls) all run in **user mode** and can be bypassed, raced, or
> blinded by kernel-level / rootkit malware.

## Why user-mode is not enough

| Capability | User-mode (today) | Kernel-mode (this design) |
|---|---|---|
| See a file **before** it is written/executed | ❌ (notified after the fact) | ✅ pre-create/pre-write callback, can **block** |
| Block a malicious process **before** it runs | ❌ | ✅ pre-process-creation callback |
| Survive a rootkit hiding files/keys | ❌ | ✅ kernel has ground truth |
| Tamper resistance (malware killing our process) | ⚠️ limited | ✅ protected process + driver watchdog |
| Catch fileless / injection at the API boundary | partial | ✅ via kernel callbacks |

## Components

```
┌────────────────────────────────────────────────────────────┐
│  User mode                                                  │
│  ┌──────────────────┐   FltSendMessage / IOCTL   ┌────────┐ │
│  │ SkidrowKiller.exe │◄──────────────────────────►│ Service │ │
│  │  (WPF UI)         │   verdict requests/results  │ (svc)   │ │
│  └──────────────────┘                              └───┬────┘ │
│        ▲  ReputationService / ThreatAnalyzer (scan)     │      │
└────────┼────────────────────────────────────────────────┼─────┘
         │ FilterCommunicationPort (FltMgr comms port)     │
┌────────┼────────────────────────────────────────────────┼─────┐
│  Kernel│ mode                                            ▼     │
│  ┌─────┴───────────────────────────────────────────────────┐ │
│  │ skk.sys  — Filesystem Minifilter (FltMgr / KMDF)         │ │
│  │  • IRP_MJ_CREATE / pre-write  → ask user mode to scan    │ │
│  │  • ObRegisterCallbacks        → protect our process      │ │
│  │  • PsSetCreateProcessNotifyRoutineEx → pre-exec block    │ │
│  │  • CmRegisterCallbackEx       → registry persistence     │ │
│  └─────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

1. **`skk.sys` — Filesystem minifilter** (FltMgr). Registers a pre-operation callback on
   `IRP_MJ_CREATE` (and optionally `IRP_MJ_WRITE`/cleanup). On a relevant open/execute it pends the IRP,
   sends the path + a transaction id up the **communication port** (`FltCreateCommunicationPort`), and
   waits (bounded timeout) for a verdict. ALLOW → complete normally; BLOCK → `STATUS_VIRUS_INFECTED` /
   `STATUS_ACCESS_DENIED`. A kernel verdict cache (by file id + USN) avoids re-asking for known-good files.
2. **Process-creation callback** — `PsSetCreateProcessNotifyRoutineEx2` to inspect (and optionally veto,
   via the `CreationStatus` field) a process *before* its first instruction runs — true pre-execution blocking
   that the current WMI `Win32_ProcessStartTrace` approach cannot do (it only observes after start).
3. **Self-protection** — `ObRegisterCallbacks` strips `PROCESS_TERMINATE`/`VM_WRITE` handle rights to our
   own process/service so malware cannot kill the scanner; the driver also re-launches the service if it dies.
4. **Registry callback** — `CmRegisterCallbackEx` to see (and block) writes to the ASEP keys the user-mode
   `PersistenceScanner` already knows about, at the moment they happen.

## User-mode side (reuse what we already built)

The driver does **no detection logic** — it only intercepts and asks. The verdict is produced by the
existing engine (`ThreatAnalyzer` + `ReputationService` + threat-intel hashes), so all 20 detection layers
are reused. A small Windows **service** (`SkidrowKiller.Guard`) owns the comms port (the UI process may be
closed); the WPF UI talks to the service over a local pipe for status/config.

## Hard requirements to ship this (the "replace Malwarebytes" gate)

- **WDK** (Windows Driver Kit) + a separate C/C++ driver project (cannot live in the .NET project).
- **Driver signing**: production kernel drivers must be **EV-code-signed and submitted to the Microsoft
  Partner Center / attestation or WHQL** signing portal. Self-signed test drivers only load with test-signing on.
- **Microsoft Virus Initiative (MVI)** membership → unlocks the **ELAM** (Early-Launch Anti-Malware) driver
  and lets us **register with Windows Security Center**, after which Defender automatically stands down.
  *(This is the legitimate answer to "make Defender turn itself off" — not a registry hack.)*
- Pass an independent test (AV-TEST / AV-Comparatives) for credibility.

## Phased rollout

1. **Phase 1 — Minifilter (monitor-only):** load `skk.sys`, log every create/exec to the service, no blocking.
   Validate stability + perf on real workloads.
2. **Phase 2 — Blocking:** pend IRPs and enforce verdicts from the engine; add the kernel verdict cache.
3. **Phase 3 — Process/registry callbacks + self-protection.**
4. **Phase 4 — ELAM + WSC registration (MVI)** → Defender auto-disables; ship signed.

## Risks

- A buggy kernel callback = **BSOD**. Must be developed against the WDK with Driver Verifier, fuzzed, and
  fail-open on any internal error (never block boot/critical processes).
- Verdict round-trips on `IRP_MJ_CREATE` add latency to every file open — the kernel cache and an
  allow-by-default-on-timeout policy are mandatory for usability.
- Until MVI/WHQL signing is obtained, the driver only loads with test-signing (dev only).
