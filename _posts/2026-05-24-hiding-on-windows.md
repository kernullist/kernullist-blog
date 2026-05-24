---
title: "About Hiding on Windows: DKOM, Injection, BYOVD, and Cross-View Detection"
date: 2026-05-24 00:00:00 +0900
categories: [Windows Internals, Anti-Cheat]
tags: [dkom, byovd, rootkit, anti-cheat, process-injection, hollowing, herpaderping, ghosting, patchguard, hvci, etw, windows]
---

> Hiding on Windows is not a single technique. It is the practice of selectively erasing — or lying about — the existence of a process, thread, DLL, driver, callback registration, or executable memory region on some of the dozen-plus observation surfaces Windows exposes, while accepting that whatever is hidden must remain on the surfaces that actually run code. A "hidden" process that has truly removed itself from every list cannot be scheduled, cannot fault a page, cannot hold a handle, and cannot execute. The same is true at the thread level, the driver level, and the executable-region level. So every real attacker chooses which lists to leave behind and which to corrupt — and every credible defender measures the gap between them. This is a technical walk through that gap, from the classic FU-rootkit `ActiveProcessLinks` unlink to current 2024–2026 BYOVD ecosystems, callback-blinding rootkits, and stealth-execution tradecraft, and how cross-view detection survives each technique.

## 1. Threat Model

A "hidden object" in this document is any execution-bearing or evidence-bearing artifact on a Windows host — a process, a thread, a loaded DLL, a kernel driver, a callback registration, an executable memory region, even a serviced IOCTL handler — whose presence the attacker is trying to suppress from at least one observer the defender controls. The observer might be `NtQuerySystemInformation`, Task Manager, a kernel callback, an ETW consumer, a memory acquisition tool, or an offline disk forensicator. The attacker — game-cheat injector, BYOVD payload, malware family, post-exploitation tradecraft — has succeeded if every meaningful observer in the defender's pipeline either fails to enumerate the artifact or returns falsified state for it. Processes are the most-discussed case because they have the richest enumeration surface, but the same logic applies to every other artifact class, and the same cross-view methodology defeats all of them.

Four observations shape the rest of this document:

1. **No single API is authoritative.** The `NtQuerySystemInformation(SystemProcessInformation)` enumeration is built on the executive's `PsActiveProcessHead` list. It is one source of truth out of many, and it is the cheapest to corrupt. Win32 APIs (Toolhelp, PSAPI, WMI), kernel callbacks, the scheduler, the memory manager, the object manager, ETW, and the file/registry subsystems each see a different facet of the process and must be cross-checked.
2. **Execution leaves traces the lists cannot.** A running thread must appear on some CPU's `KPRCB.CurrentThread`, must own a `KTHREAD` and `ETHREAD`, must walk an address space whose `KPROCESS.DirectoryTableBase` is non-zero, and must hold executable memory. Removing a process from the active list does not remove it from these. The defender's leverage is to follow execution backwards into identity, instead of forward from identity into execution.
3. **DKOM presupposes kernel write.** The classic "unlink `ActiveProcessLinks`" trick from Jamie Butler's FU rootkit (2004) requires arbitrary kernel write. On modern x64 Windows this almost always means a Bring-Your-Own-Vulnerable-Driver (BYOVD) chain, a manually-mapped driver, or a kernel exploit. Therefore process hiding and driver concealment are the same investigation conducted at two layers. PiDDBCacheTable scrubbing and `MmUnloadedDrivers` wiping should be treated as native parts of the process-hiding evidence chain.
4. **Timeline binds the evidence.** A single snapshot diff produces false positives (process exit races, protected processes, security-product timing). Pinning a driver load, a vulnerable IOCTL call, a callback list gap, a VAD executable region creation, a handle acquisition, and a KPRCB thread sample to one timestamped session converts noise into evidence.

Strong signals — those most credible cross-view inconsistencies — recur throughout this document. As a teaser:

| Signal | Implication |
|--------|-------------|
| `KPRCB.CurrentThread` or `ETHREAD.Tcb.Process` references a process not on `ActiveProcessLinks` | DKOM-hidden process, high confidence |
| Live thread's TID lookup via `PsLookupThreadByThreadId` fails while KPRCB sees it | `PspCidTable` scrubbing or thread unlink |
| `DRIVER_OBJECT` dispatch / callback target falls outside any loaded module range | Manually mapped driver or dispatch hijack |
| CI/SCM event ledger has driver load, but `PiDDBCacheTable` and `MmUnloadedDrivers` have nothing for it | Driver artifact scrub (BYOVD chain) |
| Game process holds a private executable VAD with a thread sampled inside it | Manual-map DLL, shellcode, reflective loader |
| Section's backing-file hash (via `EPROCESS.SectionObject → ControlArea → FilePointer`) ≠ main image's in-memory hash | Hollowing, herpaderping, reimaging |

A Volatility-community aphorism captures the practical implication: *"Hiding consistently from seven sources is harder than just injecting into a benign process."* Cross-view detection earns its keep because it forces the attacker to play the latter game.

---

## 2. The Cross-View Imperative

### 2.1 Attacker Tiers

| Tier | Representative actor | Primary hiding strategy |
|------|----------------------|--------------------------|
| L1 user-mode | Trainer, overlay cheat, commodity malware | Win32 API hook, PEB LDR unlink, process name spoof, DLL injection |
| L2 admin user-mode | Loader, injector, service installer | Handle duplication, doppelganging, ghosting, service-artifact deletion |
| L3 kernel BYOVD | Vulnerable signed driver abuse | DKOM, callback blinding, arbitrary kernel R/W, driver-trace scrub |
| L4 manually-mapped kernel | Unsigned PE mapped into kernel space | `PsLoadedModuleList` evasion, executable kernel memory without backing image, timer/DPC callback execution |
| L5 platform | Hypervisor cloaking, DMA card, bootkit | EPT/NPT view splitting, off-host memory R/W, pre-OS tampering |

Process hiding starts to require kernel write at L3. Anti-cheat that only watches user-mode (L1–L2) is structurally limited to detecting amateurish cheats. Anti-cheat that places its kernel components on the same SLAT-protected side as HVCI is reaching toward L4. Detecting L5 reliably requires hardware attestation, which is why anti-cheat industry trends (Vanguard requiring TPM 2.0 + Secure Boot since 2024) point in that direction.

### 2.2 Observation Surfaces

Process existence in Windows is the **union** of the following sources. Each has a different cost-to-corrupt and a different cost-to-observe.

| Surface | Representative reads | Trust | Common corruption |
|---------|----------------------|------:|--------------------|
| User-mode API | Toolhelp, PSAPI, WMI, `NtQuerySystemInformation` | Low | API hook, result filtering |
| Kernel list | `PsActiveProcessHead`, `KiProcessListHead`, session/job/MM list | Medium | DKOM unlink |
| PID/TID lookup | `PspCidTable` | Medium | Entry nulling, object-pointer tamper |
| Scheduler | `KPRCB.CurrentThread`, `KTHREAD.Process` | High | Extremely hard to spoof |
| Thread object | `ETHREAD`, thread list, pool scan | High | Thread unlink, pool tag spoof |
| Memory manager | VAD tree, section object, leaf PTE | High | VAD unlink, VAD/PTE protection split |
| Object/Handle | Handle table, object directory, `DRIVER_OBJECT` | Medium-high | Handle cloak, object unlink |
| Telemetry | ETW, callbacks, SCM, CodeIntegrity, event log | Medium-high | Callback unregister, ETW session patching |
| Kernel code | `PsLoadedModuleList`, callback target, executable kernel memory | High | Manual map, dispatch hijack |
| Offline / remote | Crash dump, server timeline, remote log shipper | Very high | Live rootkit cannot reach |

The defender's decision procedure is a single inequality:

```text
HiddenCandidate =
    PresentOnStrongSource
    AND AbsentFromExpectedWeakOrMediumSource
    AND NoLifecycleExplanation (exit grace window, protected process, etc.)
```

Concretely:

```text
ProcessSeenBy(KPRCB ∪ ETHREADPool ∪ VADThreadRIP)
AND NOT SeenBy(ActiveProcessLinks)
AND NOT HasExitLedgerWithinGraceWindow(2s)
```

This is the spine of every cross-view detector in this document. The hard part is not the inequality; it is keeping the strong-source collectors stable across Windows builds, low-IRQL race-free, and not collapsing into the same blind spot the attacker is exploiting.

### 2.3 Five Operational Principles

1. **Enumerate twice, trust neither.** At one moment in time, collect user API results, kernel callback ledgers, kernel walks, and pool scans concurrently. Diff later.
2. **Preserve the creation-time record as an append-only ledger.** PEB, VAD identity, file object, signer can all be rewritten post-fact; the create-time record cannot.
3. **Look at execution units, not just processes.** Even if no hidden process exists, an injected thread, an APC, a hollowed image, or a private RX page does.
4. **Watch the watchers.** A callback that no longer fires looks identical to silence. Self-check callbacks and ETW sessions; a dead callback is a louder signal than the threats it would have caught.
5. **Separate live decisions from forensic decisions.** Live blocking must tolerate false positives and latency; forensic determination can use crash dumps, TPM quotes, and boot-chain measurements at leisure.

---

## 3. The DKOM Foundation

DKOM — Direct Kernel Object Manipulation — is the foundation technique. The attacker does not "kill" the process; the attacker rewrites linked lists, lookup tables, and reference graphs so that selected enumeration paths fail to find it. The technique dates to Jamie Butler's FU rootkit (2004) and remains the conceptual core of every commodity game-cheat kernel mapper.

The classical methodology is still pedagogically clean, but two architectural changes since 2004 have changed its real-world calculus on x64:

- **PatchGuard (Kernel Patch Protection)** covers `PsActiveProcessHead`, `PspCidTable`, `KiProcessListHead`, the SSDT, IDT/GDT, syscall MSRs, `KdDebuggerData`, `PsLoadedModuleList`, and an expanding set of callback rosters (`PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PsLoadImageNotifyRoutine`, `CmCallbackListHead`, the object-callback lists). A naive unlink that leaves footprints PG detects produces a `BUGCHECK 0x109 CRITICAL_STRUCTURE_CORRUPTION` somewhere between seconds and tens of minutes later. The exact interval is governed by randomized timer DPCs, scheduler-tick checks, and various interrupt-side validations — there is no fixed "10-minute clock," despite the folklore.
- **HVCI / Memory Integrity** turns many of these structures into pages that are non-writable from VTL0 (the normal kernel side). A BYOVD payload trying to write to them gets a SLAT violation before PatchGuard runs. On a device shipping with HVCI on by default — most new Windows 11 22H2+ OEM devices, per Microsoft's recommended-driver-block-rules documentation — direct DKOM against these structures is materially harder, and modern attackers increasingly target callback list entries living in writable data pages, or attack at the secure kernel boundary instead.

The combined effect is that DKOM is still the *concept* defenders must master, but the modern attacker rarely unlinks `ActiveProcessLinks` and walks away — they unlink it, scrub the PiDDB and unloaded-driver evidence of the BYOVD that did the writing, and unhook callback arrays to blind further inspection. Detection therefore must follow the same chain.

### 3.1 `ActiveProcessLinks` Unlink

Targets:

- Head: `nt!PsActiveProcessHead`
- Entry: `EPROCESS.ActiveProcessLinks` (a `LIST_ENTRY`)
- Associated fields used to authenticate an entry: `EPROCESS.UniqueProcessId`, `ImageFileName`, `CreateTime`, `RundownProtect`

Effect:

- `NtQuerySystemInformation(SystemProcessInformation)` enumeration drops the entry.
- Task Manager, Process Explorer, and any anti-cheat doing a "simple process scan" miss it.
- The process continues to run because the scheduler does not consult this list.

Unlink patterns observed in commodity tools:

| Pattern | Description | Detection signature |
|---------|-------------|---------------------|
| Self-reference | `Flink == Blink == &self.ActiveProcessLinks` | Trivial; single-node invariant check |
| Forward-only orphan | Entry removed; `Flink`/`Blink` left dangling | Adjacent-node `Flink->Blink == entry`/`Blink->Flink == entry` invariant breaks |
| Spoof-to-other | `Flink`/`Blink` repointed at another live `EPROCESS` | List walk looks consistent; only forward-vs-backward walk diff or pool-scan cross-view exposes it |
| Spoof-to-decoy | Fake `EPROCESS`-shaped allocation, links repointed at it | Dispatcher-header / object-header invariants on the decoy fail |

Detection procedure that survives all four patterns:

1. Walk `PsActiveProcessHead` to form `ActiveSet`. Walk forward via `Flink` and backward via `Blink` independently; diff the two sets.
2. Build `StrongSet` from KPRCB sampling, ETHREAD pool scans, the `PspCidTable`, the handle table, and VAD thread-RIP attribution.
3. `Candidate = StrongSet - ActiveSet`.
4. For each candidate, verify `EPROCESS` invariants (dispatcher header `Type == ProcessObject(3)`, `UniqueProcessId` in a plausible range, `DirectoryTableBase` page-aligned with valid physical range, `ImageFileName` printable ASCII).
5. Compare against the process-creation ledger to filter out exit races (process exited in the grace window between `StrongSet` and `ActiveSet` collection).

### 3.2 `PspCidTable` Scrubbing

`PspCidTable` is the kernel handle table that maps PIDs and TIDs to process/thread object pointers. `PsLookupProcessByProcessId`, `PsLookupThreadByThreadId`, and many `OpenProcess`/`OpenThread` code paths fall through it. Tampering can take the form of nulling individual entries, repointing them at decoys, or freezing the entire table from view through inline hooks of the lookup routines.

The structure is `_HANDLE_TABLE` on Windows 7 through 11 24H2; layout has been stable across recent releases though field offsets shift between builds. It is global and per-system (unlike per-process `EPROCESS.ObjectTable`).

Detection: take any TID seen on `KPRCB.CurrentThread` and re-resolve it through `PsLookupThreadByThreadId`. A lookup failure on a TID that the scheduler is currently running is `CidMissingLiveThread` — a strong DKOM signal. Likewise resolve KPRCB-derived PIDs through `PsLookupProcessByProcessId` and the active list; diverging answers indicate `PspCidTable` tampering or active-list spoofing.

### 3.3 `KiProcessListHead` and the KPROCESS View

A subtle architectural fact: the first member of `EPROCESS` is `KPROCESS Pcb`. The same process object is linked into two distinct lists at two different `LIST_ENTRY` offsets in the same allocation:

| List head | Entry field | Used by |
|-----------|-------------|---------|
| `PsActiveProcessHead` | `EPROCESS.ActiveProcessLinks` (executive view) | `NtQuerySystemInformation(SystemProcessInformation)`, generic process enumeration |
| `KiProcessListHead` | `EPROCESS.Pcb.ProcessListEntry` (kernel/scheduler view) | Scheduler bookkeeping, KPROCESS-level walks |

An attacker who only unlinks `ActiveProcessLinks` leaves `KiProcessListHead` populated. Tampering with both lists requires knowing both offsets and both locks (`PspActiveProcessLock` for the executive side and a KPROCESS-side spinlock for the kernel side), and risks PatchGuard's coverage of KPROCESS invariants. Many commodity mappers don't bother; their hidden processes remain visible to a `KiProcessListHead` walk. This list is one of the few inexpensive cross-views available to a kernel-mode detector and survives the most common DKOM tier.

Note: on early Windows 8 builds `KiProcessListHead` was sometimes empty; on Windows 10 1903 and later it is reliably populated. Use as supplementary cross-view rather than primary identity source.

### 3.4 Other Process List Heads

The following lists are also worth diffing, in roughly descending order of usefulness:

- `HandleTableListHead` — kernel-wide handle-table list. The classical "walk handle tables to find process owners" backstop survives DKOM that only touches `ActiveProcessLinks`.
- `EPROCESS.SessionProcessLinks` — per-session linkage. Token session ID can be cross-checked.
- `EPROCESS.JobLinks` — per-job linkage. Job objects retain accounting state.
- `EPROCESS.MmProcessLinks` — memory-manager working set bookkeeping. Tampering here is dangerous (MM relies on its consistency for working-set trimming) so attackers usually skip it, making it a quietly useful confirmation source.

A process that is missing from two or more of these list-head views simultaneously is high-confidence DKOM, not a snapshot race.

---

## 4. Per-Source Detection

### 4.1 Active List Walk

Cheap, fast, almost always the first thing a detector touches — and the first thing an attacker corrupts. Useful precisely *because* of that asymmetry: an `ActiveSet` is the ground truth of what `NtQuerySystemInformation` and Task Manager will report, which is what you need to detect divergence from `StrongSet`.

Integrity invariants on each entry to catch unlink patterns:

- `Flink->Blink == entry` and `Blink->Flink == entry` (forward/backward symmetry)
- `Flink`/`Blink` canonical kernel pointers (sign-extended top bits, alignment)
- No same-`EPROCESS` duplicates
- Bounded walk length; head-return reached

### 4.2 `PspCidTable` Cross-View

Two collection modes:

- **Reverse lookup**: take PIDs/TIDs from create-callback ledger, ETW, KPRCB, and ETHREAD pool, and call `PsLookupProcessByProcessId` / `PsLookupThreadByThreadId`. Cheap, race-prone.
- **Enumeration**: if the build offset is known, walk `PspCidTable` itself (under appropriate locking) and compare against the active/KPRCB/ETHREAD sets. More invasive.

| Signal | Meaning |
|--------|---------|
| PID in create ledger, lookup fails | CID scrub or fast exit |
| Live KPRCB TID, lookup fails | High-confidence thread CID tamper |
| ETHREAD owner PID, lookup fails | CID/active table inconsistency |
| Present in CID, absent from active list | Active-list DKOM, CID untouched |

Exit races are handled by maintaining a `CreateTime`/`ExitTime`/last-KPRCB-hit grace window of one to two seconds.

### 4.3 KPRCB Sampling

The pivotal strong source. Every thread eventually appears on some CPU's `KPRCB.CurrentThread`, and the path `KPRCB.CurrentThread -> KTHREAD.Process -> EPROCESS` is independent of all process-list state. Corrupting this credibly requires hijacking context switches or the CR3 load path — orders of magnitude harder than DKOM.

Two sampling modes:

- **Polling** at a passive-level worker thread: simple, easy to reason about, can miss very short execution bursts.
- **NMI / IPI-based interrupt sampling**: catches sub-millisecond execution. The handler must run at NMI level: snapshot pointers only, defer string/symbol/validation work to a `PASSIVE_LEVEL` worker, accumulate in a per-CPU ring buffer, and union across the entire game session.

For session-scoped detectors, the union-over-time of KPRCB samples is the most damaging evidence an attacker faces: a thread that runs for 100 ms once per minute over an hour-long match cannot avoid the sampler if the sampler runs at even 1 Hz.

Verification on each sampled `(KTHREAD, EPROCESS)` pair:

- `KTHREAD` dispatcher header is a thread object (`KOBJECT_HEADER.Type == ThreadObject`)
- `KTHREAD.Process` points at a structurally valid `EPROCESS`
- `EPROCESS.Pcb.DirectoryTableBase` is non-zero, page-aligned, in plausible physical range
- The associated TID resolves via `PsLookupThreadByThreadId`

A KPRCB hit on a thread whose owner process is not on the active list is the gold-standard DKOM detection.

### 4.4 ETHREAD Pool / Object Scanning

ETHREAD allocations carry the `Thre` pool tag historically (`'erhT'` little-endian). Two changes affect modern systems:

- Segment pool (default for executive allocations since Windows 10 19H1 / 1903) changed the in-memory layout: many allocations no longer carry the classical `POOL_HEADER` immediately preceding the object, and tag-pattern scans miss them. Big-pool allocations are still tracked through `nt!PoolBigPageTable`, but most ETHREAD allocations sit in the segment-pool heaps where pool-tag scanning produces false negatives.
- Volatility 3's modern process plugins (`windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.handles`) reflect this; the old psxview "Proc pool tag missing → hidden process" inference is unreliable on Windows 10 19H1+ and should be treated as a corroborating signal, not a primary one.

A practical Win10/11 collector therefore prefers, in order:

1. KPRCB samples (every live thread)
2. ETHREAD pool walks via `PoolBigPageTable` and segment pool walkers
3. Per-process thread list (`EPROCESS.ThreadListHead`)
4. CID table enumeration

Cross-referencing them against `ActiveProcessLinks` membership and the create-callback ledger yields the candidate set.

### 4.5 Build-Specific Offset Discipline

> **Critical operational warning.** Hardcoded offset tables circulated on cheat forums are dangerous. The same marketing version of Windows (e.g., "Windows 11 23H2") can have multiple cumulative-update builds with `EPROCESS` field offsets that differ by 8 bytes. Detectors that hardcode offsets will eventually BSOD a normal user's machine on a Patch Tuesday Microsoft never advertised as breaking. This has happened publicly to multiple commercial anti-cheats. Use PDB-backed runtime resolution or, failing that, runtime self-validation; on validation failure, **degrade the collector to audit-only — never to enforcement.**

Offset acquisition strategies, ranked:

| Method | Pros | Cons |
|--------|------|------|
| PDB symbol resolve (signed Microsoft PDB cache) | Authoritative, future-build-resilient | Requires symbol-cache infrastructure |
| Exported-helper disassembly (e.g., `PsGetProcessId`, `PsGetProcessImageFileName`) | No symbol server needed | Helpers may be inlined or trampoline-patched |
| Field-signature scan (e.g., ASCII run for `ImageFileName`, page-aligned `DirectoryTableBase`) | Works offline | False-positive prone; sanity-only |
| Anchor-process derivation (`PsInitialSystemProcess`, current process) | Self-bootstrapping | Live-only; cannot fail-stop |

Sanity checks to run on each candidate offset profile before trusting it: `UniqueProcessId` of `System` is 4, `ImageFileName` of `System` is `"System\0"`, `ActiveProcessLinks.Flink/Blink` are canonical kernel pointers, current thread's `KTHREAD.Process` matches `IoGetCurrentProcess()`. On failure, the collector is disabled for this boot, telemetry is shipped, and the next driver update gets a new profile.

---

## 5. Threads and Scheduler Surfaces

### 5.1 Thread List Unlink

Targets the per-process thread enumeration, removing a specific `ETHREAD` from `EPROCESS`'s thread list while leaving the thread itself running. Effect mirrors process unlink at the thread granularity.

Strong-source backstops survive: KPRCB samples, ETHREAD pool scans (modulo segment-pool caveats), kernel stacks, the scheduler's run/wait queues, any object reference. Cross-view detection mechanics are identical to §3.1, applied to threads.

### 5.2 `ThreadHideFromDebugger`

Setting `ThreadInformationClass = ThreadHideFromDebugger (0x11)` via `NtSetInformationThread` sets the `HideFromDebugger` bit in `ETHREAD.CrossThreadFlags` (specifically `PS_CROSS_THREAD_FLAGS_HIDEFROMDBG`). The bit is **set-only** — once set, it cannot be cleared until the thread exits.

Effect: debugger exception events (breakpoints, single-step) for the thread are not delivered to the attached debugger. Some user-mode monitoring loops are blinded.

Detection requires reading `CrossThreadFlags` (offset is build-specific; resolve via PDB). The hide bit alone is not a sufficient malice signal — some legitimate security and DRM products use it — so it must be combined with provenance:

- Hide bit + private RX start address → strong
- Hide bit + remote-thread creation history → strong
- Hide bit + game-process memory handle acquisition by the parent → strong

The ETW provider `Microsoft-Windows-Threat-Intelligence` emits the `NtSetInformationThread(0x11)` call itself, but the provider remains accessible only to consumers running as Protected Process Light with at least `WinTcb` signer — Defender, Elastic, CrowdStrike, SentinelOne qualify; commercial anti-cheats typically do not run as PPL and cannot subscribe.

### 5.3 Timer, DPC, Work Item Execution

Modern stealth tradecraft increasingly skips the visible-thread model entirely. A driver can execute code periodically via `KTIMER` + `KDPC`, via work items, via kernel callback registrations, via WFP callouts, via minifilter dispatch, or via system threads belonging to `System` (PID 4). Process enumeration sees none of this.

| Execution vehicle | Visible artifact |
|-------------------|------------------|
| `KTIMER` + `KDPC` | DPC routine pointer, periodic CPU wakeup |
| Work item | Worker routine pointer, queue owner |
| System thread | `ETHREAD` start address, owning process `System` |
| Object/process/registry callback | Callback list entry, target address |
| Minifilter callout | Filter Manager registration |
| WFP / NDIS / TDI | Per-subsystem registration table |

Defender procedure: build an interval tree over all loaded module ranges (`PsLoadedModuleList`), then attribute every callback / dispatch / timer / DPC / work-item target into that tree. A target outside any loaded module is `CallbackTargetUnknownKernelCode` — strong manual-map signal. A target inside a loaded module but at a non-canonical entry (mid-function, trampoline-shaped prologue) is `InlineHookSuspected`.

---

## 6. Pool, Object, and Handle Cross-View

### 6.1 EPROCESS Validation

When an `EPROCESS` candidate is recovered (from KPRCB, ETHREAD pool, big pool, or list scan), every available structural invariant is checked:

| Field | Check |
|-------|-------|
| Dispatcher header | `KOBJECT_HEADER.Type == ProcessObject(3)`, plausible `Size` |
| Object header | `OBJECT_HEADER.TypeIndex` decodes to `PsProcessType`. The Win10+ decode is a 3-way XOR: `RealIndex = StoredIndex XOR nt!ObHeaderCookie XOR ((BYTE)(ObjectHeader >> 8))`. Both the global cookie and the low byte of the header's own address participate, so a single canonical value cannot be hardcoded. |
| `UniqueProcessId` | Within plausible PID range, matches creation ledger if any |
| `ActiveProcessLinks` | Pointer invariants or self-reference |
| `ObjectTable` | Valid handle-table pointer |
| `Token` | `EX_FAST_REF` form, type-checks as token object |
| `VadRoot` | User-address-range tree |
| `Pcb.DirectoryTableBase` | Page-aligned, valid physical range |
| `ImageFileName` | Printable, matches creation-ledger identity |

A validated `EPROCESS` absent from `ActiveProcessLinks` is the canonical DKOM hit. A `KTHREAD.Process` pointer recovered from KPRCB pointing at an unvalidated allocation is a high-suspicion candidate but warrants additional confirmation before action — terminated-thread artifacts can briefly resemble live ones.

### 6.2 ETHREAD Validation

`KTHREAD.Process` (or `ApcState.Process`, depending on build) cross-checks the owner. Kernel stack bounds, dispatcher header, and TID-resolution via `PspCidTable` form the next layer. Start-address attribution and current-RIP attribution into the VAD/module set provide the execution evidence.

### 6.3 Handle Cloaking

The object-manager / handle-table surface is the second-largest hiding playground after the process-list family. Common techniques:

| Technique | Mechanism | Detection |
|-----------|-----------|-----------|
| Pre-open handles | Open game/process handles before anti-cheat's `ObRegisterCallbacks` is even installed | Initial-snapshot sweep at protection start, inheritance audit |
| Handle duplication laundering | Broker process receives `DuplicateHandle` traffic and re-issues handles to cheat | Source/target lineage on `DuplicateHandle` calls |
| Handle-table entry tamper | Modify object pointer / granted-access bits in a handle table entry | Raw table walk vs. `NtQuerySystemInformation(SystemHandleInformation)` diff |
| Pseudo-handle / path confusion | API-layer obfuscation only | Object pointer / type validation |
| PPL spoofing | Claim `EPROCESS.Protection` PPL level it isn't entitled to | Signer-level / token / protection-field consistency |
| Direct kernel R/W via vulnerable driver | No handle needed | IOCTL broker analytics, vulnerable-driver inventory |

The rule that summarizes the surface: **don't ask "who has a handle to the game?"; ask "who got to read game memory and how?"** The second question covers the BYOVD-broker pattern that doesn't require an open handle at all.

A request for `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD` against the game process from an untrusted, recently-launched, unsigned parent is a strong signal — but `PROCESS_VM_READ` alone produces false positives against legitimate overlays, accessibility tools, and AV. The combination is what carries the score.

---

## 7. User-Mode Enumeration Filtering

The cheapest hiding tier: hook user-mode APIs and filter their results. No kernel write, no PatchGuard exposure. Common targets:

- `NtQuerySystemInformation(SystemProcessInformation)`
- `CreateToolhelp32Snapshot` / `Process32First` / `Process32Next`
- `EnumProcesses` (PSAPI)
- WMI `Win32_Process`
- .NET `Process.GetProcesses`
- PowerShell `Get-Process`

Two implementation flavors. The naive form patches the IAT or the inline prologue of the API in the *observer* process; the more sophisticated form lives in a DLL injected into every untrusted process and edits the result buffer (deleting entries, recomputing `NextEntryOffset` chains to keep the linked list valid). The most adversarial form is observer-aware: it activates the hooks only when known monitoring processes are running (Task Manager, Process Explorer, ProcMon, System Informer, anti-cheat sensor names).

Because the kernel is untouched, this tier loses to anything kernel-side:

| Detection | Mechanism | Caveat |
|-----------|-----------|--------|
| API cross-view | Diff `NtQuerySystemInformation` vs. Toolhelp vs. WMI vs. ETW snapshot | Tools must not all be hooked from the same hook source |
| `ntdll` integrity | Hash the `.text` section, validate syscall stub bytes | EDR products commonly hook ntdll themselves — false-positive prone |
| Clean-mapping fallback | Map a fresh, known-good `ntdll.dll` from disk and compare | Hotpatching and forwarder differences must be tolerated |
| Direct-syscall canary | Issue the same query through a normal `ntdll!Nt*` path and through a hand-rolled direct syscall; diff | Catches user-mode hooks; cannot catch kernel-mode hooks |
| Sensor diversity | Run multiple internal sensor processes with randomized names | Observer-aware malware can learn names from a long run |

Anti-cheat use of this tier is necessarily *as a low-confidence signal* — divergence triggers escalation to kernel-side checks, not direct blocking. Defender's leverage comes from the inability of user-mode hooks to suppress kernel callbacks and ETW.

### 7.1 Modern Refinement: Direct/Indirect Syscalls and Call-Stack Spoofing

A development largely post-2022 has changed what user-mode evasion means for *attackers* (and therefore what user-mode detection means for *defenders*):

- **Direct syscalls** (Hell's Gate / Halo's Gate / Tartarus Gate lineage) — payload reads the syscall number from a copy of ntdll mapped from disk, then executes `syscall` directly, bypassing inline hooks placed in the live ntdll image.
- **Indirect syscalls** — same idea, but jumps to a real `syscall; ret` gadget *inside* the legitimate ntdll image so the return address attribution looks correct to call-stack analyzers.
- **Call-stack spoofing** (SilentMoonwalk, Vulcan Raven, Hades, etc.) — manipulates the stack so that any call-stack walk from a kernel callback or ETW handler shows return addresses originating from legitimate Windows DLLs, hiding the payload module from RIP/return-address attribution.

Elastic Security Labs' "Upping the Ante: Detecting In-Memory Threats with Kernel Call Stacks" (2023) and "Doubling Down: Detecting In-Memory Threats with Kernel ETW Call Stacks" (Jan 2024) document the defender side. The current consensus is that **kernel-side call-stack inspection at ETW callback time** is the single most effective detection layer for in-memory tradecraft, because:

- Kernel call stacks are taken at the moment the syscall actually entered the kernel, by code the attacker did not get to patch.
- Frame attribution into module ranges resists the surface-level evasions that defeat user-mode hooks.
- The detector runs in a process the attacker cannot inject (PPL, in a separate kernel driver).

For anti-cheat specifically, this is one of the most material 2024–2026 detection upgrades — every modern EDR has moved into this layer, and game-security vendors should follow.

---

## 8. Process Identity Forging

A process the attacker cannot hide, the attacker dresses up. The set of fields that affect "what is this process" goes well beyond `ImageFileName`:

### 8.1 `EPROCESS.ImageFileName`

15-byte short-name field. Cheap to overwrite from kernel mode, makes `cheat.exe` appear as `svchost.exe` to anything that reads this field. The create-callback ledger has the original. Diff.

### 8.2 `EPROCESS.SeAuditProcessCreationInfo`

Holds a pointer to a full image path. Tampering produces full-path lies that survive longer than `ImageFileName` overwrites. Defense is the same: persist file id / hash / signer at create time, compare. Do not let path strings be authoritative; file id and hash are.

### 8.3 PEB `ProcessParameters`

User-mode writable. `ImagePathName`, `CommandLine`, current directory, environment — all rewritable from the process itself. PEB tampering for command-line obfuscation is universal in modern malware. The create-time snapshot recorded by the process-create callback is the authoritative version.

### 8.4 PPID Spoofing

`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` lets a `CreateProcess` caller specify an arbitrary parent process (provided the caller has a `PROCESS_CREATE_PROCESS` handle to it). The cheat loader can therefore appear to be a child of `explorer.exe`, the game launcher, or `services.exe`. Detection requires storing the actual creator at create-time, plus verifying that the claimed parent ever had the handle inheritance needed.

### 8.5 Token / Session / Job / Silo Spoofing

Privilege, integrity, elevation state, session ID, job/silo membership — every one of these can be repointed by a kernel-mode write. The defender compares against the kernel's own session list, job-object accounting, and signer-driven policy. A `svchost`-named process running in session 1 from `C:\Users\...\Temp\` is the canonical low-effort masquerade.

### 8.6 Masquerading Inconsistency Table

| Inconsistency | Implication |
|---------------|-------------|
| Name `svchost.exe`, parent is not `services.exe` | Service-host impersonation |
| Microsoft-product version resource, but signer mismatches | Resource-only masquerading |
| System-process name in user-writable path | Standard low-effort malware pattern |
| Command line differs between create-ledger and live PEB | Active PEB tamper |
| Same path, but file id / hash changed after create | Herpaderping / replace race |
| Signer matches, but section-object hash != on-disk hash | Hollowing / doppelganging / ghosting |

### 8.7 Protected Process / PPL Spoofing

`EPROCESS.Protection` (a `PS_PROTECTION` byte) carries the process's protection level (`PsProtectedTypeProtectedLight` vs `PsProtectedTypeProtected`) and signer tier (`PsProtectedSignerWinTcb`, `PsProtectedSignerWindows`, `PsProtectedSignerAntimalware`, `PsProtectedSignerLsa`, `PsProtectedSignerCodeGen`, and so on). The kernel uses this single byte to gate `OpenProcess`, `OpenThread`, and a long list of other operations: a less-privileged caller is denied access to a more-privileged target.

PPL is a major battlefield in modern endpoint security:

- **Anti-cheat and EDR products want to *be* PPL.** Defender, CrowdStrike, Elastic, and SentinelOne all run their core service as PPL/Antimalware so that user-mode malware (even running as SYSTEM) cannot terminate or inject into them. Microsoft documents the WHQL signing flow that earns the Antimalware PPL tier.
- **Malware wants to *appear* PPL.** If the cheat or rootkit can mark itself as `PsProtectedSignerWinTcb`, no normal anti-cheat callback can open it — `ObRegisterCallbacks` won't even fire on most opens because access is denied earlier. From kernel mode this is a one-byte write.
- **Malware wants to *strip* a target's PPL.** The PPLdump / Mimikatz `MIMIDRV` lineage zeros the `Protection` field of `lsass.exe` from a BYOVD-mapped driver, then dumps it. RealBlindingEDR and similar tools do the same to Defender's MsMpEng process.

| Tampering | Mechanism | Detection |
|-----------|-----------|-----------|
| Set own `Protection` to PPL/WinTcb | Kernel write to `EPROCESS.Protection` | `Protection` byte vs. process signer at create time (kernel-recorded), and vs. signature catalog |
| Strip target's `Protection` (LSASS, Defender) | Kernel write to target `EPROCESS.Protection` | Periodic protection-byte verification for known-PPL services; bugcheck history; access-denied audit gap |
| Inherit PPL via parent + handle inheritance bug | Abuse of legacy creation flag combinations | Create-time `PS_PROTECTION` vs. claimed signer chain |
| `OpenProcess(...)` denied with `STATUS_ACCESS_DENIED` from an unexpected process pair | Subtle indicator that target's protection level is higher than expected | Access-denied telemetry from known-non-PPL clients |

On HVCI/Memory-Integrity systems, the `Protection` byte sits in a kernel data page that VBS may keep read-only-from-VTL0 depending on KDP coverage. On systems without HVCI, the byte is a trivial kernel write away. For an anti-cheat the practical detection is: snapshot `Protection` at create time and watch for any change. The legitimate Windows path for setting protection is `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL` at `CreateProcess`/`NtCreateUserProcess` time only — there is no documented API for *mid-life* protection-level elevation, so any change to `Protection` after the process-create callback has fired is essentially always anomalous.

### 8.8 Pico Process / Minimal Process

A *minimal process* is created by the kernel with the `PsCreateMinimalProcess` API path: no PEB, no `ntdll.dll`, no normal user-mode startup. A *pico process* is a minimal process with a registered **Pico Provider** kernel driver attached, which intercepts system calls and emulates a foreign ABI. Microsoft's only shipping pico provider is `lxss.sys` (WSL1) and historically `picohelper.sys`. Almost no other legitimate code runs as a pico/minimal process.

Effects relevant to hiding:

- `PEB == NULL`, so anything that reads PEB via `NtQueryInformationProcess(ProcessBasicInformation)` gets back zero — the process appears "headless."
- `PsLoadedModuleList` and PEB LDR contain nothing for the process.
- Default ETW image-load events do not fire for pico processes.
- The kernel-side markers are the `Minimal` bit in `EPROCESS.Flags3` (or `Flags2`, depending on build — PDB-resolve) and a per-process pico-provider context pointer (named `PicoContext` on most Win10/11 builds, `PicoCorePtr` on some older ones). Treat both names as build-dependent.

For an anti-cheat: a non-WSL pico/minimal process on a Windows gaming endpoint is **strongly anomalous**. The detection is to enumerate the `Minimal` flag bit on every `EPROCESS` candidate and cross-reference with the registered pico provider list. The set of expected minimal-process parents is tiny (`System`, possibly `init` for WSL); any other parent producing a minimal child should be treated as Tier-1 evidence.

---

## 9. PEB, TEB, Loader, and DLL Hiding

### 9.1 PEB LDR Unlink

The classical user-mode DLL hide. The `LDR_DATA_TABLE_ENTRY` for a target DLL is removed from `InLoadOrderModuleList`, `InMemoryOrderModuleList`, `InInitializationOrderModuleList`, the LDR hash bucket, and any base-address index — depending on how thorough the operator was. `GetModuleHandle`, `EnumProcessModules`, and module-list scanners stop reporting the DLL.

The VAD is unaffected: an image-backed mapping still sits in the address space, the section object still points at the backing file, the import table and PE header are still resident. Detection is the diff between the PEB LDR set and the VAD image-map set; presence in VAD but not in LDR is `PebVadMismatch`.

### 9.2 Manual-Map DLL

The defender's nemesis at the user-mode tier. Instead of `LdrLoadDll`, the attacker hand-rolls every step the loader would have performed:

1. Allocate a private VA region of size `OptionalHeader.SizeOfImage` (usually `VirtualAllocEx` with `PAGE_READWRITE`, with per-section protection applied at the end).
2. Copy the PE header and each section's raw bytes to the section's `VirtualAddress` offset.
3. Process relocations from `IMAGE_DIRECTORY_ENTRY_BASERELOC` (typically `IMAGE_REL_BASED_DIR64` on x64) using the delta between the actual base and `OptionalHeader.ImageBase`.
4. Resolve imports via the `IMAGE_IMPORT_DESCRIPTOR` chain: either call `LoadLibrary` for each, or walk a pre-loaded module's EAT directly to fill the IAT.
5. Process TLS callbacks from `IMAGE_DIRECTORY_ENTRY_TLS`'s `AddressOfCallBacks`, invoking each as `DLL_PROCESS_ATTACH`.
6. Register exception / unwind metadata from `IMAGE_DIRECTORY_ENTRY_EXCEPTION` via `RtlAddFunctionTable` or direct inverted-function-table insertion.
7. Initialize the load-config security cookie at the address indicated by `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`.
8. Apply per-section protection (`PAGE_EXECUTE_READ` for `.text`, `PAGE_READONLY` for `.rdata`, `PAGE_READWRITE` for `.data`).
9. Call `OptionalHeader.AddressOfEntryPoint` with `DLL_PROCESS_ATTACH`.
10. Optionally zero the PE header, clean up section alignment slack, and never register a `LDR_DATA_TABLE_ENTRY`.

Because step 1 uses a private allocation (not `NtMapViewOfSection` with `SEC_IMAGE`), the `PsSetLoadImageNotifyRoutine` and ETW `KERNEL_PROCESS_IMAGE_LOAD` events never fire. The PEB LDR never receives an entry. `GetModuleHandle`, `EnumProcessModules`, and any module-list-based scanner cannot find the DLL.

Surviving evidence — none of which the attacker can fully erase if the payload actually runs:

- Private VAD with `PAGE_EXECUTE*` protection (sometimes `MEM_PRIVATE` + PE-header signatures even after header zeroing)
- Section alignment, import thunk patterns, relocation-like immediates, TLS callback patterns
- Thread start / current RIP attribution inside the region
- Region entropy and call-target density divergent from JIT/heap
- (If file-backed by a section the attacker forgot to detach) — a section object pointing at the backing file

Detection strategy:

| Technique | Implementation |
|-----------|---------------|
| VAD vs. PEB LDR diff | Compare `VadType=Image` VADs to the PEB module list |
| Private executable scan | Enumerate `PAGE_EXECUTE*` private VADs, score by size, entropy, header signatures |
| Thread-start attribution | Sample thread start addresses against the module set |
| Suspicious RX transition | Watch `RW -> RX` or `RWX -> RX` transitions; large private executable allocations |
| Erased-header recovery | Even when the PE header is zeroed, section alignment, import thunks, and exception directories are recoverable |
| Call-stack provenance | Sample game-thread call stacks; flag stacks where a return address lands in an unsigned private region |

Legitimate JIT/VM compilers — .NET CLR, V8, JVM, scripting engines, GPU shader caches — also produce private executable memory. Building an allowlist per process is unavoidable. In a focused game-anti-cheat context the allowlist is small and the false-positive surface is much narrower than for general-purpose EDR.

### 9.3 TEB / Stack Spoof

Thread start address is set to a legitimate module's `RtlUserThreadStart` or similar, but the actual execution context is hijacked once running. Combined with module stomping or manual mapping, the start address gives no provenance signal. Defense: don't look only at start address — sample current RIP and walk the call stack. A thread that "starts in kernel32" but spends 99% of its sampled time inside a private RX region is `ThreadStartOutsideImage` for practical purposes.

### 9.4 PEB / TEB Manipulation Catalog

PEB/TEB tampering is attractive to attackers because the structures are user-mode writable: no kernel write, no PatchGuard exposure, no driver footprint. They are correspondingly low-trust as evidence — the kernel's create-time record and the VAD/section/file-object identity remain authoritative. The defender's posture toward PEB/TEB is to treat them as "what the attacker currently *claims*," not as evidence of what is.

| Target | Attacker effect | Detection |
|--------|-----------------|-----------|
| `PEB.ProcessParameters.ImagePathName` | Spoof image path shown to debuggers, EDR UI, `GetModuleFileNameEx` | Create-time path / file id vs. live PEB |
| `PEB.ProcessParameters.CommandLine` | Bypass command-line rules | Process-create callback's original command line vs. live PEB |
| `PEB.ProcessParameters.CurrentDirectory.DosPath` / `Environment` | Affect downstream process spawn behavior | Snapshot at create vs. live |
| `PEB.BeingDebugged` | Anti-debug feedback to malware itself | Compare against `DebugObject`/kernel debug state |
| `PEB.NtGlobalFlag` | `FLG_HEAP_*` bits revealed in PEB; cleared to feign no-debugger | Compare against kernel `NtGlobalFlag` per build |
| `PEB.ProcessHeap->Flags` / `ForceFlags` | Heap-debug flags revealed in process heap header | Build-known default value comparison |
| `PEB.HeapTracingEnabled` / `CritSecTracingEnabled` / `LibLoaderTracingEnabled` | Tracing-state spoof | Comparison against `KUSER_SHARED_DATA` flags |
| `TEB.NtTib.ArbitraryUserPointer` | Stash hidden payload pointer in unused TEB slot | TLS / TEB slot provenance |
| `TEB.Wow64Information` | WoW64 transition state — spoofed to hide 32-bit execution under 64-bit shell | Cross-check syscall ABI used by recent thread samples |
| `KUSER_SHARED_DATA.KdDebuggerEnabled` | Live read-only state revealing kernel debugger; user-mode malware reads this | Mark threads that read it as anti-analysis candidates |
| `PEB.Ldr.InLoadOrderModuleList` | Remove DLL from load-order enumeration | VAD image map vs. PEB LDR diff |
| `PEB.Ldr.InMemoryOrderModuleList` | Same, memory-order enumeration | Module base range vs. VAD |
| `PEB.Ldr.InInitializationOrderModuleList` | Same, init-order enumeration | Image-load ledger vs. LDR |
| `ntdll!LdrpHashTable` | Defeat `GetModuleHandle`/loader lookups even when list entries are gone | PEB list set vs. hash bucket set |
| Inverted function table (`ntdll!LdrpInvertedFunctionTable`) | Erase module from exception/unwind metadata | Unwind metadata vs. VAD vs. exception directory |
| `TEB.ThreadLocalStoragePointer` / TLS slots | Hide payload pointers behind thread-local storage | TLS callback / table provenance |
| `TEB.NtTib.StackBase`/`StackLimit` | Stack pivot or fake stack frame | Sampled-RIP-and-RSP attribution outside reported stack |
| Activation context (`TEB.ActivationContextStackPointer`) | Side-by-side DLL identity confusion | File id / signature / loader-event diff |

A common practical rule: **anything reachable from PEB/TEB is "claim"; anything reachable from `EPROCESS`/`ETHREAD`/VAD/section/file object is closer to "evidence."** When the two disagree, the kernel side usually wins, with the caveat that section-object/file-object identity can itself be reimaged or ghosted (§10).

---

## 10. Stealth Process Creation

This is the family of techniques that lets a process come into existence with one identity (visible to the OS, scanners, AV) and execute another (the actual payload). Microsoft's "Using process creation properties to catch evasion techniques" (Security blog, 2022) is the foundational defender-side reference. None of these techniques have been fully closed by Microsoft as of Windows 11 24H2 / 25H2 — they remain detectable but not prevented, and rely on EDR / ETW-TI / call-stack inspection for runtime detection.

### 10.1 Process Hollowing

The progenitor (MITRE T1055.012). Standard sequence:

1. `CreateProcess` with `CREATE_SUSPENDED` on a benign image.
2. `NtUnmapViewOfSection` to remove the original image section.
3. Allocate space and write the malicious image at the original image base (or a relocated base).
4. `SetThreadContext` to set the main thread's RIP to the new entry point.
5. `ResumeThread`.

The image path in `EPROCESS.SectionObject` and in the PEB is the benign image; the in-memory code is the malicious image. The hash and entry point diverge.

Detection: create-time hash captured by the process-create callback; live main-image hash on first execution. Divergence = hollowing. The `NtUnmapViewOfSection` call against a freshly-created suspended child is itself a strong sequence indicator.

### 10.2 Process Doppelgänging

Abuses Transactional NTFS (TxF):

1. `CreateTransaction`.
2. `CreateFileTransacted` to open the target image inside the transaction.
3. Overwrite the file with malicious content via the transacted handle — invisible outside the transaction.
4. `NtCreateSection(SEC_IMAGE, hTransactedFile)` — section maps the malicious view.
5. `RollbackTransaction` — disk shows the original benign content.
6. `NtCreateProcessEx(hSection)` — process is created from the malicious section, with no on-disk evidence.

TxF is increasingly restricted in modern Windows (some operations require administrator) and deprecated — but the technique still works on Windows 11 24H2. The defining defender signal is the combination of TxF activity with `NtCreateProcessEx` in close temporal proximity.

### 10.3 Process Herpaderping

Exploits the window between section creation and the process-creation callback's view of the backing file:

1. `CreateFile` on a target path with `FILE_SHARE_WRITE` (the unusual share mode is itself a signal).
2. Write malicious payload to the file.
3. `NtCreateSection(SEC_IMAGE, hFile)` — section is bound to the file object; the memory image is the malicious payload.
4. **Write benign content over the same file handle.** The section is already created, so its memory image is unaffected, but the on-disk content now reads as benign.
5. `NtCreateProcessEx(hSection)`.
6. `PsSetCreateProcessNotifyRoutineEx` fires; if the EDR inspects `FileObject->FileName` and reads disk content, it sees the benign payload.
7. Close the file handle and resume.

Microsoft has classified this as not a security boundary issue and **has not patched it** as of Windows 11 25H2. Detection requires comparing the section's `ControlArea->FilePointer` content (the actual mapped image) against the on-disk file content at callback time, and detecting the post-section overwrite. Elastic's "Potential Process Herpaderping Attempt" rule captures the parent-overwrites-own-child sequence.

### 10.4 Process Ghosting

Exploits delete-pending file semantics — a file marked for delete still backs any open section.

1. `NtCreateFile` with `DELETE | WRITE_DATA` access.
2. Set `FileDispositionInformation` with `DeleteFile = TRUE`, or open with `FILE_DELETE_ON_CLOSE`.
3. Write the payload.
4. `NtCreateSection(SEC_IMAGE, hFile)`. The section's `ControlArea` references the file object.
5. Close the handle. NTFS removes the directory entry. The file is gone from any path-based scanner.
6. `NtCreateProcessEx(hSection)`.
7. In the create-process callback, `PsGetProcessImageFileName` returns an empty or unresolvable name.

Again, **not patched** in Windows 11 24H2 / 25H2 — Microsoft acknowledged the technique (Gabriel Landau, Elastic, 2021) but has issued partial mitigations only. Detection: `FileObject->FileName.Length == 0` or `FO_DELETE_ON_CLOSE` set at callback time, combined with section/process creation.

### 10.5 Process Reimaging

A catch-all for techniques that drift the process's claimed identity from its actual identity. Detection fields:

| Field | Compared against |
|-------|------------------|
| File ID at create | File ID at current path |
| Section ID at create | Main-image VAD's control-area section |
| Hash at create | Live main-image first-page hash |
| Signer at create | Signer of the file at the current path |
| Entry point at create | Main thread's current RIP / start address |

### 10.6 File-System-Level Payload Concealment

Beyond the section/process tricks above, NTFS offers several metadata primitives that loaders use to hide payload binaries from path-based scanners. The defender's posture is to never rely on path strings — always resolve to a file id and hash.

| Primitive | Mechanism | Hiding effect | Detection |
|-----------|-----------|---------------|-----------|
| **Alternate Data Streams (ADS)** | `file.exe:hidden.dll` — secondary stream attached to a file/directory | `dir`, most AV path scanners, Explorer all show only the unnamed stream; the payload stream is invisible | Enumerate `FILE_STREAM_INFORMATION` on every executable; treat non-empty named streams on user-writable files as suspicious |
| **Object IDs** | `FSCTL_CREATE_OR_GET_OBJECT_ID` / `FSCTL_SET_OBJECT_ID` assigns a 16-byte GUID; the file is reopenable via `OpenFileById` with a `FILE_ID_DESCRIPTOR(ObjectId)` even after the parent directory entry is renamed or removed | Path-rename / path-delete races; load by ID independent of path | Audit object-ID assignments via the file-system minifilter; flag executable files opened via `OpenFileById` from untrusted parents |
| **Reparse Points** | Junctions, symlinks, mount points (`FSCTL_SET_REPARSE_POINT`) | Make `C:\Windows\System32\foo.dll` actually resolve to a payload elsewhere | Reparse-tag enumeration; trust the final resolved file id, never the path |
| **Volume Shadow Copy** | VSS snapshot (`HarddiskVolumeShadowCopy*`) contains historic file versions | Load benign-then-malicious payload from a shadow copy that the on-disk file no longer matches | Shadow-copy enumeration; correlate file opens via `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*` paths |
| **Raw `$MFT` / `$Bitmap` read** | Bypass file-system API entirely; read clusters via `\\.\PhysicalDrive*` | No `IRP_MJ_CREATE` for the target file — minifilter scan misses it | Audit handle opens on `\Device\Harddisk*` from non-system processes; rare and high-signal |
| **DOS device / `\??\` symlinks** | Per-session symbolic link in `\??\` redirects standard path to attacker location | Cf. `\??\C:` redirection; defeats `Path.GetFullPath` |  Object-directory walk vs. boot-time baseline |

PE resource and overlay storage is a related primitive but lives inside the file rather than in the file system; it is treated separately in §11.7.

For game anti-cheat the dominant case in current ecosystems is **VSS-loaded payloads** (lets the attacker replace the on-disk file after section creation, similar to herpaderping but legitimate-looking) and **ADS-stored modules** (loader DLL drops payload to `gamefile.exe:loader.dll`). Both are defeated by file-id-first, hash-second discipline.

---

## 11. Injection and Threadless Execution

### 11.1 Remote-Thread DLL Injection

The shapes are familiar:

1. External process opens a handle to the target with `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`.
2. Allocate target memory; write payload or DLL path.
3. `CreateRemoteThread` / `NtCreateThreadEx` to invoke the payload (or `LoadLibrary` on the written path).

For game anti-cheat the ROI rules are:

| Rule | Description |
|------|-------------|
| `ExternalHandleToGame` | Untrusted external process obtains strong handle |
| `PrivateExecInGame` | Private executable region appears in game process |
| `UnsignedImageInGame` | Unsigned DLL maps into game process |
| `ThreadStartOutsideImage` | Thread starts outside any known module range |
| `DirtySignedText` | Signed module's `.text` section becomes dirty (stomping) |
| `SuspiciousParentChain` | Game process's parent chain departs from launcher/anti-cheat expectations |

### 11.2 APC / Thread Hijacking

The flavors:

| APC type | Queue API | Delivery IRQL | Delivery condition |
|----------|-----------|---------------|---------------------|
| User APC | `QueueUserAPC`, `NtQueueApcThread` | PASSIVE | Target thread in **alertable wait** |
| Special user APC | `NtQueueApcThreadEx` with `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` | PASSIVE | No alertable wait needed (Win10+ injection vector) |
| Normal kernel APC | `KeInsertQueueApc` | APC_LEVEL | Thread outside critical region |
| Special kernel APC | `KeInsertQueueApc(KernelMode, Special)` | APC_LEVEL | Delivered even inside critical region |

Attack variants by sequence:

- **Classic user APC injection** — write payload, find alertable wait, `QueueUserAPC`. Well-known signature.
- **Early-bird APC** — `CreateProcess(CREATE_SUSPENDED)`; the main thread reaches an alertable point during ntdll initialization before any user code runs; `QueueUserAPC` preempts. Strong if first APC arrives within milliseconds of process-create callback.
- **Special user APC** — the `QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC` flag on `NtQueueApcThreadEx` (Win10 19H1+) and the dedicated `NtQueueApcThreadEx2` syscall (later Win10 builds) bypass the alertable-wait requirement and force-dispatch the APC into user mode. Few legitimate consumers; high-ROI detection target.
- **Pure thread hijack** — `SuspendThread` → `GetThreadContext` → modify RIP → `SetThreadContext` → `ResumeThread`. Not directly visible in ETW; must be inferred from sampled RIP that no longer matches the start address.

### 11.3 Module Stomping and Module Overloading

Load a benign signed DLL legitimately; overwrite a portion of its `.text` with the payload. PEB/VAD report a clean image-backed module. The discrepancy is between the in-memory bytes and the on-disk bytes:

- Image-backed executable pages become copy-on-write private after the overwrite.
- The module's `.text` hash differs from the disk image's `.text` hash.
- CFG / call-target metadata and exception-directory entries don't match the rewritten code.

Detection ETW (`Microsoft-Windows-Kernel-Memory`) emits some related events; better, periodically re-hash signed modules' `.text` sections and compare against the disk image's hash.

### 11.4 Reflective DLL Injection

The Stephen Fewer (2008) classic. The DLL bootstraps itself in the remote process from a single position-independent entry point. Conceptually equivalent to manual mapping (§9.2) but with the loader logic embedded in the payload itself. Same detection surface as manual map.

### 11.5 Threadless Execution

The umbrella term for techniques that avoid `CreateRemoteThread`-shaped detection entirely. Vehicles:

- APCs (above)
- Fiber conversion
- Window hook / message callbacks
- Waitable timer callbacks
- Threadpool callbacks
- VEH / SEH handlers
- TLS callbacks
- COM / RPC callbacks
- Graphics/overlay callbacks (DirectX device-lost / `Present` callback chains, WPF `Dispatcher` hooks, OpenGL extension registrations, etc.)

CCob's **ThreadlessInject** technique (2023) is currently representative: hook an export of a remote process to gain execution when the function is called normally, with no remote-thread API ever invoked. Detection requires watching the *registration* surface — the callback / hook / VEH / handler — rather than the thread-creation surface.

### 11.6 ProcessInstrumentationCallback Abuse

`NtSetInformationProcess(ProcessInstrumentationCallback)` registers a user-mode routine that the kernel calls on *every syscall return* into the process. The mechanism predates Windows 10 (originally added for the Wow64 layer's syscall transitions) and remains undocumented in public API headers, but it is fully functional on Windows 11 24H2/25H2.

The attractive property for attackers: a single registered callback receives every syscall's return value with the original RCX/RDX preserved, allowing the callback to act as a universal post-syscall hook *without patching ntdll*. The original `ntdll!Nt*` stubs are unmodified — direct-syscall and integrity-check evasion (§7.1) bypasses are defeated, because the kernel-controlled return path runs the callback regardless of how the syscall was made.

Two real-world uses observed:

- **Userspace EDR hooking** — some endpoint products (including some Microsoft Research and academic prototypes) use it to observe every syscall in monitored processes without inline patches. It is *not* a standard EDR primitive, but it is documented in offensive-tradecraft literature as "EDR's best-kept secret."
- **Offensive use** — a payload sets its own `ProcessInstrumentationCallback` to intercept syscalls, inspect their context, and either rewrite results or invoke nested logic. Equivalent to a per-process kernel-controlled hook that survives every form of user-mode tampering detection.

Detection:

| Approach | Mechanism |
|----------|-----------|
| Kernel-side audit | At process create or on demand, read `EPROCESS.InstrumentationCallback` (offset is build-specific; PDB-resolve). Compare against an allowlist (typically empty for game processes). |
| ETW-TI subscription | `Microsoft-Windows-Threat-Intelligence` emits an event for `ProcessInstrumentationCallback` changes — but only PPL-WinTcb consumers can subscribe (anti-cheat usually cannot, §14.3). |
| Sampled-RIP anomaly | Threads whose sampled RIP lands inside a private RX region *immediately after* syscall return without explicit `call` site upstream — the instrumentation callback's signature pattern. |
| Mitigation policy | No publicly documented `PROCESS_MITIGATION_POLICY` value cleanly blocks `ProcessInstrumentationCallback` registration on current public builds. Adjacent policies (`ProcessDynamicCodePolicy`, `ProcessSignaturePolicy`) constrain related primitives. Anti-cheat-spawned subprocesses should be created with the strongest available code-integrity mitigations and have their `EPROCESS.InstrumentationCallback` field audited from kernel side as the practical control. |

This primitive deserves more attention than it typically gets. A game process whose `EPROCESS.InstrumentationCallback` is non-NULL and points outside any loaded module is a clean, high-confidence signal that rarely false-positives.

### 11.7 Resource and Overlay Payload Storage

A signed benign binary can carry an attacker payload either inside its PE sections or appended alongside the file structure on disk — in several cases without invalidating the Authenticode signature:

| Storage location | Mechanism | Why it works |
|------------------|-----------|--------------|
| `.rsrc` section | PE resource directory; embed encrypted payload as `RT_RCDATA` or custom-type resource | Resources are within the signed image extent if added pre-signing; if added post-signing the signature breaks, but unsigned droppers don't care |
| **PE overlay** | Append data to the on-disk file outside the structured PE layout | The Authenticode hash explicitly excludes the PE Checksum field, the Security Directory pointer, and the certificate table itself. Bytes appended **after** the certificate table at the very end of the file are outside the hashed range and do not invalidate the signature. Bytes added between the last section and the cert table *are* hashed and would invalidate signing. |
| Authenticode signature blob padding | Append bytes inside `WIN_CERTIFICATE` structure padding | Some PE-checking code mis-handles cert-blob length and treats trailing bytes as part of the cert |
| Manifest / version info string fields | Embed base64 payload in `FileDescription`, `CompanyName`, etc. | Visible in `sigcheck` output but invisible to most automated scanners |
| Resource directory leaf string IDs | Encode payload bytes as `LANGUAGE`/`STRING` IDs | Easy to overlook in resource trees |

The dominant 2024–2026 pattern is **encrypted Cobalt Strike / Sliver / Brute Ratel shellcode embedded as a custom `.rsrc` entry of a legitimately-signed third-party binary** — historically seen in NVIDIA `nvSCPAPISvr.exe` lineage, Microsoft `MpCmdRun.exe` derivatives, AnyDesk/TeamViewer service binaries, and various antivirus updater modules. The loader is a thin reflective DLL that decrypts the resource at runtime.

Detection:

- Compare PE `SizeOfImage`, `SizeOfHeaders`, and on-disk size — any overlay bytes are suspect when the producer isn't known to use overlay payloads (some installers legitimately do; build an allowlist).
- Enumerate `.rsrc` directory entries; treat custom-type or unusually large entries on signed binaries as high score.
- Compare a signed binary's published catalog hash against the on-disk file's content; mismatch in the overlay region is evidence of post-signing append.
- Hash the resource directory's payload entries; cross-reference against a known-good catalog of Microsoft-signed binaries.

### 11.8 IFEO Debugger, AppInit_DLLs, and Application Compatibility Shims

A category that blurs the line between hiding, persistence, and execution. All three give an attacker code execution inside a target process at startup with no `CreateRemoteThread`-shaped events:

- **Image File Execution Options (IFEO) `Debugger`** — `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>.exe\Debugger` redirects target launches through an attacker binary. Subkey `GlobalFlag` can also enable creation-time flags like `FLG_APPLICATION_VERIFIER`.
- **`AppInit_DLLs`** — `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` injects listed DLLs into every process loading `user32.dll`. Microsoft heavily restricted this in Windows 8+ (disabled by default with Secure Boot; further restricted by SmartScreen) but it can be re-enabled.
- **`AppCertDlls`** — `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` — DLLs loaded by any process that calls `CreateProcess*`.
- **Application Compatibility Shim (`.sdb`)** — shim database via `sdbinst.exe`; can attach `InjectDll` or `RedirectShortcutToShim` shim flags to a target.

For an anti-cheat focused on game-process protection, the relevant rules:

| Rule | Description |
|------|-------------|
| IFEO `Debugger` set on game executable | Hard block — there is no benign reason for this on a consumer machine |
| `AppInit_DLLs` non-empty | Audit; rare on modern Windows but legacy software still uses it |
| `AppCertDlls` non-empty | Same |
| Shim attached to game image (`SHIM` registry hive) | Audit; some legitimate compatibility shims exist but rare for current AAA titles |

### 11.9 LSA Authentication / Security / Notification Packages (PPL Code Loading)

The Local Security Authority Subsystem (`lsass.exe`) reads three registry values at boot and loads every DLL listed in each:

| Registry value | Effect |
|----------------|--------|
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages` | DLLs that implement `LsaApLogonUser` and friends; loaded for credential validation |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` | DLLs that receive password-change notifications via `PasswordFilter` exports |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` | DLLs that register Security Support Providers (SSPs) for SSPI. (`Lsa\OSConfig\Security Packages` exists as a FIPS-configuration subset and is not the persistence vector — LSA loads from the canonical `Security Packages` value.) |

Because `lsass.exe` runs as Protected Process Light at signer level `WinTcb` (on credential-guard-on systems) or `Windows` (off), a DLL loaded through any of these paths inherits PPL execution context. This is the mechanism behind Mimikatz `memssp`, `SecLogon` injection, and several APT credential-theft toolkits (notably late-2024 Bumblebee variants).

The technique is doubly attractive for hiding:

- **Code runs inside `lsass.exe`** — which by default cannot be opened with `PROCESS_VM_READ` by ordinary processes, so the injected code is shielded from external inspection.
- **Persistence and execution combined** — `lsass.exe` restarts only at reboot, so the entry is a one-write, lasts-forever installation.

| Detection | Mechanism |
|-----------|-----------|
| Registry-callback audit | Monitor writes to `Lsa\Authentication Packages`, `Notification Packages`, `Security Packages` via `CmRegisterCallbackEx` |
| Boot-time baseline | Snapshot each list at first-trusted boot; flag any addition |
| DLL provenance | Each entry must resolve to a Microsoft-signed binary in `System32`; user-writable paths or unsigned DLLs are immediate evidence |
| `lsass.exe` loaded-module audit | Cross-reference `lsass`'s actual loaded modules against the registry-driven expectation set |

For game anti-cheat the LSA paths are rarely directly exploited against game memory (LSASS isn't where game state lives), but they appear in the threat model because:

- A compromised `lsass.exe` can issue authentication tickets that lower the anti-cheat's trust posture.
- The same registry primitive class is generalizable — `Lsa\Notification Packages` is just the most famous of dozens of "load DLL into trusted process" registry values Windows still honors.

### 11.10 Print Spooler Extension Points

The Print Spooler service (`spoolsv.exe`) loads DLLs through three plug-in interfaces:

| Extension | Registration | Hosting process |
|-----------|--------------|------------------|
| **Print Provider** | `AddPrintProvider` API or `HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers` | `spoolsv.exe` directly |
| **Print Monitor** | `AddMonitor` API or `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors` | `spoolsv.exe` directly |
| **Print Processor** | `AddPrintProcessor` API or `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors` | `spoolsv.exe` directly |

`spoolsv.exe` runs as `SYSTEM` and (historically) with permissive impersonation. The PrintNightmare family (CVE-2021-1675, CVE-2021-34527, and the ~12 follow-on CVEs through 2024) abused exactly this DLL-load surface; Microsoft patched some entry points but the registry-driven Print Provider / Monitor / Processor primitives remain live and exploitable when the attacker has admin or specific service permissions.

For ransomware crews the Print Spooler is second only to LSASS as a "load DLL into a trusted SYSTEM service" target. For anti-cheat: a non-Microsoft Print Provider or Monitor on a consumer gaming endpoint is essentially never legitimate.

Detection: registry baseline at install time; ETW provider `Microsoft-Windows-PrintService` emits driver-add events; `Get-PrintProcessor`, `Get-Printer`, and the equivalent native APIs enumerate the live state. Cross-reference each provider/monitor DLL against the Microsoft signer expectation.

### 11.11 COM Hijacking

Component Object Model (COM) class registration is keyed by GUID:

```
HKEY_CLASSES_ROOT\CLSID\{GUID}\InProcServer32      (default) = path to DLL
HKEY_CLASSES_ROOT\CLSID\{GUID}\LocalServer32       (default) = path to EXE
```

When any process calls `CoCreateInstance(CLSID_X)`, the loader resolves the implementing module from this registry path. Critically, `HKEY_CLASSES_ROOT` is a *merge view* over `HKLM\Software\Classes` and `HKCU\Software\Classes`, with **HKCU taking precedence**. Any user-mode code (no admin needed) can write to its own `HKCU\Software\Classes\CLSID\{GUID}` and redirect every subsequent `CoCreateInstance` of that CLSID to attacker-controlled DLL.

Targets that real malware exploits:

- CLSIDs loaded by Explorer at startup (shell extensions, namespace handlers).
- CLSIDs loaded by Office on document open.
- CLSIDs loaded by AppX framework on every modern app start.
- CLSIDs loaded by `taskhostw.exe` for scheduled-task COM hosts.

The technique is exceptionally common in commodity malware because it provides both persistence and stealthy execution inside trusted parent processes without `CreateRemoteThread`.

Detection:

- Registry-callback monitoring of `HKCU\Software\Classes\CLSID` writes — additions to keys already present in HKLM are the canonical pattern (HKCU "wins" via search-order precedence).
- DLL provenance audit when any trusted process loads a CLSID-resolved DLL from a user-writable path.
- Periodic scan of HKCU's CLSID subtree for known-Microsoft-CLSID redirections to unexpected paths.
- Sysmon Event ID 7 (Image Loaded) cross-referenced with the loading process's COM activity.

### 11.12 DLL Search Order Hijacking, Sideloading, and Proxying

Three related primitives that exploit how Windows resolves DLL names:

**Search-order hijacking.** Windows DLL search order (with `SafeDllSearchMode` on — the default since Windows XP SP2) places the application directory ahead of `System32` for any DLL name not in the KnownDLLs object directory. An attacker who can write to a target's installation folder (sometimes user-writable, e.g., `%LOCALAPPDATA%\Programs\<app>`) drops a DLL with the same name as a system DLL the app loads. The app's loader finds the attacker DLL first.

**DLL sideloading.** A specialization: attacker drops a signed (legitimate) loader binary plus a malicious DLL with the name of a dependency the loader resolves at runtime. The signed binary is fully trustworthy from a signature standpoint; the malicious DLL rides in. Cobalt Strike has been distributed this way for years using NVIDIA, Citrix, and antivirus updater binaries as sideload hosts.

**DLL proxying.** The malicious DLL exports the same surface as the legitimate target DLL — every export is implemented as a forwarder (`#pragma comment(linker, "/export:Foo=original.Foo")`) or a tail-jump to the original loaded at a renamed path. The host application's calls into the proxy transparently reach the original implementation; the attacker gets `DllMain` execution and can intercept any export. This is the dominant 2024–2026 pattern because it preserves application functionality, evading user-visible breakage that would prompt investigation. Tools like **Spartacus** (Pavel Tsakalidis) and **Spoofify** automate proxy generation from a target DLL's export table.

Detection:

| Technique | Implementation |
|-----------|---------------|
| Image-load callback path audit | A legitimate Microsoft DLL loading from a non-Microsoft directory is the strongest single signal |
| Loader-search-order policy | Set `SafeDllSearchMode` and use `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` in your own processes |
| Export-table fingerprint diff | A DLL with a Microsoft-typical name but an unusual export forwarder pattern (every export forwards to a same-named DLL with a `_orig` suffix) is a clean proxy fingerprint |
| Signed-but-untrusted-path | Even a signed DLL loading from a user-writable path is high suspicion (the signer may be legitimate while the binary itself is a victim of supply-chain) |
| KnownDLLs check | A DLL name that is in `\KnownDlls` should *never* load from anywhere other than the kernel-mapped section — if it does, it's a hijack |

### 11.13 `LdrRegisterDllNotification` Callback Abuse

`ntdll!LdrRegisterDllNotification` is a documented user-mode API that registers a callback to be invoked on every DLL load and unload event in the calling process. The callback runs synchronously inside `LdrpLoadDll`'s critical section.

Legitimate consumers: EDR products, debuggers, application verifiers, and Microsoft's own application-compatibility shims. Almost no game or normal application uses it.

Offensive uses:

- **Stealth execution vehicle** — register the callback, then trigger any DLL load (even a benign one) → callback fires inside the legitimate process's loader. The attacker has gained execution with no `CreateRemoteThread`, no APC, no thread context manipulation.
- **In-process EDR-blinding** — the callback can patch out subsequent loads (e.g., replace just-loaded EDR-injected DLLs with stubs) before the new module returns control to the loader.

Detection:

- `LdrpDllNotificationList` is the kernel-resident list; walk it from kernel side and attribute each callback target to a loaded module. An entry whose target is private executable memory or an unexpected DLL is suspicious.
- ETW image-load events fire *after* the callback in the loader-lock window; observe the order to detect callbacks that arrive too early.
- Game-process baseline: in a clean run, count the registered callbacks at startup. Any addition mid-life is anomalous.

### 11.14 Comprehensive Injection Catalog

| Technique | Mechanism | Observation point |
|-----------|-----------|-------------------|
| Classic DLL injection | Remote `LoadLibrary` after `WriteProcessMemory` | Handle, remote write, image load |
| Reflective DLL injection | Self-bootstrapping DLL | Private RX, PE-like region, no image load |
| Manual map injection | Custom loader | VAD private exec, erased header, thread provenance |
| APC injection | Alertable thread + `QueueUserAPC` | APC queue, target state, private RX |
| Early-bird APC | APC during initial ntdll init | First-APC timing after process-create |
| Special user APC | `NtQueueApcThreadEx2` | Syscall + private RX |
| Thread hijacking | `SetThreadContext` | Sampled-RIP outside image |
| Threadless execution | Callback / hook / VEH | Callback registration + private RX |
| Module stomping | Patch signed DLL `.text` | Dirty signed image, hash diff |
| Module overloading | Substitute content for legitimate DLL path | File id / hash / signer mismatch |
| Process hollowing | `CreateProcess(SUSPENDED)` + remap | Main image hash diff, entry point diff |
| Transacted hollowing | TxF + section combination | Transaction + section lineage |
| Doppelganging | Rolled-back transacted section | TxF + create properties |
| Herpaderping | Post-section file overwrite | Process start + overwrite |
| Ghosting | Delete-pending section | Missing backing path |
| ProcessInstrumentationCallback | Kernel-invoked post-syscall hook in user mode | `EPROCESS.InstrumentationCallback` non-NULL, target outside any module |
| Resource/overlay payload | Encrypted payload in `.rsrc` or post-cert overlay of a signed binary | Resource-entry / overlay anomaly on signed image |
| IFEO Debugger | `Image File Execution Options\<exe>\Debugger` redirect | IFEO subkey present for the target |
| AppInit_DLLs / AppCertDlls | Global DLL injection via session-manager values | Non-empty registry value |
| LSA Authentication / Notification / Security Packages | DLL loaded into PPL `lsass.exe` via Lsa registry | Registry write to Lsa packages, non-Microsoft DLL provenance |
| Print Spooler extension | Print Provider / Monitor / Processor loaded into `spoolsv.exe` | Registry entry under `Control\Print\*`, non-Microsoft signer |
| COM Hijack | `HKCU\Software\Classes\CLSID\{guid}\InProcServer32` redirect | HKCU CLSID write shadowing HKLM CLSID |
| DLL search order / sideload | Same-named DLL in app directory ahead of `System32` | Microsoft-named DLL loaded from non-system path |
| DLL proxying | Wrapper DLL forwards exports through malicious shim | Export-forwarder pattern to `_orig`-suffixed twin |
| `LdrRegisterDllNotification` abuse | User-mode loader-event callback | `LdrpDllNotificationList` entry outside known modules |
| Game-specific injection framework | ReShade / BepInEx / overlay / mod loader | Framework signer + per-title allowlist |
| Graphics-stack hook | D3D / DXGI / Vulkan vtable rewrite | vtable integrity diff, frame-time anomaly |
| Window hook injection | `SetWindowsHookEx` / `SetWinEventHook` / IME | Registered hook inventory, post-create module deltas |
| Misc trusted-process registry surface | W32Time / NetSh / DCOM Surrogate / Search filter etc. | Generalized registry-driven load-list audit |
| WMI permanent event subscription | `__EventFilter` + `__EventConsumer` | WMI subscription enumeration / Sysmon 19-21 |

Defender posture: hooks on every API in the sequence catch low-tier attackers; advanced attackers will bypass any specific API path with direct syscalls. The durable answer is to combine **final memory state** observation (the VAD/PTE/thread-RIP cross-view) with **API sequence** observation. The former survives bypasses the latter does not.

### 11.15 Game-Specific Injection Frameworks

Game-anti-cheat detection is materially different from general EDR because the threat model includes *legitimate-looking* injection frameworks whose mechanics are essentially identical to cheats. The defender's job is to allowlist by signer + behavior rather than block the mechanism.

| Framework | Mechanism | Legitimate use | Cheat use |
|-----------|-----------|----------------|-----------|
| **ReShade** | `dxgi.dll` / `d3d11.dll` proxy DLL in game directory; intercepts D3D calls to inject post-processing shaders | Color grading, sharpening, custom shaders | ESP / wallhack disguised as shader effect; CRT scanline overlay hiding actual cheat draw calls |
| **BepInEx** | Mono/IL2CPP runtime injector for Unity games; loads managed assemblies via patched runtime | Modding Unity titles | Trainer / aimbot for Unity-based anti-cheat-protected games |
| **MelonLoader** | Similar to BepInEx, broader IL2CPP support | Modding Unity / IL2CPP titles | Same vector |
| **Discord overlay** | `DiscordHook64.dll` / overlay-host DLL injected via game-registration mechanism (exact filename varies across Discord builds) | Voice / message overlay | Cheat injects via shared overlay attach path |
| **Steam overlay** | `gameoverlayrenderer64.dll` injected by Steam client | Achievements, browser, friends | Cheat masquerades as overlay extension |
| **RTSS (RivaTuner Statistics Server)** | Standalone overlay product by Unwinder, bundled with MSI Afterburner and many GPU vendor utilities | FPS counter, stats display, framerate limiter | `RTSSHooks64.dll` injection pattern abused for cheat overlay |
| **Unreal/Source console** | Engine-internal command interface | Debug / modding | Trainer functionality via developer-mode commands |

These frameworks present three detection challenges:

1. **Signer trust paradox** — ReShade, BepInEx, etc. are signed by their authors (or unsigned but reputable). A pure signature check passes them, but the in-process behavior is indistinguishable from a custom cheat.
2. **D3D vtable rewriting is universal** — every overlay framework rewrites D3D vtable entries. A naive "detect D3D vtable patching" rule has 100% false-positive rate against Discord overlay alone.
3. **Mod scene legitimacy** — single-player Unity titles support BepInEx as a mod platform; the same framework dropped into a competitive multiplayer game is a cheat. Mode-aware detection is required.

Anti-cheat posture:

- Maintain an **explicit per-title allowlist** of frameworks permitted to inject. Vanguard's documented behavior is to block ReShade, BepInEx, and most overlays during Valorant matches; outside of matches the same frameworks are tolerated.
- Cross-reference framework signer + injected-DLL hash against a curated allowlist updated server-side.
- Treat the *unsigned* variant of any of these frameworks as immediate Tier-1 evidence — the cheat-scene custom builds of ReShade or BepInEx are the actual cheat carriers.
- Distinguish "framework loaded before game start" (typical for legitimate use) from "framework injected mid-match" (cheat pattern).

### 11.16 Graphics-Stack Hooking (D3D / DXGI / Vulkan)

The dominant ESP / wallhack mechanism. Cheat author obtains a pointer to the game's `IDXGISwapChain` / `ID3D11DeviceContext` / `VkQueue` (typically by hooking `D3D11CreateDeviceAndSwapChain` or `vkCreateInstance` at game startup), then rewrites entries in the COM vtable or Vulkan dispatch table:

| Target | Hook effect |
|--------|-------------|
| `IDXGISwapChain::Present` | Runs once per frame after the game's draw list completes; perfect spot to draw ESP overlays |
| `ID3D11DeviceContext::Draw*` / `DrawIndexed*` / `DrawInstanced*` | Per-draw-call inspection — read vertex/index buffers to identify enemies, modify draw state to make walls transparent |
| `ID3D11DeviceContext::OMSetRenderTargets` | Intercept render target binding to capture intermediate frames |
| `ID3D11Device::CreatePixelShader` / `CreateVertexShader` | Replace shaders with cheat-friendly variants (no-fog, no-occlusion) |
| `ID3D12CommandQueue::ExecuteCommandLists` | D3D12 equivalent — every submission visible |
| `vkQueueSubmit` / `vkCmdDraw*` | Vulkan equivalents |
| `glXSwapBuffers` / `wglSwapBuffers` | OpenGL (legacy, but still relevant for some Source Engine games) |

Detection (anti-cheat side):

- **vtable integrity check** — read the game's D3D / DXGI vtables, compare against expected pointers from a freshly-loaded module. Off-target entries are hooks. Caveat: legitimate overlays do this too, so allowlist required.
- **Frame-time anomaly** — `Present` hooks add per-frame overhead; sustained `Present` latency outliers correlated with overlay-style draws. Caveat: games have substantial natural frame-time variance from GC, asset streaming, network jitter, etc., so this signal is noisy and must be combined with vtable / shader-audit evidence to avoid false positives.
- **Shader source audit** — the game knows its expected shader catalog; an unexpected pixel shader bound at runtime is suspicious.
- **Render-target inspection** — a captured render-target write to a surface the game didn't create is an overlay signature.
- **PIX / RenderDoc-shaped capture activity** — these debug tools also hook D3D, so allowlist their signers.

For game engineers: D3D vtable protection via `VirtualProtect(PAGE_EXECUTE_READ)` on the vtable's containing page is a partial defense — the attacker can flip it back, but the operation is observable.

### 11.17 Window Hook and Message Callback Injection

`SetWindowsHookEx` and its cousins are documented mechanisms that load DLLs into other processes:

| API | Hook type | DLL load into |
|-----|-----------|---------------|
| `SetWindowsHookEx(WH_GETMESSAGE, ...)` | Global message hook | Every process processing window messages |
| `SetWindowsHookEx(WH_CALLWNDPROC, ...)` | Window-procedure hook | Same |
| `SetWindowsHookEx(WH_KEYBOARD, ...)` | Keyboard event hook | Same |
| `SetWinEventHook(EVENT_*, ...)` | Accessibility event hook | Process that receives accessibility events |
| IME hijack via `ImmInstallIMEW` / registry `HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\<klid>\IME File` | Input Method Editor DLL | Every process loading the IME |
| `RegisterShellHookWindow` + `WH_SHELL` | Shell hook | `explorer.exe` and other shell-message consumers |

The classical-but-still-effective technique: register a global `WH_GETMESSAGE` hook whose hook DLL is dropped in `System32` (or a path on the system DLL search path). Any process that pumps a message loop loads the DLL. For game targeting: a `WH_GETMESSAGE` global hook installed seconds before the game launches, where the hook DLL is unsigned or in a user-writable path, is a clean signal.

Detection:

- Enumerate registered hooks per desktop from kernel side by walking the desktop-info hook array (`tagDESKTOPINFO->aphkStart[]` and `aphkEnd[]` on win32k internals; build-specific, PDB-resolve). No documented user-mode API enumerates this; commercial detectors invoke private win32k routines or read the array directly via kernel attach.
- ETW providers `Microsoft-Windows-Win32k` and `Microsoft-Windows-Win32k-Filter` may emit hook-related events on supporting builds; coverage varies and should be empirically verified per Windows version.
- Game-process baseline: snapshot the loaded modules list at process create; any DLL that loads in response to a window message after `WM_USER` traffic begins is a hook candidate.
- Allowlist legitimate accessibility tooling (screen readers, magnifiers, dictation) so as not to false-positive on disabled users' setups.

### 11.18 Miscellaneous Trusted-Process DLL Load Surfaces

Beyond LSA (§11.9), Print Spooler (§11.10), COM (§11.11), and IFEO/AppInit (§11.8), Windows has *dozens* of registry-driven entry points that inject a DLL into a trusted host process. None individually deserves a long writeup, but defenders should enumerate them as a class:

| Registry path | Hosting process | Use |
|---------------|-----------------|-----|
| `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\*` | `svchost.exe` (Win Time) | Time-source plugin DLL |
| `HKLM\Software\Microsoft\NetSh\*` | `netsh.exe` | NetSh helper DLL |
| `HKLM\System\CurrentControlSet\Services\EventLog\<log>\Sources\<src>\EventMessageFile` | `EventLog` service | Message-format DLL |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*` (task action `ComHandler`) | `taskeng.exe` / `taskhostw.exe` | COM-host scheduled task |
| `HKLM\Software\Classes\Wow6432Node\CLSID\{guid}\InProcServer32` | Any 32-bit COM caller | 32-bit COM hijack (parallel to §11.11) |
| `HKLM\System\CurrentControlSet\Control\Print\Environments\<env>\Drivers\Version-3\<driver>` | Print drivers | Vendor printer driver DLL |
| `HKLM\System\CurrentControlSet\Services\WSearch` related providers | `SearchProtocolHost.exe` | Search filter / handler |
| DCOM **Surrogate Process** (`DllSurrogate` value on AppID) | `dllhost.exe` per AppID | Out-of-proc COM hosted in surrogate |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved` | `explorer.exe` | Shell extension DLL |

The pattern across all of these is identical: registry callback monitoring + DLL provenance auditing on the hosting process. The defender doesn't need bespoke logic per entry — just a generalized "trusted-process load-list" approach with a per-surface allowlist.

### 11.19 WMI Permanent Event Subscriptions

WMI provides a fileless persistence + execution primitive that real-world attackers use heavily (Stuxnet popularized it; modern ransomware uses it routinely):

```
__EventFilter            (WQL query — what to watch for)
__EventConsumer          (what to do)
  ├ CommandLineEventConsumer  → spawn an EXE with given command line
  ├ ActiveScriptEventConsumer → execute VBS / JScript inline
  ├ SMTPEventConsumer         → email
  └ LogFileEventConsumer      → write to file
__FilterToConsumerBinding (links Filter ↔ Consumer)
```

The triple is stored in the WMI repository (`C:\Windows\System32\wbem\Repository\OBJECTS.DATA`). On the trigger (process create, time interval, registry change, etc.), `WmiPrvSE.exe` executes the consumer payload — no scheduled task, no service, no `Run` key.

For game anti-cheat the WMI subscription pattern is rarely the direct cheat-load mechanism (cheats want to be inside the game process, not in `WmiPrvSE.exe`), but it shows up as:

- **Cheat loader installer** — set up a permanent subscription that re-installs the cheat client whenever the game launches.
- **EDR-shutdown payload** — fire on process-creation events to kill anti-cheat-related processes.
- **Lateral persistence** — survives game uninstall, anti-cheat updates, and most cleanup tools.

Detection: enumerate `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` instances via WMI; baseline at install time; flag additions. Microsoft Sysmon Event IDs 19, 20, 21 cover WMI subscription create/modify/delete and are the standard EDR signal. Anti-cheat drivers can also subscribe to the same WMI events through kernel-side WMI consumer registration.

---

## 12. VAD, PTE, Section, and CR3 Deception

The memory-manager surfaces are stronger sources than the PEB precisely because the memory manager won't tolerate inconsistency — the system corrupts and crashes if the underlying invariants break. The price the defender pays for this strength is build-fragility and the need for careful, lock-aware walks.

### 12.1 VAD Snapshotting

Per process, snapshot:

- All executable VADs (`VadType` ∈ `image`, `private`, `mapped`)
- Backing file id / path / hash
- VAD-claimed protection
- Threads whose start or sampled RIP lands inside

Key diffs:

| Comparison | Implication |
|------------|-------------|
| VAD image map present, PEB LDR entry missing | PEB LDR unlink |
| Private executable VAD | Manual map / shellcode / JIT |
| Main image VAD hash != create-time hash | Hollowing / stomping / herpaderping |
| No image load event, VAD image map exists | Callback gap or manual section map |
| Thread RIP doesn't land inside any VAD | VAD unlink or PTE-level deception |

Operational note: VAD walks must run at `PASSIVE_LEVEL` while attached to the target process; locking and use of `MmAccessFault`-safe accessors is mandatory to avoid race-induced bugchecks.

### 12.2 VAD Unlink and Protection Spoofing

Attacker techniques against VAD-based scanners:

- Unlink a private executable VAD from the tree.
- Mark the VAD as non-executable (RO) while leaf PTEs remain executable.
- Confuse `VadType` between `image` / `private` to break scanner heuristics.
- Tamper with page tables directly to defeat any `VirtualQuery`-shaped probe.
- Under a hypervisor: serve a clean view to the anti-cheat reader and an executable view to the CPU.

Defender resources are richer than the attacker's:

| Cross-view | Description |
|------------|-------------|
| VAD vs. PTE | VAD-claimed protection vs. leaf-PTE NX/W bits |
| VAD vs. working set | Executable pages present, no VAD covering them |
| VAD vs. sampled RIP | RIP lands at an address with no VAD |
| VAD vs. thread start | Start address has no VAD or non-exec VAD |
| VAD vs. ETW image load | Image-backed VAD with no `PsSetLoadImageNotifyRoutine` event |
| Guest PTE vs. EPT timing | Different read vs. execute timing under a malicious hypervisor |

### 12.3 PTE Spoofing

Directly modifying leaf-PTE NX/W/U/S bits is feasible from kernel mode and defeats `VirtualQuery` and VAD-based scanners that don't walk page tables. Detection means walking the page tables yourself for any address of interest — the cost being significant (and the build-fragility considerable, since walk discipline must respect PAE / 4-level / 5-level paging, large/huge pages, and the recursive self-map idiom modern Windows builds use).

### 12.4 CR3 / `DirectoryTableBase` Abuse

The most exotic option: a kernel-mode payload alters `KPROCESS.DirectoryTableBase` and stages a separate page-table hierarchy. Probes that attach to the process and read its `DirectoryTableBase` see a "decoy" view; the actual execution uses a different CR3 loaded at context-switch time. Detecting this requires sampling CR3 at NMI time and comparing against `EPROCESS.Pcb.DirectoryTableBase`. The technique is rare in commodity tooling but is documented in academic anti-cheat literature.

Caveats: CR3-sampling detectors must coexist with HVCI, VBS, and Hyper-V; their CR3 semantics in guest mode are not identical to bare metal. Treat as a Phase 5 advanced capability rather than a Phase 1 must-have.

### 12.5 Working Set Manipulation and Dump Evasion

Memory acquisition — full-process minidumps, `MiniDumpWriteDump`, `LiveKD`, kernel crash dumps, forensic tools like `DumpIt` or WinPmem — is the defender's most powerful evidence-collection mechanism. A sufficiently motivated attacker can manipulate the process's working set and page-protection state to ensure the payload pages are either evicted, marked inaccessible, or actively rewritten just before the dump completes.

Techniques:

| Technique | Mechanism | Effect |
|-----------|-----------|--------|
| `VirtualProtect(PAGE_NOACCESS)` | Mark payload pages as no-access right before suspecting a dump is imminent | `MiniDumpWriteDump`'s default flags skip non-accessible pages |
| `VirtualUnlock` + working-set trim | `SetProcessWorkingSetSizeEx(-1, -1)` forces pages out to the page file | Standard dump doesn't include paged-out content unless `MiniDumpWithFullMemory` is set |
| `NtSetInformationProcess(ProcessWorkingSetWatch)` | Subscribe to working-set changes — detect when an external tool starts touching pages | Trigger evidence cleanup race |
| Memory compression | Windows 10+ compressed working set; payload bytes in compressed form aren't directly readable from a minimal dump | Bypasses naïve byte-pattern dump scans |
| Re-encryption on-the-fly | Decrypt payload, execute, re-encrypt within a few milliseconds | Snapshot at random time captures only encrypted state |
| AWE (Address Windowing Extensions) | Map/unmap physical pages from a user-mode window | Pages physically present but not in any committed VA at the moment of dump |
| `NtSetInformationVirtualMemory(VmPrefetchInformation)` poisoning | Inject decoy patterns into prefetch | Confuses pattern-based reconstruction |

Detection has to be live, not post-mortem:

- KPRCB-sampled RIPs are taken without the target's cooperation; cumulative session sampling defeats just-in-time re-encryption.
- ETW `Microsoft-Windows-Kernel-Memory` emits `PageAccess` / `PageRelease` events that can correlate with suspect protection changes.
- Anti-cheat should snapshot suspicious VAD regions on detection, *before* the attacker has a chance to apply `PAGE_NOACCESS`.
- Don't rely on `MmCopyVirtualMemory(KernelMode)` to bypass `PAGE_NOACCESS` — the previous-mode argument only relaxes accessor-mode validation, not the underlying MMU protection (the read still faults). To actually read pages the target has marked `PAGE_NOACCESS`, the detector has to either (a) walk the page tables, locate the PFN, and map it via `MmMapIoSpace`/`MmGetPhysicalAddress` mechanics, or (b) temporarily restore protection through `NtProtectVirtualMemory` (which is visible to the attacker and to ETW). Option (a) is the cleaner kernel-side primitive but is build-fragile and IRQL-sensitive.

A related primitive is **`ProcessReflection`** (`PssCaptureSnapshot` / `RtlCreateProcessReflection` / `NtCreateProcessEx` with `PROCESS_CREATE_FLAGS_CREATE_SESSION`). It snapshots the target's address space into a new minimal process that mirrors the VA; the resulting reflection can be examined without freezing the target. Attackers occasionally use it inversely — reflecting their own process to a snapshot, freeing original payload pages, leaving the snapshot as the only memory copy and using `NtClose` race to evict it before dumping. Detection: a non-EDR, non-debugger process creating a reflection of a sibling untrusted process is high-signal.

### 12.6 Process Mitigation Policy Weakening

A subtler in-process technique: instead of *hiding* code, the attacker *weakens* the mitigations that would have detected or constrained it. Each policy is reachable via `SetProcessMitigationPolicy` (own process) or `NtSetInformationProcess(ProcessMitigationPolicy*)` (with sufficient handle rights):

| Policy | Effect when weakened |
|--------|----------------------|
| `ProcessDynamicCodePolicy` | Re-enables dynamic code generation (`VirtualAlloc(PAGE_EXECUTE_READWRITE)` works again) |
| `ProcessControlFlowGuardPolicy` | Suppresses CFG indirect-call validation, enabling arbitrary indirect jumps |
| `ProcessSignaturePolicy` (MicrosoftSigned / StoreSigned / mitigation opt-out) | Allows loading non-Microsoft-signed binaries into the process |
| `ProcessImageLoadPolicy` | Allows image loads from remote shares or low-mandatory-label paths |
| `ProcessStrictHandleCheckPolicy` | Disables strict-handle-check (which would otherwise terminate on invalid handle use) |
| `ProcessChildProcessPolicy` | Allows the process to spawn children even when launched under `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` |
| `ProcessUserShadowStackPolicy` | Disables CET hardware shadow-stack enforcement |

Note: many of these policies are documented as *opt-in tightening* — once tightened, Windows enforces them for the process lifetime and the process cannot self-loosen. But the **initial process-creation** stage allows the creator to specify any policy combination, and **kernel-mode writes** can rewrite the per-process policy bits at any time.

For game anti-cheat, the rule is: snapshot the game process's mitigation-policy bitmap at create time and verify it matches the launcher's intent. Any mid-life weakening of `ProcessDynamicCodePolicy`, `ProcessSignaturePolicy`, or `ProcessUserShadowStackPolicy` is essentially always anomalous and is a high-confidence signal of in-process tampering.

---

## 13. Kernel Hooks

### 13.1 SSDT

The System Service Descriptor Table (`nt!KeServiceDescriptorTable` and its `Shadow` variant for win32k) maps syscall numbers to routine pointers. SSDT hooking — patching an entry to redirect to a filter routine — used to be the rootkit author's bread and butter.

On x64 Windows the table format is 32-bit signed-displacement encoding off `KiServiceTable`, and PatchGuard explicitly covers it. A naive SSDT hook today produces `BUGCHECK 0x109 CRITICAL_STRUCTURE_CORRUPTION`. The interval between tamper and bugcheck is governed by randomized timer-DPC checks, scheduler-tick checks, and various interrupt-side validations — most practical observations sit between a few seconds and a few minutes, with no fixed "10-minute clock." (The "PatchGuard runs every 10 minutes" claim is folklore.)

SSDT hooking still appears in two contexts: DSE-bypass / bootkit configurations where PatchGuard has been disabled at boot, and proof-of-concept code that knowingly accepts the bugcheck. As a defender, the rare event you actually need to handle is the bootkit/DSE-bypass case; from a clean boot, an SSDT hook is mostly a "wait briefly and watch the system crash" affair.

### 13.2 Inline Kernel Hooks

Patch the prologue of an exported (or internal) kernel routine to redirect through a trampoline. Common targets: `NtOpenProcess`, `NtReadVirtualMemory`, `PsLookupProcessByProcessId`, `ObOpenObjectByPointer`, callback dispatchers, and EDR/anti-cheat driver dispatch routines.

Detection mechanisms:

| Mechanism | Notes |
|-----------|-------|
| `.text` hashing | Hash loaded modules' executable sections; compare against disk/symbol baseline |
| Control-flow validation | Branch target leaves owning module's range |
| Hotpatch-aware diff | Don't false-positive on Microsoft hotpatch regions |
| HVCI/KDP state | Live policy vs. claimed posture |
| Call-stack provenance | Kernel-mode call stack frame in unknown executable pool |

On HVCI-protected systems, `.text` patches in protected modules raise SLAT exceptions before they take effect — converting many would-be hooks into bugchecks instead.

### 13.3 IDT / GDT / MSR / Debug Registers

The deepest tier. Targets on x64.

**Syscall-path MSRs**:

| MSR | Number | Role |
|-----|--------|------|
| `IA32_STAR` | `0xC0000081` | Syscall/sysret CS/SS bases |
| `IA32_LSTAR` | `0xC0000082` | 64-bit syscall entry RIP (`KiSystemCall64`, or `KiSystemCall64Shadow` under KVA shadow) |
| `IA32_CSTAR` | `0xC0000083` | Compat-mode syscall entry; effectively unused on modern Windows |
| `IA32_FMASK` | `0xC0000084` | RFLAGS mask applied on syscall entry |
| `IA32_SYSENTER_*` | `0x174`–`0x176` | 32-bit `sysenter` entry / CS / ESP (relevant only under WoW64) |

Attacker move at this layer: redirect `IA32_LSTAR` to a trampoline, intercept syscalls. Some BYOVD tools patch only one CPU's `LSTAR`, so a per-CPU MSR poll catches partial coverage.

**CET-related MSRs** (Intel Tiger Lake+, AMD Zen 3+):

| MSR | Number | Role |
|-----|--------|------|
| `IA32_U_CET` | `0x6A0` | User-mode CET state (shadow stack + IBT enable bits) |
| `IA32_S_CET` | `0x6A2` | Supervisor (kernel) CET state |
| `IA32_PL0_SSP` | `0x6A4` | Ring-0 shadow stack pointer |
| `IA32_PL3_SSP` | `0x6A7` | Ring-3 shadow stack pointer |
| `IA32_INTERRUPT_SSP_TABLE_ADDR` | `0x6A8` | Per-CPU interrupt SSP table base |

CET-related MSRs are a BYOVD attack target on hardware-CET systems. Disabling `S_CET.SH_STK_EN` or `U_CET.SH_STK_EN` breaks shadow-stack enforcement, allowing classic ROP/JOP chains to operate on otherwise-protected processes. PatchGuard covers these MSRs on recent builds, but tamper-and-restore races still appear in research code.

Detection:

- `LSTAR` / `CSTAR` / `SYSENTER_EIP` per logical processor; all should point at `ntoskrnl!KiSystemCall64` or `KiSystemCall64Shadow` (KVA-shadow build) or `KiFastCallEntry` (32-bit).
- `FMASK` should equal a known constant (typically `0x4700` family — masks `IF`, `TF`, `DF`, etc.).
- IDT entries 0x01, 0x03, 0x0E, 0x2E (and others) must point inside `nt`/`hal` ranges.
- Debug registers `DR0`–`DR3`, `DR7` non-zero in a non-debugger context = hardware breakpoints set for anti-debug or for RWX-bypass tricks.

PatchGuard covers IDT, GDT, the syscall MSRs, and (on modern builds) parts of the debugger state. Attempting to restore tamper from a kernel detector is usually inadvisable — flag, report, and let the bugcheck (if any) provide forensic evidence.

### 13.4 WoW64 Transition Layer Hooking

On 64-bit Windows, 32-bit (x86) processes execute their syscalls through a translation layer rather than directly. The path is:

```
x86 code  →  ntdll!Wow64Transition  →  wow64.dll → wow64cpu.dll  →  64-bit syscall  →  kernel
```

`Wow64Transition` is a global pointer in 32-bit ntdll resolved at process load to a routine inside `wow64cpu.dll` (specifically `wow64cpu!CpupReturnFromSimulatedCode` and adjacent). The dispatcher then routes the syscall into the 64-bit thunk that issues the actual `syscall` instruction. Attacker primitives:

- **`Wow64Transition` pointer overwrite** — single 8-byte write redirects every syscall a 32-bit process makes to attacker code, while 64-bit ntdll integrity remains intact. Defeats most direct-syscall and ntdll-hash detection because the *trampoline* is hijacked, not the syscall stubs.
- **`wow64cpu!Wow64SystemServiceEx` inline patch** — patch inside the 64-bit half of the translation layer to filter syscalls before they reach the kernel. Affects only the patched process.
- **"Heaven's Gate" abuse** — direct `cs:0x33` far call from 32-bit code into a 64-bit code segment to execute 64-bit instructions without going through the documented WoW64 path. Originally used for evasion of 32-bit-only hooks; now well-known and detectable.
- **Cross-architecture syscall confusion** — issue 64-bit syscalls from a 32-bit process by manually setting up the long-mode transition. Defeats 32-bit-targeted hook chains.

For game anti-cheat the WoW64 layer matters less than for general EDR (most current AAA titles are 64-bit), but it's relevant for:

- 32-bit launchers / overlay tools that the cheat hijacks
- Legacy game titles that still ship 32-bit
- Cheat loaders that intentionally use 32-bit to escape 64-bit-only inspection

Detection:

- Snapshot `wow64.dll` / `wow64cpu.dll` `.text` hashes at module load (PsSetLoadImageNotifyRoutine fires for these too).
- For every 32-bit process the game spawns or trusts, read `Wow64Transition` from its 32-bit ntdll and verify the target is inside the expected `wow64cpu.dll` range.
- ETW `Microsoft-Windows-WoW64` emits transition-related events on some builds.
- `KTHREAD.Wow64InfoPtr` and `EPROCESS.Wow64Process` are kernel-side handles to the per-thread / per-process WoW64 state — sanity-check fields, but treat as build-fragile.

### 13.5 ARM64EC and x64-on-ARM Emulator Hooking

Windows 11 on ARM64 introduces **ARM64EC** ("Emulation Compatible") and the **`xtajit64.dll`** binary translator that lets x64 code run on ARM64 hardware. The translator dynamically rewrites x64 instructions into ARM64, manages a per-thread emulation context, and bridges native ARM64 calls into emulated x64 callees through "FFS thunks." This is the substrate that x64 game binaries run on when launched on a Copilot+ / Snapdragon X laptop (ARM64-native game builds bypass the emulator entirely, but those are still rare in 2026).

Threat-model implications:

- The translator is the single largest piece of trusted user-mode code in an x64 process on ARM. Hooks inside `xtajit64.dll` or its supporting `xtajit.dll` / `wowarmhw.dll` see every syscall the x64 game makes, before the syscall ever reaches the ARM64 kernel-bridge code.
- ARM64EC modules can call freely between native ARM64 and emulated x64. An ARM64EC-compiled malicious module loaded into an x64 game can issue native ARM64 syscalls that bypass any x64-side instrumentation.
- The emulator allocates and manages JIT-style code caches (private RX VAD regions filled with translated ARM64 instructions). Distinguishing legitimate emulator JIT from manual-map / shellcode requires emulator-aware allowlisting that anti-cheat vendors have not yet broadly implemented.

For an anti-cheat targeting Windows-on-ARM:

- Verify `xtajit64.dll` and friends are Microsoft-signed and loading from `System32` / `SysWOW64` only.
- Hash the `.text` sections of the translator modules at load and re-check periodically.
- Treat the emulator's JIT regions as a known allowlisted class of private RX, distinct from cheat shellcode.
- ARM64EC kernel-side state is exposed via `EPROCESS.PicoContext`-shaped fields on these builds; PDB-resolve.

This is a small footprint of current gaming installs (Snapdragon X / Surface Pro 11 / 12 plus a few Copilot+ AMD/Intel boxes that run x64 natively without this emulator) but is forecast to grow.

---

## 14. Callback and Telemetry Blinding

A complete hiding chain almost always pairs the actual hiding technique with blinding the kernel events that would have surfaced it. Microsoft's documented callback registration mechanisms are:

- `PsSetCreateProcessNotifyRoutineEx`
- `PsSetCreateThreadNotifyRoutine`
- `PsSetLoadImageNotifyRoutine`
- `ObRegisterCallbacks` (process / thread / desktop object operations)
- `CmRegisterCallbackEx` (registry)
- `FltRegisterFilter` (Filter Manager, file I/O minifilters)
- ETW providers and sessions

`ObRegisterCallbacks` specifically requires the calling driver to be built with the `/INTEGRITYCHECK` linker flag (the resulting PE has `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` set) and to be appropriately signed (WHQL/EV on production; on HVCI-on systems, WHCP is the only acceptable path).

### 14.1 Callback Tampering Mechanics

The current public state of the art:

1. Obtain arbitrary kernel R/W via BYOVD or kernel exploit.
2. Locate the callback list / array via build-specific signature/symbol resolution.
3. Null or rewrite specific vendor callback entries.
4. For object callbacks: manipulate the altitude / order or rewrite object-type flags.
5. For minifilters: detach or alter altitudes.
6. For ETW: stop sessions, change provider enable masks, kill consumer processes, orphan sessions.

Public projects implementing the kernel-mode tier — **EDRSandBlast** (wavestone-cdt), **RealBlindingEDR** (myzxcg) — automate steps 1–4 against a parametrized list of EDR drivers. They have been continuously updated through 2024–2025 for offset drift across Windows builds. **EDRSilencer** takes a different approach: it uses Windows Filtering Platform (WFP) to block EDR-driver network telemetry from reaching cloud backends without touching kernel callbacks at all.

On HVCI-protected systems, callback arrays that live in non-writable VTL0 pages can't be tampered from VTL0; the attacker has to go to a callback registration whose state lives in a writable kernel data page, or operate at the secure-kernel boundary. This shrinks the attack surface materially but doesn't close it. KDP (Kernel Data Protection), extended in 23H2/24H2 to cover additional sections, has continued the shrinkage.

### 14.2 Per-Callback Blinding Effects

| Callback | What it hides | Backstop |
|----------|---------------|----------|
| Process notify | Process create/exit ledger | ETW process events, Security event log, SCM events |
| Thread notify | Remote-thread / APC follow-up | ETHREAD/KPRCB/VAD execution traces |
| Image load notify | DLL/EXE load events | VAD image map, section objects, PEB LDR |
| Object callback | Process/thread handle policy | Handle table, granted access, source PID |
| Registry callback | Service/Run/persistence registry events | Hive transactions, Sysmon/ETW registry events |
| Minifilter | File scan/deny | File object, MFT, USN journal |
| ETW provider/session | User-mode consumer events | Kernel callbacks, partial event log |
| WMI provider | WMI query results | Native API, kernel view |

**Callback blinding is rarely the goal in itself.** It is a force multiplier for other hiding techniques — ghosting alongside callback nulling is much harder to detect than ghosting alone. The defender's posture should be:

- Self-check callback pointers, counts, and altitudes immediately after registration and on a rolling basis.
- Register decoy callbacks; flag broad nulling that hits decoys too.
- Trigger expected events (decoy process handle requests, etc.) and verify the expected callback / policy outcome.
- Treat the absence of expected events as evidence, not silence.

### 14.3 ETW / Sysmon / WMI

These are user-mode collection pipelines and therefore broader attack surface than kernel callbacks. The blinding moves: stop sessions, change enable masks, kill consumers, hook the event-write path, tamper with the EventLog service, replace Sysmon config, modify WMI repository.

The most common surgical technique in current public tradecraft is **`ntdll!EtwEventWrite` / `NtTraceEvent` inline patching**. A single attacker process patches the prologue of `EtwEventWrite` (or its variants `EtwEventWriteFull`, `EtwEventWriteEx`, `EtwEventWriteTransfer`) in its own ntdll with one of:

```
xor eax, eax    ; 31 C0
ret             ; C3
```

or equivalently `mov eax, 0; ret`. All subsequent ETW writes from that process return success without actually emitting anything. The same pattern applies to `NtTraceEvent` directly. Because each process has its own ntdll mapping (after copy-on-write), the patch affects only the patching process — it doesn't blind ETW system-wide, but it perfectly blinds any provider inside that process. The same family of techniques (AMSI bypass, ScriptBlockLogging bypass) targets `amsi!AmsiScanBuffer` and PowerShell's `System.Management.Automation.AmsiUtils.amsiInitFailed` with one-byte patches.

Detection:

- **ntdll integrity check** — hash the `.text` section of every untrusted process's ntdll against a known-good baseline. False positives from EDR self-hooks are real but bounded.
- **Direct-syscall canary** — issue a probe that should produce a known ETW event from the suspect process; if the kernel-side ETW session sees it but the user-mode write path is reported as having occurred, the discrepancy is the patch.
- **ETW-TI subscription** of `EtwEventWrite` modification events (PPL-only).
- **Kernel-side prologue verification** — anti-cheat driver can attach to the target, read the first 16 bytes of `ntdll!EtwEventWrite`, and compare against expected.

A modern variant uses `WriteProcessMemory` from a *broker* process rather than self-patch — the broker writes the `xor eax,eax; ret` bytes into a child or sibling process's ntdll. This shifts attribution: the patched process itself looks innocent (its ntdll is dirty but the process didn't touch it), while the patcher leaves a clean trail of `WriteProcessMemory` against `ntdll!EtwEventWrite` that **kernel-side process-write ETW** (via `PsSetCreateProcessNotifyRoutineEx`-paired observability) can catch. Defenders should treat any `WriteProcessMemory` against an ntdll `.text` page as Tier-1 suspicion regardless of which process is the destination.

**WPP (Windows Software Trace Preprocessor) is a parallel target.** WPP is the tracing macro framework used by many Microsoft kernel-mode drivers (and some user-mode subsystems) for debug instrumentation. Unlike ETW, WPP emits through `WppTraceMessage` → `EtwTraceMessage` rather than `EtwEventWrite`. Patches against `EtwEventWrite` therefore don't blind WPP-using consumers, but patches against `WppTraceMessage` or `EtwTraceMessage` do — and these are less commonly hashed by defender ntdll-integrity checks. Recent research-grade EDR-blinders (2024–2025 PoCs) target both call paths to fully blind tracing in a target process. Defender's response: hash both `EtwEventWrite*` and `EtwTraceMessage`/`NtTraceEvent` byte ranges in any ntdll integrity routine.

The ETW provider `Microsoft-Windows-Threat-Intelligence` is a special case worth restating: as of Windows 11 25H2, **its consumers must run as Protected Process Light at signer level `WinTcb` or higher.** Defender, Elastic, CrowdStrike, SentinelOne qualify; commercial anti-cheat drivers generally don't, and so cannot consume the ETW-TI feed. Anti-cheat must rely on its own kernel callbacks for `NtQueueApcThread`, `WriteProcessMemory`, `SetThreadContext`, `MapViewOfFile2`, `ReadProcessMemory`, and so on.

Telemetry-cliff signals worth treating as evidence:

| Signal | Description |
|--------|-------------|
| Provider heartbeat absent | Normally-periodic provider events stop |
| Event-rate cliff | Process/image/file/driver events drop dramatically |
| Source disagreement | Sysmon empty, kernel ledger populated |
| Service-state transition | Sysmon/EventLog/WMI service stop, crash, restart |
| Config-hash drift | Sysmon config, WMI registration, ETW autologger changes |
| Local-only gap | Endpoint log gap, but remote collector saw events just before |

### 14.4 Object Callback Altitude and Order Abuse

`ObRegisterCallbacks` orders registrations by an **altitude** string (similar to minifilter altitudes). The callback chain runs from lowest altitude to highest, and each callback can strip or downgrade the granted access requested by the open. A more subtle attacker doesn't null the anti-cheat callback at all — they manipulate the order or the surrounding chain so that the anti-cheat callback runs after a malicious one has already issued the open, or so that the anti-cheat callback receives a confusing pre/post state.

Tampering moves observed in the wild and in research code:

- Register a malicious callback at an altitude *lower* than the anti-cheat's so that it runs first and either grants the access the anti-cheat would have stripped, or transparently brokers the handle through to the attacker.
- Rewrite the callback target pointer to look like a trampoline inside a legitimate module's range while actually jumping out to attacker code.
- Modify the `OB_OPERATION_REGISTRATION` array to flip the `Operations` mask, effectively unsubscribing the anti-cheat from `OB_OPERATION_HANDLE_CREATE` or `OB_OPERATION_HANDLE_DUPLICATE` events.
- Change the object type's flag bits to disable callback invocation entirely for `PsProcessType`/`PsThreadType` operations.

Detection procedure for anti-cheat callbacks:

1. **Snapshot at registration** — record callback cookie, altitude string, target address, owning image, and the `OB_OPERATION_REGISTRATION` array contents (operation mask, pre/post pointers).
2. **Periodically diff** — compare the current callback list's target range, altitude ordering, and operation masks against the registration snapshot.
3. **Range check** — every callback target must fall inside a signed, expected driver image range.
4. **Decoy access probe** — issue a known-deniable process-handle request from a controlled test process and verify the expected access mask is stripped. A live callback that no longer strips access is evidence of preceding-callback tamper or operation-mask manipulation.
5. **Object-type flag check** — `OBJECT_TYPE.TypeInfo.SupportsObjectCallbacks` must remain set for `PsProcessType` and `PsThreadType`.

This whole layer is genuinely difficult to defend on a non-HVCI system because the attacker has arbitrary kernel write. On HVCI-on systems, the `OBJECT_TYPE` structures live in pages the attacker can't directly write from VTL0, narrowing the surface to callback-list entries and registration metadata. KDP (Kernel Data Protection) further restricts which kernel data sections are writable at runtime; the practical implication is that **the same anti-cheat callback is materially harder to blind on a 24H2 device with HVCI + KDP + Smart App Control than on a downgraded or pre-22H2 device.**

### 14.5 Forensic and Crash-Dump Suppression

Working-set evasion (§12.5) targets live dumps. A parallel attacker move targets the *post-mortem* dump surface — preventing or corrupting kernel crash dumps, user-mode minidumps, and WER reports that would otherwise reach a defender's analyst:

| Surface | Tampering | Effect |
|---------|-----------|--------|
| `HKLM\System\CurrentControlSet\Control\CrashControl\CrashDumpEnabled` | Set to `0` | No kernel dump on bugcheck |
| `HKLM\System\CurrentControlSet\Control\CrashControl\DumpFile` | Redirect to nonexistent path | Dump write silently fails |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug\Debugger` | Replace post-mortem debugger with attacker EXE | Crashing processes call the attacker's "debugger" |
| `HKLM\Software\Microsoft\Windows\Windows Error Reporting\Disabled` | `1` | WER turned off, no user-mode crash dumps shipped |
| `WerSvc` service | Stop / disable | WER subsystem inert |
| IFEO `<exe>\DumpType` / `DumpFolder` / `DumpCount` | Zero / invalid | Per-process dump policy degraded |
| `ntdll!MiniDumpWriteDump` (in EDR's process) | Inline patch | Dump API itself returns success without writing |
| `nt!IoWriteCrashDump` / `nt!IoCaptureLiveDump` | Inline patch | Kernel dump path neutralized |
| **CSRSS callback registration** (`CsrApiCallList`, esoteric) | Unhook crash-related callbacks | Console subsystem doesn't notify on faults |
| **DTrace for Windows** (`dtrace.sys`) | Disable / unload | Lose runtime tracing surface used by some forensic tools |

For game anti-cheat specifically, the most important of these are:

- **WER and `MiniDumpWriteDump` integrity** — when an anti-cheat detects a cheat, it commonly dumps the suspect process for upload. Patches against these defeat the evidence pipeline.
- **`AeDebug\Debugger`** — IFEO-adjacent surface that can hijack any crashing process's post-mortem handling.

Detection: baseline these registry values and service states at install time; treat any change as Tier-1 evidence. The CrashControl tree is rarely modified by legitimate software outside of admin debugging, so changes are very-low-false-positive signals.

---

## 15. BYOVD and Driver Concealment

Process DKOM, callback blinding, kernel memory R/W — almost all of them sit on top of either a manually-mapped driver or a BYOVD (Bring Your Own Vulnerable Driver) chain. Hidden process detection and driver concealment detection are therefore the same investigation at two layers.

The 2024–2026 BYOVD ecosystem is a moving target. Several factors define the current state:

- **Microsoft Vulnerable Driver Blocklist** (formal name within App Control for Business) is enabled by default on Windows 11 22H2+ devices that have HVCI, Smart App Control, or S mode. Updates ship **quarterly** through Windows Update plus monthly rule bumps. The most current rule list is also published at `aka.ms/VulnerableDriverBlockList`.
- **ASR rule "Block abuse of exploited vulnerable signed drivers"** (`56a863a9-...`) blocks the *drop-to-disk* stage of BYOVD on managed endpoints — preventing the loader from writing a vulnerable `.sys` to disk in the first place.
- **HookSignTool / FuckCertVerifyTimeValidity** (2023–2024) and similar techniques abuse certificate-timestamping flaws to sign *new* drivers under expired-but-still-trusted Windows attestation chains. Microsoft has revoked many implicated certificates, but the technique class remains relevant.
- **LOLDrivers** (loldrivers.io, magicsword-io/LOLDrivers) tracks 1,800+ known-malicious-or-vulnerable signed drivers as of 2025, with hashes, certificates, IOC packs, YARA, and Sigma rules. Defender, Elastic, CrowdStrike, SentinelOne integrate LOLDrivers metadata.

Notable BYOVD families in current operational use:

| Family | Year | Vulnerable driver | Use |
|--------|------|--------------------|-----|
| **AuKill** (Sophos, 2023) | 2023 | `PROCEXP.SYS` (Process Explorer) | Pre-Medusa/LockBit deployment EDR kill |
| **Backstab** | 2022 | `PROCEXP.SYS` | Open-source AuKill predecessor |
| **Terminator / Spyboy** | 2023 | `zamguard64.sys` / `zam64.sys` (Zemana) | Commercially sold EDR-killer |
| **EDRKillShifter** (Sophos, Aug 2024) | 2024 | Various rotating drivers | RansomHub-linked; **major current threat** |
| **AVNeutralizer / AuKill v2** | 2024 | Rotating | FIN7 affiliates |
| **EDRPrison** | 2024 | WatchDog Antimalware driver (rotating module names) | EDR callbacks zeroing |
| **EDRSandBlast** | 2022–2025 | Multiple, parametrized | Open-source reference |
| **RealBlindingEDR** | Ongoing | Multiple | Open-source callback zeroer |
| **EDRSilencer** | 2023–2024 | None (WFP-based) | Network-telemetry blocker |

### 15.1 What a Legitimate Driver Load Leaves Behind

Defender baseline: a legitimately loaded driver leaves evidence in many places. Detecting concealment is detecting *gaps* in this list, not absence in any single place.

| Surface | Trace |
|---------|-------|
| SCM / registry | `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` |
| File system | `.sys` file, file id, USN journal, MFT entry |
| Code Integrity | CI signature/hash validation event/cache |
| Kernel loader | `PsLoadedModuleList`, `KLDR_DATA_TABLE_ENTRY` |
| Driver object | `DRIVER_OBJECT`, `DriverSection`, dispatch table |
| Device object | `\Device\...`, symbolic link, device stack |
| PnP / WDF | WDF runtime list, PnP devnode, filter stack |
| Unload history | `MmUnloadedDrivers` ring buffer, ETW unload events |
| CI cache | `PiDDBCacheTable`, `g_KernelHashBucketList`, CI hash cache |
| ETW / event log | `Microsoft-Windows-CodeIntegrity`, Kernel-ImageLoad, SCM `7045`/`7036`, Sysmon driver event |

### 15.2 Concealment Techniques

| Technique | Mechanism | Detection |
|-----------|-----------|-----------|
| `PsLoadedModuleList` unlink | Remove `KLDR_DATA_TABLE_ENTRY` from list | Pool executable scan, import / call-stack attribution |
| `MmUnloadedDrivers` clear | Zero the unload ring buffer | Circular-buffer anomaly, timestamp gap |
| `PiDDBCacheTable` clear | Remove cached driver entry | Cache invariant, CI event vs. PiDDB diff |
| `ci.dll` cache clear | Remove validation cache entry | `Microsoft-Windows-CodeIntegrity` event vs. cache diff |
| WdFilter runtime list clear | Defender-internal driver list | WdFilter state, Defender event diff |
| `ExpCovUnloadedDrivers` clear | Verifier coverage trace | Verifier state, coverage list anomaly |
| Manual-mapped driver | Direct PE placement in kernel memory | Executable non-image kernel memory |
| Device object unlink | Hide `\Driver` / `\Device` namespace | Object directory walk vs. dispatch pointer |
| Vulnerable driver proxy | Legitimate driver as IOCTL broker | Known vulnerable hash/cert, IOCTL behavior |
| Dispatch table hijack | Repoint dispatch pointer on benign driver object | Dispatch pointer range check |
| Driver object reuse | Attach malicious context to benign object | Extension memory provenance |
| Temporary load/unload | Load BYOVD briefly, unload | Session-time-window CI/SCM/ETW correlation |
| Service key deletion | Remove SCM service key after load | SCM event vs. registry/file ledger diff |
| File delete/rename | Delete `.sys` after load | File id, section object, MFT/USN |
| Blocklist disable | Lower vulnerable-driver-blocklist / HVCI / CI policy | Policy state drift, reboot-time attestation |

### 15.3 `PiDDBCacheTable` Scrubbing

`PiDDBCacheTable` is `ci.dll`'s internal cache of previously-validated driver image metadata. It is undocumented, stored as an `RTL_AVL_TABLE` protected by `PiDDBLock` (an `ERESOURCE`). Each entry is approximately:

```c
typedef struct _PiDDBCacheEntry {
    LIST_ENTRY      List;
    UNICODE_STRING  DriverName;
    ULONG           TimeDateStamp;
    NTSTATUS        LoadStatus;
    // additional fields, build-dependent
} PiDDBCacheEntry;
```

The exact layout drifts across Windows builds; PDB-backed resolution is the only safe way to walk it. It is **still present** on Windows 11 24H2 / 25H2 — Microsoft has not deprecated or replaced it.

Why mappers scrub it: it remembers that a specific vulnerable driver was loaded. KDMapper, KDU, and most public mapper code includes routines to acquire `PiDDBLock` exclusively, walk the tree, and remove the entry for the BYOVD that just provided arbitrary R/W.

Cross-view detection:

| Comparison | Implication |
|------------|-------------|
| `PsLoadedModuleList` has driver, PiDDB lacks it | Inconsistent state, possible scrub or new load before tree update |
| CI event (`Microsoft-Windows-CodeIntegrity`) has the driver load, PiDDB lacks it | Scrub after-load |
| File ledger has `.sys` load, PiDDB lacks it | Scrub after-load |
| Known BYOVD-family hash/cert present in any of the other ledgers | Identified BYOVD chain |
| AVL tree count / ordering invariant violated | Tampered tree state |
| Load/unload just before game session start, then PiDDB missing | Temporally suspicious |

Scoring:

- PiDDB-only gap: medium.
- PiDDB + `MmUnloadedDrivers` gap + CI event present: strong driver scrub.
- PiDDB gap + unknown executable kernel memory: high-confidence BYOVD/manual-map chain.

Operational caveats: read-only consistency check only — locking discipline must be exact (`PiDDBLock` shared); never write/restore the tree, the build drift is too severe. With HVCI on, write attempts to `ci.dll` data sections may themselves be blocked depending on whether the page falls in SLAT-protected memory.

### 15.4 `MmUnloadedDrivers`

A fixed-size circular buffer of `UNLOADED_DRIVERS` records — name, start/end address, unload time. The default array length on shipping Windows is **50 entries**. The next-write index is `MmLastUnloadedDriver` (or equivalent). Wraparound is silent.

Attack patterns: full-zero the array; selectively remove specific entries while preserving ring-buffer ordering; rewrite `MmLastUnloadedDriver` to fake natural wraparound.

Detection:

| Signal | Implication |
|--------|-------------|
| Unload events exist (SCM, CI, ETW), no `MmUnloadedDrivers` record | Selective wipe |
| Array uniformly empty | Full clear (rare on a live system) |
| Unload timestamps non-monotonic | Forgery |
| Unloaded address range overlaps live executable pool | Manual map / stale overlap |
| Known-vulnerable driver in CI log, absent from unload history | BYOVD trace deletion |

Caveat: with only 50 entries, normal systems naturally rotate them — pre-existing entries from boot may be evicted within minutes on busy systems. Time-windowed analysis around a known game-session start mitigates this.

### 15.5 Code Integrity Cache and `g_KernelHashBucketList`

CI validates signatures and hashes on every driver load and leaves multiple traces: ETW events under `Microsoft-Windows-CodeIntegrity`, internal hash caches, lookaside lists, policy state. The **CI ETW provider is one of the most useful BYOVD detection signals** — it logs WHQL/WHCP decisions, signer info, and on revocation/blocklist hits the reason.

Attackers target the internal caches because PiDDB and `MmUnloadedDrivers` together are not the only evidence. The defender's posture should rely *less* on internal cache walks and *more* on the CI ETW provider, App Control audit logs, and Windows event logs — all of which are more stable than undocumented kernel structures.

### 15.6 `DRIVER_OBJECT`, Dispatch Tables, Device Namespace

Even with `PsLoadedModuleList` unlinked, a driver that handles IOCTLs must keep a `DRIVER_OBJECT` reachable from somewhere. More sophisticated attackers reuse a benign driver object and only rewrite its dispatch pointers.

| Detection | Description |
|-----------|-------------|
| Object namespace diff | Walk `\Driver`, `\Device`, symbolic link, device stack and cross-reference |
| Dispatch range check | Dispatch pointers must fall inside owning driver's image |
| Module interval tree | All callback / dispatch / timer / DPC targets fall inside known modules |
| Device ACL audit | User-writable device objects, Everyone/Users write access |
| IOCTL behavior profile | High-entropy IOCTLs, arbitrary physical/virtual memory semantics |
| Stack attribution | IRP-dispatch call stack includes unknown executable memory |

### 15.7 Manually-Mapped Drivers

Manual mapping skips SCM, CI, and the loader entirely. The PE is placed directly in kernel memory; the attacker resolves imports, registers exception metadata, and possibly zeroes the PE header. `MZ`/`PE` byte scanning alone is insufficient.

Detection candidates:

- Executable kernel memory outside `PsLoadedModuleList`'s ranges
- Non-paged pool or system PTE with code-shaped contents
- Import thunk / call-thunk patterns
- MSVC runtime / security cookie helper patterns
- Exception/unwind metadata, C++ RTTI, SEH structures
- Indirect call targets in unknown kernel memory
- Thread / timer / DPC / callback / dispatch targets in unknown ranges
- `MmGetSystemRoutineAddress` / export-resolver call patterns
- Pages with executable PTE but no backing module

A complete detector composes a `PsLoadedModuleList` interval tree as baseline, scans for executable PTEs / big-pool allocations outside that tree, and scores each candidate by PE-fragment likelihood, import resolution patterns, exception-metadata presence, call-target density, and entropy. A region cross-referenced from a callback / dispatch / thread / timer dramatically increases score. Temporal correlation with driver-load gaps in CI/SCM/PiDDB/`MmUnloadedDrivers` produces the strongest signal.

### 15.8 PnP Upper/Lower Filter Driver Injection

Beyond SCM-registered service drivers, the Plug-and-Play subsystem honors `UpperFilters` and `LowerFilters` registry values on each device class and device instance. A driver listed there gets loaded as a filter on the corresponding device stack — without any explicit `CreateService` call — and remains loaded as long as any matching device is enumerated.

Attractive for hiding because:

- No SCM service entry to scrub.
- Loaded automatically by PnP, not by SCM — different code path, different ETW provider.
- Embedded in a normal device-class stack (`{4d36e972-e325-11ce-bfc1-08002be10318}` for Net, `{4d36e97d-e325-11ce-bfc1-08002be10318}` for System, `{36fc9e60-c465-11cf-8056-444553540000}` for USB, etc. — see Microsoft's *System-Defined Device Setup Classes* documentation) and is hard to distinguish from legitimate filters (network monitors, USB stack helpers, antivirus mini-filters).
- Class filters in `HKLM\SYSTEM\CurrentControlSet\Control\Class\{class GUID}\UpperFilters` affect every device of that class.

Detection: enumerate `UpperFilters` and `LowerFilters` on every device class and instance; cross-reference each named driver against the loaded-module ledger, the LOLDrivers database, and the WHQL signer expectation for that class. A filter driver that loads but has no PnP `IRP_MN_*` traffic is suspicious.

### 15.9 WDF Runtime Driver List

KMDF/UMDF (Kernel-Mode and User-Mode Driver Frameworks) drivers register with the Windows Driver Framework runtime, which maintains its own driver list separate from `PsLoadedModuleList`. The framework state lives in:

- `WdfLdr.sys` runtime structures
- Per-driver `WDFDRIVER` handles, accessible from kernel
- WDF debug extensions (`!wdfldr.wdfdriverinfo`, `!wdfkd.*`) show the list

Public mappers commonly forget the WDF runtime list — they unlink from `PsLoadedModuleList` but leave the WDF framework's entry intact, or vice versa. Cross-view: any driver in `PsLoadedModuleList` but not in the WDF runtime list (when it's supposed to be a WDF driver per its imports of `WdfFunctions`), or vice versa, is a strong divergence signal.

### 15.10 DSE / `g_CiOptions` Patching

Manual-map drivers and many BYOVD chains begin by lowering Driver Signature Enforcement. The relevant kernel state lives in `ci.dll`:

- `ci!g_CiOptions` — bitfield: `0x6` is the typical "DSE on" value (`CI_OPTION_ENABLED | CI_OPTION_DRIVERS_BLOCKED`). Patching to `0x0` disables enforcement for subsequent driver loads.
- `ci!g_CiEnabled` (older) — boolean.
- `nt!SeCi*` callback structures, `ci.dll!CiInitialize`-installed function pointers, and (on HVCI builds) secure-kernel mirrors of these decisions — all interact with code-integrity gating, all build-dependent in name and offset. PDB resolution mandatory.

A BYOVD chain typically:

1. Loads a signed vulnerable driver (writes possible via its IOCTL).
2. Locates `ci.dll!g_CiOptions` via signature scan or PDB.
3. Writes `0x0` (or `0x4`, depending on desired mode).
4. Loads the attacker's unsigned driver via standard `NtLoadDriver` or `ZwLoadDriver`.
5. Restores `g_CiOptions` to `0x6` to avoid drawing attention.

Detection:

- Sample `g_CiOptions` periodically; flag any value other than the boot-time observed value.
- On HVCI systems, this is harder to attack — `ci.dll` data lives in pages VBS keeps non-writable from VTL0 (depending on KDP coverage).
- Correlate driver loads in `Microsoft-Windows-CodeIntegrity` ETW with `g_CiOptions` state: any successful driver load while the option is lowered is high-confidence DSE bypass.

### 15.11 Service Trigger Events for Delayed/Conditional Load

`HKLM\SYSTEM\CurrentControlSet\Services\<svc>\TriggerInfo` lets the Service Control Manager start a service in response to specific runtime events instead of at boot or on demand. Triggers include:

- ETW provider GUID emitting an event
- Device class GUID arrival or removal
- IP-address availability
- Domain join / leave
- Custom system event GUID
- Named-pipe presence
- RPC interface registration

A driver registered with a trigger isn't loaded at boot, so an inventory taken at game start may miss it. The driver loads later when the trigger fires (e.g., when a specific USB device is plugged in, or when a particular ETW event is emitted by another process). Common abuse patterns:

- Driver loads only after the anti-cheat finishes its initial scan.
- Driver loads from a triggered cheat-loader process via a custom ETW event the loader emits.
- Driver loads via device-arrival trigger when a USB DMA peripheral is plugged in.

Detection: enumerate `TriggerInfo` subkeys on all service entries at game start; treat non-Microsoft drivers with any trigger registration as suspicious. ETW `Microsoft-Windows-Services` emits service-trigger events that the anti-cheat can consume.

### 15.12 Volume / Disk / Partition Filter Drivers

Beyond the NTFS file-system minifilter layer, the storage stack has several lower attachment points:

| Layer | Attachment | Effect |
|-------|-----------|--------|
| **Volume manager** | Attach as upper or lower filter on `\Device\HarddiskVolume*` | See raw cluster I/O before file-system layer |
| **Partition manager** | Attach on `\Device\Harddisk*Partition*` | Even lower — pre-volume |
| **Disk class** | Attach on `\Device\Harddisk*` | Below the partitioning layer, see SCSI/ATA SRBs |
| **Storport miniport filter** | Attach inside the Storport driver stack | At the host-controller level |

A driver attached at the disk-class layer or below sees I/O that the NTFS minifilter never observes (raw cluster reads, bypassing all file-object machinery). The same primitive is what legitimate disk-encryption (BitLocker), backup, and snapshot products use, so signer/allowlist is the only practical control. A non-Microsoft, non-allowlisted driver at the disk-class layer on a consumer gaming endpoint is suspicious.

Detection: walk the device stack of `\Device\Harddisk0\DR0` (and equivalents) via `IoEnumerateDeviceObjectList`; cross-reference each attached filter's owning driver against the LOLDrivers blocklist and against an allowlist of known storage filters (BitLocker, vendor backup tools, etc.).

### 15.13 Boot-Time Driver Loading (`SERVICE_BOOT_START` / `SERVICE_SYSTEM_START`)

The `Start` value in `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` controls when the driver loads:

| Value | Name | Loaded by | Timing |
|------:|------|-----------|--------|
| 0 | `SERVICE_BOOT_START` | NTLDR / Boot Manager | Before kernel initialization |
| 1 | `SERVICE_SYSTEM_START` | Session Manager (`smss.exe`) | During kernel init, before `Win32` subsystem |
| 2 | `SERVICE_AUTO_START` | SCM after services pipe ready | At normal services start |
| 3 | `SERVICE_DEMAND_START` | On demand | Whenever explicitly loaded |
| 4 | `SERVICE_DISABLED` | Never | — |

A driver registered with `Start=0` or `Start=1` is loaded *before any anti-cheat driver* that uses the default `SERVICE_DEMAND_START`. This puts the attacker driver in a position to hook callbacks, registry, or filter-manager registrations before the defender driver gets a chance.

The legitimate countermeasure is **Early Launch Anti-Malware (ELAM)**: a specifically-signed driver class that the boot loader is guaranteed to load *before* any other boot driver. Defender, third-party EDRs, and a growing list of anti-cheats (Vanguard is in this category in 2024–2025 builds) ship ELAM drivers exactly so they can vet other boot-start drivers.

| Detection | Mechanism |
|-----------|-----------|
| Boot-start driver inventory | At ELAM-stage, log every driver passed to the ELAM callback (`PiCi*` family) |
| Trust-decision policy | Reject (or audit) unsigned / non-WHQL boot-start drivers from the ELAM callback |
| Post-boot reconciliation | Compare ELAM-observed driver list against `PsLoadedModuleList` at full boot — gaps suggest unlink |

**Niche driver-side primitives.** A few esoteric primitives worth mentioning briefly:

- **Driver Verifier configuration tampering** — `HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\VerifyDriverLevel` / `VerifyDrivers` selects which drivers Driver Verifier instruments. Disabling Verifier on an attacker driver lets it engage in unaligned access, pool overruns, IRQL violations, etc. without crashing or being logged. Detection: baseline the Verifier configuration and any disabling change.
- **DPC routine spoofing** — `KDPC.DeferredRoutine` of a queued DPC can be rewritten before the DPC fires. Catches in the existing "callback / dispatch / timer / DPC target attribution" (§5.3, §17.2) generalization.
- **Object reference count tampering** — artificially incrementing `OBJECT_HEADER.PointerCount` extends an object's lifetime past expected cleanup (preventing rundown while the attacker's other references are gone); decrementing prematurely causes use-after-free races that may be exploitable for further privilege escalation. Niche, but a defender doing pool-walk validation should sanity-check refcount plausibility against the set of known referencers.

### 15.14 Vulnerable Driver Proxy Pattern

Many cheats no longer manually map at all — they simply keep a vulnerable signed driver loaded and use it as an IOCTL broker for arbitrary memory R/W. There is no hidden module to find. Detection rotates to:

- Known vulnerable-driver hash, cert, name, device name (LOLDrivers)
- Wide device-object ACL allowing untrusted user-mode access
- User-mode untrusted process holding handle to the device
- Anomalous IOCTL input/output size distributions
- IOCTLs that don't match the driver's documented function (physical-memory / MSR / PCI-config access from drivers without those features)
- Game-process memory access bursts time-correlated with vulnerable-device IOCTLs

Defender stack: WDAC allowlist + Microsoft vulnerable-driver blocklist + custom blocklist + driver-load notify policy. The ASR rule above is a useful complement on managed endpoints.

### 15.15 Cross-View Driver Artifact Matrix

| Source | Current loaded driver | Past loaded driver | Manual map | BYOVD proxy |
|--------|----------------------:|-------------------:|-----------:|------------:|
| `PsLoadedModuleList` | High | Low | Low | High |
| `DRIVER_OBJECT` namespace | Medium | Low | Low-Medium | High |
| Device object / IOCTL | Medium | Low | Low-Medium | High |
| `PiDDBCacheTable` | Medium | High | Low | High |
| `MmUnloadedDrivers` | Low | High | Low | Medium |
| CI event/cache | Medium | High | Low | High |
| SCM/service event | Medium | High | Low | High |
| File / MFT / USN | Medium | High | Low | High |
| Kernel executable memory scan | High | Low | High | Medium |
| Callback / dispatch attribution | High | Low | High | Medium |

High-confidence chained signals:

- `PsLoadedModuleList` lacks the module + executable kernel memory + callback target outside any known module → manual map.
- CI / SCM logged vulnerable-driver load, but PiDDB and `MmUnloadedDrivers` both lack it → scrubbing chain.
- LOLDrivers-known-vulnerable device exposes wide ACL, untrusted loader process has issued IOCTLs, game memory was accessed within the temporal window → BYOVD proxy.
- HVCI / WDAC / blocklist was lowered immediately before the game session, followed by driver-artifact gaps → policy-weakening chain.

### 15.16 Anti-Cheat Policy Implications

For an anti-cheat game match-start decision, any one of these is a defensible block:

- HVCI off **and** any known-vulnerable driver currently loaded
- Anti-cheat callback self-check failed
- Unknown unsigned / manually mapped kernel executable memory present
- Kernel module list disagrees with ETW `Microsoft-Windows-CodeIntegrity` events
- Vulnerable-driver blocklist disabled or stale
- Two or more of {`PiDDBCacheTable`, `MmUnloadedDrivers`, CI cache} show selective-scrub patterns
- Known-vulnerable driver's device handle is held by an untrusted process
- DSE flag (`ci!g_CiOptions`) observed lowered from its boot-time value at any point during the session
- Unknown (non-Microsoft-signed) IUM trustlet running

Userland compatibility means production rollouts should stage these as audit → warn → block. The CrowdStrike Falcon outage of 19 July 2024 — where a faulty kernel-driver configuration channel-file update bugchecked an estimated 8.5 million Windows endpoints globally — is the year's most expensive reminder that even legitimate kernel code can cause catastrophic outages. Block decisions must be reversible, audit-first, and accompanied by telemetry.

---

## 16. Hypervisor, DMA, Firmware

### 16.1 Hypervisor / EPT / NPT Deception

A hypervisor that runs underneath Windows can split the memory view: anti-cheat reading a page sees one set of bytes, the CPU executing the page sees different bytes. This is implemented on Intel via VT-x / EPT, on AMD via SVM / NPT (RVI).

| Vendor | Extension | Second-level paging | Guest→host entry |
|--------|-----------|---------------------|------------------|
| Intel | VMX (`vmxon`/`vmlaunch`/`vmresume`) | EPT | `vmcall` |
| AMD | SVM (`vmrun`) | NPT/RVI | `vmmcall` |

Attack surface:

- **EPT/NPT cloaking** — execute/read view separation. Anti-cheat reads `.text` and sees clean; CPU executes patched instruction stream. Used by HyperDeceit, hvcheat, and similar 2024–2025 hypervisor-based cheating frameworks.
- **Selective-cloak on fault** — provide the legitimate view to anti-cheat-process reads, the malicious view to anyone else.
- **Timing / NMI / CPUID / MSR fingerprint interception** — the hypervisor intercepts the guest's detection probe and rewrites the answer.
- **PatchGuard / KDP integrity-monitor evasion** — show PG the clean memory.

Detection (in order of effort):

- CPUID leaf consistency: `CPUID.1:ECX[31]` (hypervisor-present), `CPUID.0x4000_0000` family (vendor leaves), Microsoft-recommended-leaf behaviors. Compare against expected Hyper-V / VBS / no-hypervisor configurations.
- MSR / VMX / SVM capability anomaly: `IA32_FEATURE_CONTROL`, `IA32_VMX_BASIC`, AMD `VM_CR`; their content vs. observed `vmxon`/`vmrun` behavior.
- TSC / HPET / APIC timing jitter: `rdtsc` framing of suspect operations, latency spikes around `vmcall`/`vmmcall` attempts.
- EPT/NPT side-effect timing: I-cache vs. D-cache latency patterns to infer view separation.
- VBS / HVCI fingerprint: `HvDetectedHypervisor` and friends; known vs. unknown hypervisor delineation.
- TPM / DRTM / Secure Boot / CI policy attestation — boot-time PCR measurements verified server-side.

Vanguard's TPM 2.0 + Secure Boot requirement (since 2024 for League of Legends rollout) is a direct response to hypervisor-based and bootkit-based cheating; the requirement provides a measured-boot foundation that the runtime detector can lean on.

### 16.2 DMA / External Device

DMA cheats — FPGA-based PCIe endpoints that issue Memory Read TLPs against game memory — leave **no process artifact on the gaming PC**. There is literally nothing to hide because there is nothing on the host. This is the subject of a separate deep dive ([About PCIe DMA Cheats](https://kernullist.github.io/kernullist-blog/posts/pcie-dma-cheats/)).

For the purposes of this document: detection at the host has to fall back on platform-level checks (IOMMU / Kernel DMA Protection status, Thunderbolt / PCIe device inventory and hot-plug events, suspect device class / vendor IDs), behavioral telemetry (input pattern, gameplay anomaly, network telemetry), and server-side attestation. The pure-DMA case is why anti-cheat industry posture is shifting toward server-side anti-cheat and behavior analytics.

### 16.3 SMM / UEFI / Bootkit

Pre-OS tamper that runs before Windows can install its own protections. Defender posture is entirely measurement-based: Secure Boot state, TPM PCR quote, ELAM / CI policy events, boot-chain measurement, kernel image measurement at runtime vs. expected, firmware update state, known-vulnerable-firmware policy. Server-side verification of the measured-boot quote is the only durable check.

### 16.4 GPU Compute Shader and Direct3D Resource Memory Reading

A 2024–2026 emerging vector that anti-cheat industry is starting to track: using the GPU as a memory-acquisition co-processor. Three sub-flavors:

**GPU shared-memory read.** When the game (or any host process) creates a Direct3D resource and asks the GPU driver to make it CPU-accessible (`D3D11_USAGE_STAGING`, `WriteCombine` flags, or `ID3D12Resource::Map` with appropriate heap), the underlying VRAM pages are mapped into the host's address space *and* into a GPU-visible aperture. A second cooperating process (with `D3D11CreateDevice` / `D3D12CreateDevice` and the same adapter) can sometimes open a shared resource handle or, with `IDXGIResource::GetSharedHandle` / `CreateSharedHandle`, gain read access to the GPU side of the mapping. This is the architectural ancestor of "GPU peeking."

**GPU compute shader for memory exfiltration.** A `D3D11ComputeShader` or `D3D12ComputeShader` executing on the GPU can `Load()` from any UAV/SRV bound to it. If an attacker process can convince the driver to bind a resource that happens to alias game memory (often through resource-recycling races, shared heaps, or BC1-block-aliased textures), the compute shader reads game state and writes it to a buffer the attacker can map back. Recent NVIDIA driver advisories (2024) flagged several attack vectors in this category.

**WDDM shared-surface exfiltration.** The Windows Display Driver Model exposes `D3DKMT_*` kernel APIs (`D3DKMTOpenResource`, `D3DKMTQueryResourceInfo`) that a kernel-mode driver can use to walk all GPU resources on the system. A BYOVD with kernel R/W can enumerate game textures, framebuffers, and depth buffers directly from VRAM. This is the cleanest GPU-side bypass: no userspace handle needed, no D3D context required, just a kernel-mode `D3DKMT*` call sequence.

Why this matters for anti-cheat:

- All three sub-techniques bypass everything in §10–§15 because the cheat doesn't read game *system* memory — it reads game *VRAM*. Process-level scanners see nothing.
- DMA cheats (covered in the PCIe DMA blog post) attack system RAM only; GPU-side reading is the host-resident complement.
- ESP / wallhack cheats that work off-camera (showing enemy positions through walls) often need rendered scene data that lives precisely in VRAM, so GPU-side reads are a natural fit.

Detection is genuinely hard:

- Audit `D3DKMTOpenAdapterFromLuid` callers; an untrusted process holding a D3DKMT adapter handle to the game's GPU adapter is suspicious.
- Watch for `IDXGIKeyedMutex` / `IDXGIResource1::CreateSharedHandle` calls on game-process resources.
- WDDM driver telemetry (vendor-specific, partial) can sometimes report inter-process resource sharing.
- The robust defense is to never mark game resources as cross-process-shareable, never use NT shared handles for sensitive textures, and prefer non-CPU-accessible heap types where possible. This is game-engine-side mitigation, not anti-cheat-side detection.

Anti-cheat industry response to this is still maturing. Riot's Vanguard has been documented disabling some Direct3D inter-process resource sharing on protected titles; EAC and BattlEye have less public surface here. The threat is real but the detection toolkit is shallow compared to the rest of this document.

**DirectStorage** (Windows 11 24H2+) is a related emerging vector. The DirectStorage API enables NVMe → GPU VRAM data transfer that bypasses CPU mediation entirely — the storage controller writes directly into a GPU upload heap that the GPU then references. Legitimate use is game asset loading (massive textures, level data); abuse vector is large memory transfers between attacker-controlled NVMe regions and GPU VRAM that the CPU-resident anti-cheat never sees. Detection requires either game-engine-side cooperation (the engine reports DirectStorage usage to anti-cheat) or GPU driver telemetry. As of 2026 this is a research frontier with no public detection tooling.

### 16.5 Trustlet / VBS Enclave / IUM (VTL1) Surface

Virtualization-Based Security (VBS) splits Windows execution between two Virtual Trust Levels: VTL0 (the normal kernel and user mode) and VTL1 (the **secure kernel** plus a small set of **Isolated User Mode (IUM)** processes called *Trustlets*). VTL1 code cannot be inspected or modified from VTL0 — even a fully-compromised normal kernel cannot read or write VTL1 memory.

Microsoft-shipped trustlets include `lsaiso.exe` (the LSA isolation trustlet — Credential Guard's secret store), `bioiso.exe` (biometric isolation), `vmsp.exe` (Hyper-V secure procedure), and on Copilot+ devices a growing list of AI-related secure enclaves. **Windows Recall**, introduced in 24H2 for Copilot+ devices, runs its sensitive memory inside a VBS enclave.

Why this is relevant to a hiding/detection document:

- **As a defensive surface** — anti-cheat could (in principle) place its measurement state in a VTL1 trustlet, making it un-tamperable by kernel-mode malware. No commercial anti-cheat does this today; it's emerging.
- **As an offensive surface** — a sufficiently privileged attacker who can convince the platform to launch a malicious trustlet (or to attest one) gains code execution that VTL0 cannot inspect. This is a research frontier: published trustlet escapes (Saar Amar, James Forshaw, Jonas Lykkegaard, 2020–2023) show the attack surface is real but high-bar. Legitimately launching a trustlet requires the binary to satisfy IUM signing policy (Microsoft `WindowsTcb` signer level plus an explicit IUM extension in the certificate's enhanced-key-usage) — a bar far above ordinary kernel-driver signing.
- **Detection limits** — by design, VTL0 detection cannot see inside a trustlet. The defender's leverage is to:
  - Enumerate the set of running trustlets at process-create time. A trustlet manifests in `EPROCESS` with a secure-process flag set (typically `Flags3.SecureProcess` on Win10/11 — build-specific, PDB-resolve). When in doubt, ask the secure kernel directly via `HvlGetVsmTrustletInfo`-shaped APIs rather than walking `EPROCESS` flag bits.
  - Compare against a known-good baseline (typically just `lsaiso.exe`, possibly `bioiso.exe`).
  - Trust only Microsoft-signed trustlet binaries; any third-party-signed trustlet attempting to launch on a consumer endpoint is a Tier-1 signal.
  - Walk the secure-kernel trustlet roster via build-appropriate internals (the symbol name varies between Windows builds — typical candidates include `nt!IumInvokeSecureService` callers, `securekernel.exe!SkmiTrustletData`-shaped structures, or simply the set of `EPROCESS` with the secure-process flag). PDB resolution is mandatory.

For game anti-cheat: a non-Microsoft IUM trustlet on the gaming machine is essentially never legitimate. It deserves match-block treatment.

---

## 17. Detection Architecture

### 17.1 Overall Structure

```text
                         Server Correlator
                               |
                  evidence upload / policy decision
                               |
+------------------------------+------------------------------+
|                         User Service                         |
| API diff | file hash | signer | ETW consumer | UX/reporting  |
+------------------------------+------------------------------+
                               |
                          IOCTL boundary
                               |
+------------------------------+------------------------------+
|                        Kernel Driver                         |
| process ledger | thread ledger | image ledger | handle mon.  |
| VAD sampler    | KPRCB sampler | pool scan     | self-check  |
| driver ledger  | callback inv. | exec scan     | platform chk|
+------------------------------+------------------------------+
                               |
                    Windows kernel / hardware
```

### 17.2 Collector Priority

| Priority | Collector | Rationale |
|---------:|-----------|-----------|
| 1 | Process/thread/image callback ledger | Authoritative create-time record |
| 2 | KPRCB current-thread sampler | DKOM-resistant |
| 3 | VAD executable-region sampler | Injection / manual-map evidence |
| 4 | Handle / object monitor | Game memory access pathway |
| 5 | Active / CID / handle / session / job / MM cross-view | DKOM classification |
| 6 | Driver artifact ledger | BYOVD / manual driver detection |
| 7 | Pool / executable kernel scan | Confirmation of advanced concealment |
| 8 | Platform attestation | Hypervisor / DMA / bootkit |
| 9 | Call-stack provenance at kernel callbacks | In-memory tradecraft (post-2023 detection upgrade) |
| 10 | `EPROCESS.InstrumentationCallback` sampler | Catches `ProcessInstrumentationCallback`-based hooks (§11.6) |
| 11 | `EPROCESS.Protection` sampler | Catches mid-life PPL elevation (§8.7) |
| 12 | `ci!g_CiOptions` periodic check | Catches DSE patching during session (§15.10) |
| 13 | Trustlet enumeration | Detects non-Microsoft IUM trustlets (§16.5) |
| 14 | PnP filter / WDF runtime cross-view | Catches non-SCM driver concealment (§15.8–§15.9) |
| 15 | Mitigation-policy sampler | Catches `ProcessDynamicCodePolicy` / CFG / shadow-stack weakening (§12.6) |
| 16 | DLL notification callback inventory | `LdrpDllNotificationList` walk (§11.13) |
| 17 | LSA Packages / Print Spooler / COM CLSID baseline auditors | Registry-driven trusted-process injection (§11.9–§11.11) |
| 18 | DLL provenance auditor | Sideload / proxy / search-order hijack (§11.12) |
| 19 | GPU resource sharing audit | `D3DKMT*` and shared-handle activity on game adapter (§16.4) |
| 20 | Storage stack filter inventory | Volume / partition / disk-class filter drivers (§15.12) |
| 21 | Service trigger inventory | Delayed-load drivers (§15.11) |
| 22 | Boot-driver ELAM ledger | Boot-start driver auditing (§15.13) |
| 23 | `Wow64Transition` / `xtajit64` integrity sampler | 32-bit and ARM64 emulator hooks (§13.4–§13.5) |
| 24 | Graphics-stack vtable / hook inventory | D3D / DXGI / Vulkan COM vtable integrity for the game's render pipeline (§11.16) |
| 25 | Game-framework / overlay allowlist auditor | ReShade / BepInEx / Discord overlay / Steam overlay signer + per-title policy (§11.15) |
| 26 | Window-hook inventory | `SetWindowsHookEx` / `SetWinEventHook` registered hook walker (§11.17) |
| 27 | Generalized trusted-process load-list audit | W32Time / NetSh / Search filter / DCOM Surrogate / etc. (§11.18) |
| 28 | WMI permanent-event-subscription monitor | `__EventFilter` / `__EventConsumer` / `__FilterToConsumerBinding` (§11.19) |
| 29 | Crash-dump / WER / AeDebug policy sampler | Forensic-suppression detection (§14.5) |

### 17.3 Source Trust Table

| Source | Description | Trust |
|--------|-------------|------:|
| `ApiNtQuery` | User-mode native API | Low |
| `ApiToolhelp` | Snapshot API | Low |
| `ETWProcess` | Kernel-process provider | Medium |
| `PsCallbackLedger` | Kernel create callbacks | Medium-High |
| `ActiveProcessLinks` | EPROCESS active list | Low-Medium |
| `PspCidTable` | PID/TID lookup | Medium |
| `HandleTable` | Object references | Medium |
| `KPRCBCurrentThread` | Currently executing thread | High |
| `ETHREADPool` | Thread object scan | High |
| `VAD` | Address-space ground truth | High |
| `KernelCallStack` | Stack at callback time | High |
| `PsLoadedModuleList` | Loaded kernel modules | Medium |
| `DriverObjectDirectory` | `\Driver` namespace | Medium |
| `DeviceObjectDirectory` | `\Device` namespace | Medium |
| `PiDDBCacheTable` | Prior-loaded-driver cache | Medium |
| `MmUnloadedDrivers` | Recent unload history | Medium |
| `CodeIntegrityEvents` | CI ETW signature/hash | High |
| `SCMEvents` | Driver service lifecycle | Medium-High |
| `KernelExecScan` | Executable kernel memory outside modules | High |
| `CallbackPointerInventory` | Callback/dispatch/timer/DPC attribution | High |
| `OfflineDump` | Crash dump replay | Very High |
| `BootAttestation` | TPM-anchored measured boot quote | Very High |

### 17.4 Race Discipline

| Mitigation | Description |
|------------|-------------|
| Re-sample | Two consecutive confirmations |
| Identity key | PID + create-time, not PID alone |
| Exit grace window | 1–2 s window for race-prone signals |
| Session-union sampling | KPRCB session-union prevents short-burst misses |
| Pool-scan low weight | Terminated-thread artifacts |
| Two-source minimum for block | High-confidence block requires independent sources |

### 17.5 Kernel-Side Stability Standards

| Constraint | Standard |
|------------|----------|
| IRQL | Pageable memory at `PASSIVE_LEVEL` or `APC_LEVEL` |
| Locking | Read-only snapshot preferred; never acquire undocumented locks blindly |
| Pointer validation | Canonical address, alignment, range, module-interval |
| List walk | Max-node count, visited set, head-return |
| Memory copy | SEH-safe or MDL/probe path |
| Symbol drift | Sanity-check on collect; degrade on failure |
| Performance | KPRCB sampling bounded, pool scan in idle windows |
| PatchGuard interaction | Never write/restore covered structures |
| Evidence form | Normalized keys / hashes / bitsets, not raw pointers |

---

## 18. Real-Time Rules and Scoring

### 18.1 Primary Rules

| Rule | Condition | Score |
|------|-----------|------:|
| `HiddenFromActiveList` | Present in KPRCB or ETHREAD, absent from active list | 5 |
| `CidMissingLiveThread` | Live `KPRCB`-running thread's TID lookup fails | 4 |
| `MultiListDkom` | Two or more of {active, CID, Ki, session, job, MM} disagree | 5 |
| `CallbackHealthFailed` | Self-check on any registered callback fails | 6 |
| `GamePrivateExec` | Game process has private executable VAD | 4 |
| `GameThreadOutsideImage` | Game thread sampled RIP outside any known module | 5 |
| `PebVadMismatch` | VAD image map present, PEB LDR entry absent | 3 |
| `MainImageHashMismatch` | Main-image memory hash != create-time file hash | 5 |
| `HerpaderpSequence` | Process start + executable overwrite by same parent | 5 |
| `GhostImage` | Process executes against delete-pending / missing backing file | 5 |
| `StrongHandleToGame` | Untrusted external PID holds strong handle to game | 3 |
| `VulnerableDriverLoaded` | Known LOLDrivers entry loaded | 5 |
| `KernelExecUnknown` | Executable kernel memory outside any loaded module | 7 |
| `PiDDBScrubSuspected` | CI / SCM / driver ledger has driver, PiDDB lacks it | 5 |
| `MmUnloadedScrubSuspected` | Unload event present, unload history empty | 4 |
| `CiCacheScrubSuspected` | CI event vs. cache vs. driver ledger diverge | 5 |
| `DriverObjectNoModule` | `DRIVER_OBJECT` present, no `KLDR` entry | 6 |
| `CallbackTargetUnknownKernelCode` | Callback / dispatch / timer / DPC target outside loaded modules | 7 |
| `WdFilterRuntimeListGap` | Defender state diverges from driver ledger | 3 |
| `ObserverReactivePause` | Cheat behavior correlated with TaskMgr / sensor start | 2 |
| `MasqueradeSystemName` | System-name process in user-writable path | 3 |
| `Cr3DeceptionSuspected` | Sampled CR3 != `EPROCESS.Pcb.DirectoryTableBase` | 6 |
| `KernelCallStackUnattributed` | Kernel callback's user-mode return address outside any module | 6 |
| `DirectSyscallAnomaly` | Syscall entry RIP not in `ntdll!Nt*` stub range | 4 |
| `PplProtectionTampered` | `EPROCESS.Protection` changed after process-create callback | 7 |
| `PicCallbackNonNull` | Game process `EPROCESS.InstrumentationCallback` non-NULL and target outside any module | 7 |
| `IfeoDebuggerSet` | `Image File Execution Options\<game>.exe\Debugger` populated | 8 |
| `AppInitDllsPresent` | `AppInit_DLLs` / `AppCertDlls` value non-empty | 4 |
| `CiOptionsLowered` | `ci!g_CiOptions` observed below boot-time value | 7 |
| `UnknownTrustletLaunched` | IUM trustlet running that is not Microsoft-signed allowlisted | 8 |
| `WorkingSetEvictionRace` | Suspect VAD region transitions to `PAGE_NOACCESS` within seconds of an external `MiniDumpWriteDump`-shaped open | 5 |
| `EtwEventWritePatched` | `ntdll!EtwEventWrite` prologue diverges from disk baseline | 4 |
| `AdsModuleLoaded` | Image load from `file:stream` named ADS path | 5 |
| `VssBackedImage` | Process image VAD's backing file resolves through a `HarddiskVolumeShadowCopy*` path | 6 |
| `PnpFilterUnsigned` | Non-WHQL driver listed in `UpperFilters`/`LowerFilters` on a device class | 5 |
| `LsaPackagesTampered` | `Lsa\Authentication Packages` / `Notification Packages` / `Security Packages` adds a non-Microsoft DLL | 8 |
| `PrintSpoolerExtensionUnsigned` | Non-Microsoft Print Provider / Monitor / Processor registered | 6 |
| `ComHijackHkcu` | `HKCU\Software\Classes\CLSID\{guid}\InProcServer32` shadowing an HKLM-resident CLSID | 5 |
| `DllSearchOrderHijack` | Microsoft-named DLL loaded from a non-system path into the game process | 6 |
| `DllProxyDetected` | DLL with export-forwarder pattern to `_orig`-suffixed twin loaded into game | 6 |
| `LdrDllNotificationCallback` | `LdrpDllNotificationList` entry targets private executable memory or untrusted module | 6 |
| `Wow64TransitionTampered` | 32-bit ntdll `Wow64Transition` pointer outside expected `wow64cpu.dll` range | 7 |
| `Arm64ecEmulatorTampered` | `xtajit64.dll` / `wowarmhw.dll` `.text` diverges from disk hash | 6 |
| `MitigationPolicyWeakened` | Mid-life weakening of `ProcessDynamicCodePolicy` / `ProcessSignaturePolicy` / `ProcessUserShadowStackPolicy` | 6 |
| `BootStartDriverUnsigned` | `SERVICE_BOOT_START` or `SERVICE_SYSTEM_START` driver lacks WHQL/Microsoft signer | 6 |
| `VolumeFilterUnsigned` | Non-allowlisted filter driver attached at volume / partition / disk class | 5 |
| `ServiceTriggerSuspect` | Non-Microsoft driver with `TriggerInfo` registration | 4 |
| `CetMsrDisabled` | `IA32_U_CET.SH_STK_EN` or `IA32_S_CET.SH_STK_EN` cleared during session | 6 |
| `GpuResourceShared` | Untrusted process holds `D3DKMT` adapter handle or shared resource on game's GPU | 5 |
| `UnsignedGameFramework` | ReShade / BepInEx / overlay framework injected unsigned or not on per-title allowlist | 6 |
| `D3DVtableHookOutsideAllowlist` | D3D / DXGI / Vulkan vtable entry pointing outside game image and not in allowlisted overlay | 6 |
| `GlobalWindowHookSuspect` | `WH_GETMESSAGE` / `WH_CALLWNDPROC` global hook with unsigned / user-writable hook DLL | 5 |
| `WmiPersistenceCreated` | New `__FilterToConsumerBinding` writing executable consumer | 7 |
| `CrashDumpPolicyTampered` | `CrashControl` registry or `AeDebug\Debugger` modified during session | 6 |
| `WerDisabled` | `WerSvc` stopped or `Windows Error Reporting\Disabled = 1` mid-session | 5 |
| `MiniDumpApiPatched` | `MiniDumpWriteDump` / `IoWriteCrashDump` prologue diverges from baseline | 6 |
| `DriverVerifierTampered` | `VerifyDrivers` reduced to exclude a non-Microsoft driver | 5 |
| `DirectStorageAnomaly` | DirectStorage activity from non-game-engine process on protected title | 4 |

### 18.2 Decision Bands

| Score | Action |
|------:|--------|
| 0–3 | Baseline noise; local log only |
| 4–6 | Suspicious; re-sample + server upload |
| 7–10 | High risk; block match entry, shadow review |
| 11+ | High confidence; immediate block + full evidence bundle |

### 18.3 Evidence Bundle

Minimum payload for ban / review:

- Process key (PID + create time + object pointer hash)
- Source-presence bitset
- Per-source mismatch detail
- Image path / file id / hash / signer
- VAD executable-region summary (small first-page hashes, not raw bytes)
- Thread start / current RIP provenance
- Handle owner / access mask history
- Callback health state
- Loaded-driver delta against trusted baseline
- PiDDB / `MmUnloadedDrivers` / CI / SCM / WdFilter delta
- HVCI / WDAC / Secure Boot / TPM state
- Kernel call-stack samples at relevant ETW callback firings

Privacy: full paths and command lines are hashed or tokenized per policy; sensitive user document paths are redacted; only the minimum byte hashes needed for evidence replay are collected.

---

## 19. Validation Scenarios

| Test | Goal | Expected detection |
|------|------|--------------------|
| User-mode API hook lab | API result filtering | API vs. kernel/ETW diff |
| PEB LDR unlink | Hidden DLL | VAD image map vs. PEB LDR diff |
| Manual-map DLL | Private exec payload | Private RX + thread hit |
| Process hollowing | Main image replacement | Create hash vs. live image mismatch |
| Process herpaderping | Post-section file overwrite | Process start + overwrite sequence |
| Process ghosting | Delete-pending image | Missing / delete-pending backing file |
| DKOM active unlink | `ActiveProcessLinks` removal | KPRCB / ETHREAD vs. active list |
| CID scrub | PID/TID lookup tamper | Live ETHREAD vs. lookup fail |
| Thread unlink | Process thread list removal | ETHREAD / KPRCB vs. thread list |
| Callback removal (EDRSandBlast-style) | Callback blinding | Callback self-check fail |
| BYOVD proxy | Vulnerable driver as broker | Known-vulnerable + device handle |
| PiDDB scrub simulator | Driver cache deletion | CI / SCM / file vs. PiDDB diff |
| `MmUnloadedDrivers` wipe | Unload trace deletion | Unload event vs. history gap |
| Manual-mapped driver | Hidden kernel code | Unknown executable kernel memory |
| Dispatch hijack | Normal driver object reuse | Dispatch pointer outside owner |
| VAD unlink simulator | Memory metadata hiding | RIP / PTE / working-set vs. VAD diff |
| CR3 deception lab | Address-space deception | Sampled CR3 vs. `EPROCESS` field |
| Observer-aware miner | TaskMgr reactivity | Process state correlation |
| Direct syscall canary | User-mode hook evasion | Direct vs. inline path diff |
| Call-stack spoofing | Return-address tradecraft | Sampled stack frame unattributable |
| Hypervisor-cloak simulator | EPT view split | Read vs. exec timing |
| PPL spoofing simulator | Self-elevate `EPROCESS.Protection` | Protection byte vs. create-time signer diff |
| PPL strip simulator | Lower a target's PPL (LSASS-style test) | Protection-byte change on a known-PPL service |
| Pico/minimal process simulator | Non-WSL `PsCreateMinimalProcess` | `Flags.Minimal` set with non-WSL parent |
| NTFS ADS payload lab | Image load from `file:stream` | ADS stream resolved at image-load callback |
| Object ID payload lab | Image load via `OpenFileById` | File id present, path absent |
| VSS-backed payload lab | Image load from shadow-copy path | Backing-file path matches VSS namespace |
| `ProcessInstrumentationCallback` lab | Set `EPROCESS.InstrumentationCallback` to private RX | Field non-NULL outside any module |
| Resource/overlay payload lab | Signed binary with `.rsrc`-embedded shellcode | Resource directory anomaly / overlay-after-cert |
| IFEO Debugger lab | `IFEO\<game>.exe\Debugger` populated | Registry-callback detection at process create |
| Working-set evasion lab | `PAGE_NOACCESS` toggle before MiniDump | Region protection change + dump-shape access pattern |
| `EtwEventWrite` patch lab | Inline prologue patch in target ntdll | `.text` hash diff against disk |
| Broker-pattern ETW patch lab | `WriteProcessMemory` against sibling ntdll | Cross-process write to ntdll `.text` |
| PnP filter injection lab | Inject driver via `UpperFilters` class key | Filter entry on device class, unsigned producer |
| WDF runtime gap lab | Manual-map a WDF-style driver | `PsLoadedModuleList` vs. WDF runtime list diff |
| DSE patch lab | Lower `ci!g_CiOptions` then load unsigned driver | g_CiOptions sampler catches the dip |
| Trustlet enumeration lab | Launch a self-signed IUM-shaped trustlet | Trustlet roster has non-Microsoft signer |
| LSA package registration lab | Add unsigned DLL to `Lsa\Notification Packages` | Registry-callback catches the write; lsass loaded-module audit catches the load |
| Print Spooler injection lab | `AddPrintProvider` with attacker DLL | Spooler-module audit catches non-Microsoft provider |
| COM hijack lab | Write `HKCU\Software\Classes\CLSID\{ms-clsid}\InProcServer32` redirect | HKCU CLSID shadowing baseline-HKLM CLSID |
| DLL sideload lab | Drop signed loader + same-named malicious DLL | Microsoft-named DLL loaded from user-writable path |
| DLL proxy lab | Replace a normally-loaded DLL with proxy + `_orig` twin | Export-forwarder fingerprint |
| `LdrRegisterDllNotification` abuse lab | Register a notification callback with private RX target | `LdrpDllNotificationList` walker flags it |
| `Wow64Transition` tamper lab | Overwrite 32-bit ntdll's `Wow64Transition` pointer | Per-process pointer check vs. expected `wow64cpu.dll` range |
| ARM64EC translator tamper lab | Patch `xtajit64.dll` `.text` | Hash diff against disk |
| Mitigation-policy weakening lab | `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` to off | Mid-life policy snapshot diff |
| Boot-start driver lab | Register an unsigned driver with `Start=1` | ELAM callback rejects / audits |
| Volume filter lab | Attach a filter at `\Device\HarddiskVolume0` | `IoEnumerateDeviceObjectList` of storage stack flags it |
| Service trigger lab | Register driver with custom ETW-event trigger | Service-trigger inventory + ETW correlation |
| CET disable lab | Clear `IA32_U_CET.SH_STK_EN` via BYOVD | Per-CPU MSR sample diff |
| GPU resource share lab | Open a shared D3D resource handle from outside the game | `D3DKMT*` caller audit flags the open |
| Game framework injection lab | Inject an unsigned ReShade / BepInEx variant | Framework allowlist match fails |
| D3D vtable hook lab | Patch `IDXGISwapChain::Present` vtable slot | Vtable integrity diff |
| Window hook injection lab | `SetWindowsHookEx(WH_GETMESSAGE)` with custom DLL | Hook inventory finds non-allowlisted DLL |
| WMI subscription lab | Create permanent event subscription with executable consumer | WMI subscription monitor catches the binding |
| Crash dump suppression lab | Set `CrashControl\CrashDumpEnabled = 0` | Policy sampler diff |
| `AeDebug\Debugger` hijack lab | Replace post-mortem debugger value | Same |
| Driver Verifier tamper lab | Lower `VerifyDriverLevel` on attacker driver | Verifier config baseline diff |
| DirectStorage anomaly lab | Spawn DirectStorage transfer from non-engine process on protected title | DirectStorage activity audit |

Safety principles:

- Production hosts are not test beds. Use test-signed VMs with snapshots.
- DKOM / driver-artifact scrub tests must be exercised through simulators or a controlled lab driver, never an actual BYOVD on production hardware.
- Maintain a crash matrix for PatchGuard / VBS / HVCI / Smart App Control combinations.
- New blocking rules go through an audit period before enforcement.

Validation tools:

- **WinDbg**: `!process`, `!thread`, `!handle`, `!vad`, `dt nt!_EPROCESS`
- **Volatility 3**: `windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.handles`, `windows.thrdscan`, `windows.malfind`, `windows.vadinfo`. (Note: psxview's pool-tag heuristic is unreliable on Win10 19H1+ — corroborate, don't rely.)
- **System Informer** / Process Hacker — hidden-process / handle observation
- **Sysmon / ETW** — process / image / file / driver telemetry
- **WDAC audit mode** — measure vulnerable-driver policy impact before enforcing
- **Custom replay harness** — event-ordering / race reproduction
- **EDR-vs-anti-cheat compatibility matrix** — coexistence with Defender / Elastic / CrowdStrike when running with HVCI on
- **WinDbg IUM commands** — `!process 0 0` (`SecureProcess` flag), `!vm` (secure-kernel memory split), `!skci` (secure-kernel code integrity state); `Get-CimInstance -ClassName Win32_DeviceGuard` for HVCI/VBS posture from PowerShell

---

## 20. Implementation Roadmap

### Phase 1 — Immediate ROI

1. Process / thread / image creation ledger.
2. Game-process handle monitor.
3. Callback self-check + decoy events.
4. Game-process executable VAD sampler.
5. User-mode API vs. ETW / kernel-callback diff (weak signal).
6. Driver-load inventory: hash, signer, vulnerable-list match (LOLDrivers).
7. `EPROCESS.Protection` snapshot at process create (PPL change detection, §8.7).
8. `EPROCESS.InstrumentationCallback` field check for game process (§11.6).
9. IFEO / `AppInit_DLLs` / `AppCertDlls` audit at game start (§11.8).
10. LSA `Authentication Packages` / `Notification Packages` / `Security Packages` baseline (§11.9).
11. Print Spooler Provider / Monitor / Processor baseline (§11.10).
12. HKCU `\Software\Classes\CLSID` shadow-of-HKLM monitor (§11.11).
13. Game-process mitigation-policy snapshot (§12.6).

### Phase 2 — Kernel cross-view

1. `ActiveProcessLinks` bidirectional walk + invariant check.
2. KPRCB current-thread sampling.
3. ETHREAD owner-process sampling.
4. CID lookup validation.
5. Handle / session / job / MM list diff.
6. Source-bitset suspicion scoring.

### Phase 3 — Memory identity

1. VAD vs. PEB LDR diff.
2. Main-image section / file / memory hash diff.
3. Private RX scoring.
4. Thread sampled-RIP attribution.
5. VAD-vs-PTE protection diff.
6. Module-stomping dirty-page detection.

### Phase 4 — BYOVD / platform

1. Known-vulnerable-driver blocklist (LOLDrivers + Microsoft + custom).
2. `PsLoadedModuleList` baseline interval tree.
3. Dispatch / callback / timer / DPC target attribution.
4. Unknown executable kernel-memory scan.
5. `PiDDBCacheTable` / `MmUnloadedDrivers` / CI / SCM / WdFilter cross-view.
6. WDAC / HVCI / Secure Boot / TPM state collection.
7. PnP `UpperFilters`/`LowerFilters` inventory and signer verification (§15.8).
8. WDF runtime list vs. `PsLoadedModuleList` cross-view (§15.9).
9. `ci!g_CiOptions` boot-time baseline and periodic sampling (§15.10).
10. EtwEventWrite / NtTraceEvent prologue integrity check (§14.3).
11. NTFS file-system payload primitives audit (ADS, Object IDs, VSS-backed images, §10.6).
12. Service trigger inventory (§15.11).
13. Volume / disk / partition filter inventory (§15.12).
14. Boot-start driver / ELAM ledger (§15.13).
15. Per-CPU CET MSR sampler (§13.3).
16. `Wow64Transition` integrity sampler for trusted 32-bit subprocesses (§13.4).
17. `xtajit64.dll` / `wowarmhw.dll` integrity sampler on Windows-on-ARM (§13.5).

### Phase 5 — Advanced

1. Sampled-CR3 validation.
2. Hypervisor / EPT / NPT deception heuristics.
3. DMA / IOMMU / device attestation.
4. Offline crash-dump replay and server-side correlation.
5. Call-stack provenance at kernel callback firings (Elastic-style).
6. Automated evidence minimization / redaction pipeline.
7. IUM trustlet enumeration and non-Microsoft signer detection (§16.5).
8. Working-set / dump-evasion behavioral detection (page-protection transitions correlated with snapshot-shaped opens, §12.5).
9. GPU / D3DKMT resource sharing audit on game adapter (§16.4).
10. DLL provenance auditor (sideload, search-order hijack, proxy detection) at game-process image-load callback (§11.12).
11. `LdrpDllNotificationList` walker at game-process startup and on demand (§11.13).
12. Game-framework / overlay allowlist auditor (§11.15) and D3D / DXGI / Vulkan vtable integrity sampler (§11.16) — particularly high game-anti-cheat ROI given that ESP / wallhack cheats commonly use these surfaces.
13. Window-hook inventory at game-create + WMI permanent-subscription monitor (§11.17, §11.19).
14. Crash-dump / WER / AeDebug policy sampler (§14.5).

### Recommended Sequence

For a new anti-cheat engineering effort, the most practical ordering is:

1. **Game-process internal execution hiding** — private RX, VAD/PEB diff, thread provenance.
2. **Kernel cross-view hidden process detection** — KPRCB / ETHREAD / active-list diff.
3. **Callback and self-protection** — verify the detection apparatus is still alive.
4. **Stealth-execution identity diff** — hollowing / herpaderping / ghosting.
5. **Platform attestation** — HVCI / WDAC / TPM / hypervisor / boot attestation.

This order reflects the empirical fact that real cheats have moved away from "a separate hidden process" toward "execution inside the game process" or "kernel helper driver." Pure DKOM-of-EPROCESS is mostly a 2010s memory; the modern threat is BYOVD chains and in-process tradecraft.

Block policies should fire only when independent sources agree: `KernelExecUnknown`, `CallbackTargetUnknownKernelCode`, `HiddenFromActiveList + CidMissingLiveThread`, `PiDDBScrubSuspected + CI/SCM evidence`. False positives on Windows 11 — especially with new platform features like Administrator Protection (24H2/25H2 isolated-admin-SID elevation), Smart App Control, and Windows Resiliency Initiative changes — will be the dominant operational cost.

---

## 21. Industry Context (2024–2026)

Two events frame the period this post is written in:

**CrowdStrike Falcon outage, 19 July 2024.** A faulty configuration channel file pushed to CrowdStrike's kernel-mode Falcon sensor caused approximately 8.5 million Windows endpoints worldwide to bugcheck simultaneously, grounding airlines, halting payment systems, and disrupting healthcare. The event triggered Microsoft's **Windows Resiliency Initiative**, announced at the Windows Security Summit on 12 September 2024, with the explicit goal of moving EDR vendors out of the kernel — the platform team is building new user-mode APIs (`Microsoft-Windows-EndpointSecurity` ETW family, secure-kernel-side telemetry surfaces, deeper PPL primitives) so that future EDR products can deliver kernel-equivalent telemetry without shipping kernel drivers.

For anti-cheat the implications are still unfolding. Microsoft's stated direction reduces kernel-driver attack surface — including the surface anti-cheat depends on. The industry response has been mixed: Riot Vanguard expanded its kernel driver footprint (rolling out to League of Legends in 2024 with TPM 2.0 + Secure Boot requirements on Windows 11), while Activision's Ricochet has invested more in server-side trickery ("Damage Shield" / "Hallucinations" — confusing telemetry returned to flagged players) than in kernel depth. Easy Anti-Cheat and BattlEye continue iterating on kernel telemetry, but the Linux client of EAC (used on Steam Deck via Proton) is user-mode only and notably weaker — a reminder that kernel privilege is a real defensive resource the platform may soon partially withdraw.

**The DMA-cheat shift.** The dominant tactical evolution of the past three years is not better kernel rootkits — it is the migration of high-end cheaters to PCIe DMA cards that put no code on the gaming PC at all. Every technique in this document deals with the gaming-PC side of the problem; the DMA case requires a fundamentally different defender posture, discussed in the [PCIe DMA cheats deep-dive](https://kernullist.github.io/kernullist-blog/posts/pcie-dma-cheats/). Anti-cheat investment patterns since 2023 reflect this: more telemetry, more behavior analytics, more server-side anomaly detection. Hiding detection on the host remains necessary baseline hygiene — but it is no longer where the marginal defensive dollar pays the highest return.

---

## 22. References

### Microsoft official documentation

| Reference | Topic |
|-----------|-------|
| [NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) | `SystemProcessInformation` enumeration |
| [Tool Help Functions](https://learn.microsoft.com/en-us/windows/win32/toolhelp/tool-help-functions) | Process/thread/module snapshot APIs |
| [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex) | Process create/delete callback |
| [PsSetCreateThreadNotifyRoutine](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine) | Thread create callback |
| [PsSetLoadImageNotifyRoutine](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine) | Image load callback |
| [ObRegisterCallbacks](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) | Process / thread object callbacks |
| [CmRegisterCallbackEx](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) | Registry callback |
| [PEB_LDR_DATA](https://learn.microsoft.com/en-us/windows/win32/api/Winternl/ns-winternl-peb_ldr_data) | Loaded module list |
| [Using process creation properties to catch evasion techniques](https://www.microsoft.com/en-us/security/blog/2022/06/30/using-process-creation-properties-to-catch-evasion-techniques/) | Doppelganging / herpaderping / ghosting |
| [Kernel Data Protection](https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/) | VBS-based kernel-data corruption defense |
| [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) | BYOVD defense, blocklist |
| [Code Integrity Event Log Messages](https://learn.microsoft.com/windows-hardware/drivers/install/code-integrity-event-log-messages) | CI signature/hash events |
| [Windows Driver Policy](https://support.microsoft.com/windows/the-windows-driver-policy-ecd2a78c-750c-415d-93f2-e37302ce0443) | WHCP / kernel trust |
| [Kernel DMA Protection](https://learn.microsoft.com/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt) | DMA defense |
| [Administrator Protection](https://techcommunity.microsoft.com/blog/windows-itpro-blog/administrator-protection-on-windows-11/4303482) | Win 11 24H2/25H2 isolated-admin elevation |
| [Windows Security Summit / Resiliency Initiative](https://blogs.windows.com/windowsexperience/2024/09/12/windows-security-summit/) | Post-CrowdStrike platform direction |
| [Windows 11 24H2 status](https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2) | 24H2 release and support |

### MITRE ATT&CK

| Reference | Topic |
|-----------|-------|
| [T1014 Rootkit](https://attack.mitre.org/techniques/T1014/) | Hiding / defense evasion |
| [T1055 Process Injection](https://attack.mitre.org/techniques/T1055/) | Injection taxonomy |
| [T1055.012 Process Hollowing](https://attack.mitre.org/techniques/T1055/012/) | Hollowing |
| [T1055.013 Process Doppelganging](https://attack.mitre.org/techniques/T1055/013/) | TxF-based stealth execution |
| [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) | BYOVD chain |

### Implementation, forensic, research

| Reference | Topic |
|-----------|-------|
| [Volatility 3 source](https://github.com/volatilityfoundation/volatility3) | Modern process plugins (psxview/psscan considerations) |
| [Process Hacker hidnproc.c](https://processhacker.sourceforge.io/doc/hidnproc_8c_source.html) | Hidden process implementation |
| [RAIDE BlackHat Europe 2006](https://www.blackhat.com/presentations/bh-europe-06/bh-eu-06-Silberman-Butler.pdf) | Historical: cross-view hidden process detection |
| [Elastic — Potential Process Herpaderping Attempt rule](https://www.elastic.co/guide/en/security/current/potential-process-herpaderping-attempt.html) | Process start + executable overwrite rule |
| [Elastic — Upping the Ante: Kernel Call Stacks](https://www.elastic.co/security-labs/upping-the-ante-detecting-in-memory-threats-with-kernel-call-stacks) | 2023 in-memory threat detection |
| [Elastic — Doubling Down: ETW Call Stacks](https://www.elastic.co/security-labs/doubling-down-etw-callstacks) | 2024 ETW-TI call-stack detection |
| [Sophos — AuKill EDR Killer Malware](https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/) | BYOVD case study |
| [Sophos — EDRKillShifter](https://news.sophos.com/en-us/2024/08/14/edrkillshifter/) | RansomHub-linked BYOVD loader |
| [KDMapper README](https://github.com/TheCruZ/kdmapper) | Mapper artifact-scrub coverage |
| [EDRSandBlast](https://github.com/wavestone-cdt/EDRSandBlast) | Callback removal + PspCidTable walking |
| [RealBlindingEDR](https://github.com/myzxcg/RealBlindingEDR) | Open-source callback zeroer |
| [LOLDrivers](https://www.loldrivers.io/) | Vulnerable / malicious driver inventory |
| [Exploring CI.dll and Bigpool Cache](https://hlunaaa.github.io/2025/04/18/Exploring-CI.dll-and-Bigpool-Cache.html) | CI cache, big pool, mapper artifacts |
| [HookMap — Microsoft Research](https://www.microsoft.com/en-us/research/publication/countering-persistent-kernel-rootkits-through-systematic-hook-discovery/) | Systematic kernel-hook surface discovery |
| [ETW-TI manifest](https://github.com/jdu2600/Windows10EtwEvents/blob/master/manifest/Microsoft-Windows-Threat-Intelligence.tsv) | Threat Intelligence event catalog |
| [RootkitRevealer](https://learn.microsoft.com/en-us/sysinternals/downloads/rootkit-revealer) | Original cross-view API/raw diff |
| [PPLdump (itm4n)](https://github.com/itm4n/PPLdump) | PPL bypass via known-vulnerable driver |
| [Hijacking Instrumentation Callbacks (Adam Chester / SpecterOps)](https://posts.specterops.io/hijacking-the-process-instrumentation-callback-31407097ff8d) | `ProcessInstrumentationCallback` weaponization |
| [ThreadlessInject (CCob)](https://github.com/CCob/ThreadlessInject) | Threadless injection via remote export hook |
| [HyperDeceit](https://github.com/Xyrem/HyperDeceit) | Hypervisor-based memory view splitting |
| [Microsoft PssCaptureSnapshot](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot) | Process Snapshotting API (ProcessReflection) |
| [Process Herpaderping (Jonas Lykkegaard, 2020)](https://github.com/jxy-s/herpaderping) | Original herpaderping research |
| [Process Ghosting (Gabriel Landau, 2021)](https://www.elastic.co/security-labs/process-ghosting) | Original ghosting research |
| [SilentMoonwalk (klezVirus / namazso)](https://github.com/klezVirus/SilentMoonwalk) | Call-stack spoofing reference |
| [System-Defined Device Setup Classes](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/system-defined-device-setup-classes-available-to-vendors) | PnP class GUIDs for filter-driver detection |
| [Reverse-Engineering the Isolated User Mode (Alex Ionescu, REcon 2015)](https://www.alex-ionescu.com/blackhat2015.pdf) | Original IUM/Trustlet architecture |
| [Attacking the VM Worker Process (Saar Amar / Daniel King, 2019)](https://www.youtube.com/watch?v=g_qoQQrYK4o) | Secure-kernel / IUM attack surface |
| [HyperGuard — Secure Kernel Patch Guard (Connor McGarr, 2022)](https://connormcgarr.github.io/hyperguard-research-pt-1/) | HyperGuard internals |
| [PrintNightmare CVE-2021-34527 advisory](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) | Print Spooler RCE / DLL load |
| [Spartacus — DLL hijacking discovery (Pavel Tsakalidis)](https://github.com/Accenture/Spartacus) | DLL proxy / sideload tooling |
| [ARM64EC ABI overview (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/arm/arm64ec-abi) | ARM64EC / `xtajit64.dll` reference |
| [Early Launch Anti-Malware (ELAM) drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware) | ELAM driver class and policy |
| [Process Mitigation Policy reference](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy) | All `ProcessMitigationPolicy*` flags |
| [Mimikatz `memssp` source](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_misc.c) | LSA Security Package injection reference |
| [Intel CET — Programming Reference (Vol. 1, Chapter 18)](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/cet.html) | CET MSRs and shadow-stack architecture |
| [WoW64 Internals (Wikipedia / Geoff Chappell)](https://www.geoffchappell.com/studies/windows/win32/wow64/index.htm) | `Wow64Transition`, `wow64cpu.dll` semantics |
| [ReShade](https://github.com/crosire/reshade) | Reference D3D/Vulkan post-processing injector |
| [BepInEx](https://github.com/BepInEx/BepInEx) | Unity / IL2CPP injection framework |
| [Detecting WMI Persistence (FireEye / Mandiant)](https://www.mandiant.com/resources/blog/wmi-vs-wmi-monitoring-malicious-wmi) | WMI permanent event subscription detection |
| [Sysmon Event IDs 19/20/21](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | WMI create/modify/delete telemetry |
| [Microsoft DirectStorage overview](https://devblogs.microsoft.com/directx/directstorage-developer-preview-now-available/) | NVMe → GPU direct transfer architecture |
| [CrashControl registry reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options) | Crash-dump configuration values |
| [SetWindowsHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw) | Hook injection reference |
| [Driver Verifier flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier) | `VerifyDrivers` / `VerifyDriverLevel` semantics |

---

**End of document.**
