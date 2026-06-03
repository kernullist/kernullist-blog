---
title: "About ETW Internals: Architecture, Hooking, Tampering, and Detection"
date: 2026-06-03 00:00:00 +0900
categories: [Windows Internals, Anti-Cheat]
tags: [etw, etwti, windows-internals, anti-cheat, edr, kernel, infinityhook, dkom, tracelogging, windbg, forensics, tdh, byovd, windows]
---

> Event Tracing for Windows is the telemetry fabric behind a large part of modern Windows security work. EDRs, anti-cheats, forensic tools, WPR, Sysmon-adjacent pipelines, and many Microsoft components all lean on it. Attackers know that too, so ETW ends up being both a signal source and a target. This post walks through ETW from the inside: how providers reach sessions, where buffers and enable slots live, which parts are public API, which parts are private kernel state, and where tampering actually changes what a defender sees. The reference target is Windows 11 25H2 (ntoskrnl 10.0.26200.x) with 24H2 deltas called out. 26H1 (10.0.28000.x) is public in Microsoft's May 2026 release table as a scoped new-device release, but private structure claims here still require symbols and live validation for the exact target.

The shape follows the PCIe DMA walkthrough: start with the threat model, go down into the machinery, then come back up into detection architecture. The point is not to memorize every field. The point is to know which layer should carry truth when another layer starts lying.

## 1. Threat Model

An ETW attack in this document is any attempt to make a meaningful Windows action disappear from one or more telemetry views that a defender controls. The action might be process creation, image load, thread context manipulation, executable-memory allocation, LSASS memory read, driver load, RPC activity, AMSI scan, or a provider's own self-telemetry. The observer might be a real-time ETW consumer, an AutoLogger ETL file, Sysmon, an EDR service, a kernel callback ledger, a WinDbg live session, or an offline memory dump. The attacker has succeeded if the operation still happens, but every meaningful consumer in the defender's pipeline either receives no event, receives a filtered event, or receives an event whose context is no longer trustworthy.

Every Windows process or driver that does something interesting eventually crosses an ETW boundary. A process creation passes through `Microsoft-Windows-Kernel-Process`, a remote-thread injection passes through `Microsoft-Windows-Threat-Intelligence` (ETWTI), an LSASS handle acquisition passes through `Microsoft-Windows-Kernel-Audit-API-Calls`, a PowerShell script block compiles through `Microsoft-Windows-PowerShell` event 4104, and the scheduler emits context-switch events into the Circular Kernel Context Logger on every transition. This is why every commercial EDR is, structurally, an ETW consumer plus a kernel-callback ledger plus a few targeted memory scans. It is also why every kernel-mode cheat or post-exploitation toolkit eventually answers the same question: how do I make this loader's work not appear on the consumer's side?

Four observations shape the rest of this document:

1. **ETW is a router, not a log file.** The high-value state lives in provider registrations, enable slots, session buffers, consumer objects, filters, AutoLogger registry state, and per-silo driver state. An `.etl` is only one possible output of that routing fabric.
2. **The fast path is small enough to corrupt with byte writes.** Each `ETW_REG_ENTRY` carries an `EnableMask`, and each `ETW_GUID_ENTRY` carries `ProviderEnableInfo.IsEnabled` plus up to eight `EnableInfo[]` slots. Clearing one byte or one `ULONG` can silence a provider for a session without stopping the session itself.
3. **Kernel-originated ETW is qualitatively different from user-mode ETW.** Patching `ntdll!EtwEventWrite` can blind PowerShell inside one process. It does not blind `Microsoft-Windows-Kernel-Process` or ETWTI, because those events originate inside the kernel paths that perform the work.
4. **The consumer path is part of the security boundary.** A provider can be enabled and still useless if `WMI_LOGGER_CONTEXT.AcceptNewEvents`, buffer queues, real-time consumers, filters, or loss counters are corrupted. Provider integrity without delivery integrity is not enough.

Strong signals recur throughout this document:

| Signal | Implication |
|--------|-------------|
| ETWTI provider handle is `NULL`, or `ProviderEnableInfo.IsEnabled` unexpectedly drops | Kernel DKOM against the security provider path |
| Provider enable state is intact, but the expected canary event never reaches the consumer | Session / consumer / delivery-path tampering |
| `Microsoft-Windows-Kernel-EventTracing` stops reporting session changes while other activity continues | Meta-provider was disabled before tampering |
| ETWTI memory events exist, but user-mode syscall telemetry reports different arguments | Argument-spoofing or post-syscall user-mode deception |
| Real-time loss counters climb during a narrow suspicious window | Buffer exhaustion, slow consumer, or deliberate flood |
| Hidden TraceLogging provider appears in live registration but not in the manifest registry | Runtime provider, randomized provider, or undocumented Windows telemetry surface |

The defender's decision procedure is the same cross-view inequality used throughout the Windows hiding post:

```text
EtwTamperCandidate =
    ExpectedActivityObservedByStrongSource
    AND MissingOrContradictoryOnEtwPath
    AND NoLifecycleExplanation
```

Concretely:

```text
KernelCallbackLedger shows remote VM write
AND ETWTI remote-write event is absent
AND ETWTI provider/session/canary health changed in the same window
```

That is the article's working model. Naming an event is easy. Proving which layer lied is the real work.

Build discipline matters because ETW's public API surface is stable while the private kernel layouts drift. As of **2026-06-03 KST**, Microsoft's Windows 11 release table lists 25H2 as version `26200` and 24H2 as `26100`, both serviced through the May 2026 security update (`26200.8457` / `26100.8457`) and the May 26, 2026 preview update (`26200.8524` / `26100.8524`). Microsoft also lists 26H1 as version `28000` (`28000.2179` in the May 26, 2026 table), while the Windows SDK page lists the latest Windows SDK as `10.0.28000`. Microsoft's release page explicitly scopes 26H1 to new devices coming to market in early 2026 and says it is not offered as an in-place update from 24H2 or 25H2 on existing devices. The live verification host used for this review is 25H2 build `26200.8524` with SDK `10.0.26100.0` installed locally, so 25H2 remains the practical broad-client baseline; 26H1 is public, but private ETW layout claims still need target-specific symbols before they become engineering facts.

Operationally, that produces three rules:

1. **Use 25H2 public symbols as the current broad-client baseline.** Vergilius' 25H2 views show `_WMI_LOGGER_CONTEXT` at `0x650`, `_ETW_SILODRIVERSTATE` at `0x1238`, `_ETW_GUID_ENTRY` at `0x1a8`, and `_ETW_REG_ENTRY` at `0x70`, matching the 24H2 public layouts for the fields this document uses.
2. **Use the 26100/28000 SDK headers for API constants, not kernel offsets.** `evntrace.h`, `evntprov.h`, and `evntcons.h` define filter constants, `TraceQueryInformation` classes, system-provider GUIDs, context-register tracing, and compression flags. They do not define private kernel layouts. If your build box only has the 26100 SDK, do not infer that 28000-era controller classes or provider GUIDs are absent from the target OS; query the target and build against the SDK you actually ship.
3. **Resolve before shipping.** Production drivers, WinDbg scripts, memory scanners, and SOC parsers should resolve offsets and metadata against the target image: PDB/DIA for private structures, `TraceMaxLoggersQuery` for session capacity, `TraceStreamCount` for stream topology, `logman query providers` / `wevtutil gp` / manifest or TraceLogging metadata diffing for event metadata, and live kernel inspection for undocumented hardening such as KDP-protected ranges.

---

## 2. The ETW Topology

Four entity roles describe everything ETW does. A **provider** generates events, identified by a 128-bit GUID. A **session** (also called a logger) owns a buffer pool and a flushing thread, identified by a small integer slot (0..MaxLoggers-1). A **consumer** reads from a session, either by attaching to its real-time queue or by reading the `.etl` file the session flushes to disk. A **controller** starts and stops sessions and binds providers to them by calling `EnableTraceEx2`. The fourth role is invisible to most readers because the controller is usually `logman`, `wpr`, an EDR service, or `xperf`. It is the only entity that ever writes to `ETW_GUID_ENTRY.EnableInfo[]`, which is the field that turns events on.

Providers and sessions are connected through enable records, not by a permanent provider-to-consumer object. A modern provider has up to eight `TRACE_ENABLE_INFO` slots inside its `ETW_GUID_ENTRY`. Each slot, if `IsEnabled` is non-zero, names one logger session and the keyword/level/filter state that session imposed. At event-write time, the provider walks the eight slots, filters per slot, and writes one copy into each matching session's stream buffers. The important property is not "zero copies"; it is bounded fanout. One provider can feed several sessions, but the hot path never has to walk an unbounded subscriber list.

```text
┌────────────────────────────────── USER MODE ────────────────────────────────┐
│   Provider              Controller              Consumer                    │
│   EventWrite            StartTrace              OpenTrace / ProcessTrace    │
│       │                 EnableTraceEx2                  │                   │
│       │ NtTraceEvent           │ NtTraceControl         │ NtOpenFile        │
└───────┼──────────────────────┼─────────────────────────┼───────────────────┘
        │                      │                         │
─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─
        ▼                      ▼                         │
┌────────────────────────────── KERNEL ───────────────────────────────────────┐
│  ntoskrnl ETW subsystem                                                     │
│    ETW_SILODRIVERSTATE     (PspHostSiloGlobals->EtwSiloState)                │
│      ├─ EtwpLoggerContext[MaxLoggers]  -> WMI_LOGGER_CONTEXT                 │
│      ├─ EtwpGuidHashTable[64]          -> ETW_GUID_ENTRY                     │
│      ├─ EtwpSecurityLoggers[8]                                              │
│      └─ EtwpCounters                                                        │
│                                                                             │
│    Per-CPU buffer pool  (WMI_BUFFER_HEADER + payloads)                      │
│    Per-session Logger Thread (flushes to .etl or to real-time consumer)     │
│                                                                             │
│  Kernel-mode providers                                                      │
│    EtwRegister -> ETW_REG_ENTRY linked into ETW_GUID_ENTRY.RegListHead       │
│    EtwWrite    -> reserves space in per-CPU buffer and emits event           │
└─────────────────────────────────────────────────────────────────────────────┘
```

Two surfaces in this picture are load-bearing for the rest of the document:

- **`PspHostSiloGlobals->EtwSiloState`** is the entry point. Every other ETW kernel object is reached by walking from there. On a container-aware kernel it is one of several `EtwSiloState` instances; the *host silo* is the default.
- **`EtwpGuidHashTable[64]`** indexes every provider in the system by GUID. Each bucket is an `ETW_HASH_BUCKET` whose `ListHead[0..2]` lists hold the three GUID types (trace, notification, group). Discovering "every ETW provider currently registered, including TraceLogging providers that have no manifest" reduces to walking these three lists across 64 buckets.

The kernel ETW initialization itself runs in two phases. `EtwpInitialize(0)` registers a small set of core providers (around 15, including ETWTI) and resolves Global Logger configuration; `EtwpInitialize(1)` starts CKCL, runs AutoLogger from the registry, and finishes registering kernel providers. By the time the first non-boot driver loads, the entire ETW topology is already up. That is also why early-boot rootkits can interpose between phase 0 and phase 1 if Secure Boot / ELAM are not enforced.

---

## 3. The Kernel Data Structures

The structures below are the smallest set that lets you write either a detection module or a credible exploitation primitive. Field offsets *drift* across Windows builds, sometimes within a single feature update, so production code must resolve them at runtime via Vergilius/PDB or by anchoring to a stable signature. The annotations are Windows 11 25H2 x64; the 24H2 public layouts match for the fields called out here.

### 3.1 ETW_SILODRIVERSTATE

```c
struct _ETW_SILODRIVERSTATE {
    PEJOB                        Silo;                            // +0x000
    PESERVER_SILO_GLOBALS        SiloGlobals;                     // +0x008
    ULONG                        MaxLoggers;                      // +0x010  // typically 0x50 (80)
    ETW_GUID_ENTRY               EtwpSecurityProviderGuidEntry;   // +0x018
    PEX_RUNDOWN_REF_CACHE_AWARE* EtwpLoggerRundown;               // +0x1C0
    PWMI_LOGGER_CONTEXT*         EtwpLoggerContext;               // +0x1C8  // array of size MaxLoggers
    ETW_HASH_BUCKET              EtwpGuidHashTable[64];           // +0x1D0
    USHORT                       EtwpSecurityLoggers[8];          // +0xFD0
    UCHAR                        EtwpSecurityProviderEnableMask;  // +0xFE0
    LONG                         EtwpShutdownInProgress;          // +0xFE4
    ULONG                        EtwpSecurityProviderPID;         // +0xFE8
    ETW_PRIV_HANDLE_DEMUX_TABLE  PrivHandleDemuxTable;            // +0xFF0
    PWCHAR                       RTBacklogFileRoot;               // +0x1010
    ETW_COUNTERS                 EtwpCounters;                    // +0x1018
    LARGE_INTEGER                LogfileBytesWritten;             // +0x1028
    PETW_SILO_TRACING_BLOCK      ProcessorBlocks;                 // +0x1030
    ETW_SYSTEM_LOGGER_SETTINGS   SystemLoggerSettings;            // +0x1088
    KMUTANT                      EtwpStartTraceMutex;             // +0x1200
};
```

`EtwpLoggerContext` is a pointer array, not an embedded array. Unused slots are not `NULL`. They are often observed as `(PWMI_LOGGER_CONTEXT)0x1`, a sentinel chosen so that a partial DKOM that zeroes a slot becomes visually distinguishable in dumps. Verification predicate: `p != 0 && p != 1`. `MaxLoggers` is the array length; prior to Windows 10 1709 the non-private logger cap was a fixed 64, while modern Windows exposes the current cap through `TraceQueryInformation(..., TraceMaxLoggersQuery, ...)` and can raise it through `HKLM\SYSTEM\CurrentControlSet\Control\WMI\EtwMaxLoggers`.

### 3.2 WMI_LOGGER_CONTEXT

The per-session control structure. About `0x650` bytes on 25H2 and 24H2. The fields below are the ones that matter for either implementing a session or attacking one.

```c
struct _WMI_LOGGER_CONTEXT {
    ULONG          LoggerId;             // 0..MaxLoggers-1
    ULONG          BufferSize;           // per-buffer size; default 64 KiB
    ULONG          MaximumEventSize;
    ULONG          LoggerMode;           // EVENT_TRACE_*_MODE flags
    LONG           AcceptNewEvents;      // 0 -> events refused
    ULONGLONG      GetCpuClock;          // old branches: function ptr;
                                         // modern branches: clock-source index
    PETHREAD       LoggerThread;         // flusher
    LONG           LoggerStatus;
    ULONG          FailureReason;
    ETW_BUFFER_QUEUE BufferQueue;        // file-mode flush queue
    ETW_BUFFER_QUEUE OverflowQueue;
    EX_FAST_REF    CurrentBuffer;        // active stream buffer fast ref
    LIST_ENTRY     GlobalList;
    UNICODE_STRING LoggerName;
    UNICODE_STRING LogFileName;
    ULONG          ClockType;
    ULONG          FlushTimer;
    ULONG          MinimumBuffers;
    volatile LONG  NumberOfBuffers;
    ULONG          MaximumBuffers;
    ULONG          EventsLost;           // monotonic loss counter
    LIST_ENTRY     Consumers;            // ETW_REALTIME_CONSUMER list
    ULONG          Flags;                // includes RealTime, SecurityTrace,
                                         // StackTracing, BootLogger, etc.
    ETW_STACK_TRACE_BLOCK StackTraceBlock;
    WMI_BUFFER_HEADER** ScratchArray;
    ETW_SILODRIVERSTATE* SiloState;
    LONG           CompressionOn;
};
```

This is intentionally a reduced field list, but the names above are aligned with the 25H2 public type information. Older drafts of this material often show a `BufferTable[]` member or a standalone `SecurityTrace` field; that is misleading for modern Windows. Stream state is reached through the current/batched buffer machinery plus per-silo processor tracing blocks, and `SecurityTrace` is a bit in `Flags` (`WMI_LOGGER_CONTEXT.Flags.SecurityTrace` in public type views), not a separate `USHORT`.

`GetCpuClock` is the single most consequential field for offensive research. On older branches it held a function pointer; rewriting it (with the system trace logger or CKCL targeted) gave control on every event write, which InfinityHook turned into a syscall hook. On modern branches the field is a clock-source selector rather than an arbitrary function pointer. Public 24H2 reversing shows selector values for system time, QPC, HAL host-performance-counter, and raw TSC paths; exact dispatch details should be resolved against the target PDB. The important defensive point is narrower than older drafts of this article implied: writing an attacker-controlled kernel pointer into `GetCpuClock` no longer yields a callable hook, but forcing the selector into a branch that reaches a mutable downstream HAL timer callback can still produce an InfinityHook-style hot-path hook (§10).

### 3.3 ETW_GUID_ENTRY

```c
struct _ETW_GUID_ENTRY {
    LIST_ENTRY        GuidList;              // bucket linkage in EtwpGuidHashTable
    LIST_ENTRY        SiloGuidList;          // all GUIDs in this silo
    volatile LONGLONG RefCount;
    GUID              Guid;
    LIST_ENTRY        RegListHead;           // ETW_REG_ENTRY list - every registration
    PVOID             SecurityDescriptor;
    union { ETW_LAST_ENABLE_INFO LastEnable; ULONGLONG MatchId; };
    TRACE_ENABLE_INFO ProviderEnableInfo;    // aggregate enable (the "is any session live?" bit)
    TRACE_ENABLE_INFO EnableInfo[8];         // per-session enable; up to 8 sessions
    PETW_FILTER_HEADER FilterData;
    PETW_SILODRIVERSTATE SiloState;
    PETW_GUID_ENTRY    HostEntry;            // points to host-silo entry from a container
    EX_PUSH_LOCK      Lock;
    PETHREAD          LockOwner;
};
```

The two enable fields above are the controller-visible state that changes during `EnableTraceEx2` and AutoLogger enablement. They are also the smallest possible offensive surface: zeroing `ProviderEnableInfo.IsEnabled` disables the aggregate provider path; zeroing one `EnableInfo[i].IsEnabled` slot disables a specific logger; downgrading `Level` or replacing `MatchAnyKeyword` with a keyword bit that the provider never emits can starve a session. Do **not** describe `MatchAnyKeyword = 0` as a blocking write: in ETW keyword semantics, a zero `MatchAnyKeyword` usually means "match all keywords", so blindly zeroing it widens rather than narrows delivery.

### 3.4 ETW_REG_ENTRY

```c
struct _ETW_REG_ENTRY {
    LIST_ENTRY        RegList;                  // GuidEntry->RegListHead linkage
    LIST_ENTRY        GroupRegList;             // GroupEntry->RegListHead linkage
    PETW_GUID_ENTRY   GuidEntry;                // owning provider GUID entry
    PETW_GUID_ENTRY   GroupEntry;               // group GUID (NULL if not grouped)
    union {
        PETW_REPLY_QUEUE  ReplyQueue;
        PETW_QUEUE_ENTRY  ReplySlot[4];
        struct { PVOID Caller; ULONG SessionId; };
    };
    union { PEPROCESS Process; PVOID CallbackContext; };
    PVOID             Callback;                 // Enable callback function pointer
    USHORT            Index;
    union {
        USHORT Flags;
        struct {
            USHORT DbgKernelRegistration:1;
            USHORT DbgUserRegistration:1;
            USHORT DbgReplyRegistration:1;
            USHORT DbgClassicRegistration:1;
            USHORT DbgSessionSpaceRegistration:1;
            USHORT DbgModernRegistration:1;     // Manifest/TraceLogging
            USHORT DbgClosed:1;
            USHORT DbgInserted:1;
            USHORT DbgWow64:1;
            USHORT DbgUseDescriptorType:1;
            USHORT DbgDropProviderTraits:1;
        };
    };
    UCHAR             EnableMask;               // per-session enable bits (8 bits)
    UCHAR             GroupEnableMask;          // group enable
    UCHAR             HostEnableMask;
    UCHAR             HostGroupEnableMask;
    PETW_PROVIDER_TRAITS Traits;                // TraceLogging metadata
};
```

A REGHANDLE returned by `EtwRegister` (kernel) or `EventRegister` (user-mode) is an encoded pointer to one of these. Lazarus's *FudModule*, the canonical kernel-ETW killing rootkit, scans `nt!.text` for `nt!EtwRegister` call sites, walks back to the `EtwRegister` argument that stores the resulting handle into a global, follows the global to its `.data` location, and zeroes the global. The result: `EtwTi*` log calls hit a `NULL` registration handle, take the dead-code early-return path, and silently drop the event. The same idea generalizes to any kernel provider whose registration handle lives in writable kernel memory.

### 3.5 TRACE_ENABLE_INFO

```c
struct _TRACE_ENABLE_INFO {
    ULONG     IsEnabled;        // 0 / 1
    UCHAR     Level;            // 1 (CRITICAL) ... 5 (VERBOSE)
    UCHAR     Reserved1;
    USHORT    LoggerId;         // session slot
    ULONG     EnableProperty;   // EVENT_ENABLE_PROPERTY_*
    ULONG     Reserved2;
    ULONGLONG MatchAnyKeyword;  // OR mask (event passes if any bit overlaps; 0 = pass all)
    ULONGLONG MatchAllKeyword;  // AND mask (event must have all these bits set; 0 = no constraint)
};
```

The common modern-provider filter test is conceptually:

```c
event_match = enable.IsEnabled
   && event.Level <= enable.Level
   && (enable.MatchAnyKeyword == 0 || (event.Keyword & enable.MatchAnyKeyword))
   && ((event.Keyword & enable.MatchAllKeyword) == enable.MatchAllKeyword);
```

Level filtering has one important edge case: event level `0` is `win:LogAlways`. Many events use levels 1..5 and will be excluded if the enable level is forced to 0, but `Level = 0` is not a universal "off" switch. For tamper detection, treat unexpected level downgrade as suspicious, but use `IsEnabled`, `EnableMask`, and the exact keyword masks as the authoritative state.

### 3.6 ETW_REALTIME_CONSUMER

A real-time consumer creates a kernel object of type `EtwConsumer` in the consumer process's handle table; the backing structure lives on the session's `Consumers` list:

```c
struct _ETW_REALTIME_CONSUMER {
    LIST_ENTRY  Links;          // WMI_LOGGER_CONTEXT.Consumers
    PVOID       ProcessHandle;
    PEPROCESS   ProcessObject;  // consuming process
    PVOID       NextNotDelivered;
    PVOID       RealtimeConnectContext;
    PKEVENT     DisconnectEvent;
    PKEVENT     DataAvailableEvent;
    ULONG*      UserBufferCount;
    SINGLE_LIST_ENTRY* UserBufferListHead;
    ULONG       BuffersLost;
    ULONG       EmptyBuffersCount;
    USHORT      LoggerId;
    UCHAR       Flags;          // disconnected / notified / WOW64 etc.
    ULONG*      EventsLostCount;
    ULONG*      BuffersLostCount;
    ETW_SILODRIVERSTATE* SiloState;
};
```

Walking `EtwpLoggerContext[i]->Consumers` enumerates every live real-time subscriber of session `i`. This is how you find out, from a kernel debugger, *which* user-mode process is reading from CKCL or from your ETWTI session. The same walk also shows an attacker enumerates the EDR's consumer process before deciding what to suspend.

### 3.7 ETW_COUNTERS - What It Is *Not*

`ETW_SILODRIVERSTATE.EtwpCounters` (offset `+0x1018` on Win11 25H2/24H2) is often misdescribed as a system-wide event-loss counter block. It is not. The 25H2 public type is:

```c
struct _ETW_COUNTERS {
    LONG GuidCount;
    LONG PoolUsage[2];
    LONG SessionCount;
};
```

Use it for coarse topology sanity checks, not throughput health. Event loss and delivery health live on the session, exposed through both public `EVENT_TRACE_PROPERTIES` query output (`EventsLost`, `LogBuffersLost`, `RealTimeBuffersLost`, `NumberOfBuffers`, `FreeBuffers`) and internal `WMI_LOGGER_CONTEXT` fields (`EventsLost`, `LogBuffersLost`, `RealTimeBuffersLost`, `BuffersWritten`). A practical health monitor samples each session with `ControlTrace(..., EVENT_TRACE_CONTROL_QUERY, ...)` and only falls back to kernel fields when a live debugger or driver already has trusted offsets.

### 3.8 EVENT_TRACE_PROPERTIES and WNODE_HEADER

The user-mode side of any session-control call (`StartTrace`, `ControlTrace`, `TraceSetInformation`) passes an `EVENT_TRACE_PROPERTIES` (or its V2 variant) whose first member is the legacy `WNODE_HEADER`. The header is a vestige of the original WMI Trace infrastructure that ETW replaced, but the layout is still load-bearing for kernel-side parsing:

```c
typedef struct _WNODE_HEADER {
    ULONG          BufferSize;            // total size of the properties block
    ULONG          ProviderId;            // legacy MOF source identifier
    union {
        ULONG64    HistoricalContext;     // TRACEHANDLE for control operations
        struct {
            ULONG  Version;
            ULONG  Linkage;
        };
    };
    union {
        HANDLE        KernelHandle;
        LARGE_INTEGER TimeStamp;
    };
    GUID           Guid;                  // session GUID (or system trace control GUID)
    ULONG          ClientContext;         // clock type (1=QPC, 2=SystemTime, 3=CPU cycle)
    ULONG          Flags;                 // WNODE_FLAG_* (e.g. WNODE_FLAG_TRACED_GUID,
                                          // WNODE_FLAG_VERSIONED_PROPERTIES for V2)
} WNODE_HEADER, *PWNODE_HEADER;
```

Two practical points: (1) `BufferSize` is checked at every call and must include the trailing logger-name / log-file-name UTF-16 strings, which is the single most common reason `StartTrace` returns `ERROR_BAD_LENGTH` for hand-rolled code; (2) `WNODE_FLAG_VERSIONED_PROPERTIES` toggles V2 mode and is the prerequisite for `EVENT_TRACE_PROPERTIES_V2.FilterDescCount` / `FilterDesc` / `V2Options`, including system-wide private logger PID or executable-name filters described in §14.6.

### 3.9 Container Awareness - Silo Isolation

Windows 10's introduction of *server silos* (the OS-level container primitive that backs `docker run` on Windows hosts) made ETW silo-aware. The result is that there is no single global ETW state. There are *N* `ETW_SILODRIVERSTATE` instances, one per silo, with the *host silo* (`PspHostSiloGlobals`) being the default. A process in a container has its own `EtwpLoggerContext`, its own `EtwpGuidHashTable`, and its own provider registrations. Container-internal events do not cross the silo boundary unless the host explicitly subscribes through the container's silo state.

The relevant bridge field is `ETW_GUID_ENTRY.HostEntry`. When the same provider is registered in both the host silo and a container silo, the container's entry points back to the host's via `HostEntry`, allowing the kernel to hierarchically route events that the host has subscribed to even when they originate inside a container. The forensic consequence is that incident analysis on a containerized workload must walk the silo's `EtwSiloState` rather than `PspHostSiloGlobals`. A container-escape attacker who reaches kernel mode can read or tamper with the *host's* ETW state, which is one of the strongest reasons that container-host separation requires HVCI to be credible.

The same `EtwSiloState` plumbing also propagates `EVENT_HEADER_EXT_TYPE_CONTAINER_ID` extended items onto events emitted from inside a container, so a host-side consumer can attribute every event to its originating container.

### 3.10 Modern High-End Session Fields

The reduced `WMI_LOGGER_CONTEXT` layout above is enough to reason about provider enablement and basic delivery, but 25H2's public layout exposes a second cluster of fields that matters for high-fidelity EDR, anti-cheat, and performance-forensics work:

```c
ETW_STACK_TRACE_BLOCK StackTraceBlock;          // +0x340
RTL_BITMAP            StackHookIdMap;           // +0x410
ETW_STACK_CACHE*      StackCache;               // +0x420
ETW_PMC_SUPPORT*      PmcData;                  // +0x428
ETW_LBR_SUPPORT*      LbrData;                  // +0x430
ETW_IPT_SUPPORT*      IptData;                  // +0x438
ETW_APC_POOL          ContextRegisterLoggingApcPool;
volatile ULONG        ContextRegisterTypes;     // control/integer register classes
volatile ULONG        ContextRegisterHookCount;
USHORT                ContextRegisterHookIdMap[8];
LIST_ENTRY            BinaryTrackingList;       // provider-to-image correlation
```

These fields explain why a "session" is not just a buffer pool. A session can ask the kernel to attach stacks, deduplicate stacks into cache keys, sample PMCs, collect Last Branch Record snapshots, track provider binaries, and collect register state for selected system-provider events. They also explain several confusing extended-data items in user-mode consumers: `PMC_COUNTERS`, `PEBS_INDEX`, `STACK_KEY32/64`, `PROV_TRAITS`, and `EVENT_SCHEMA_TL` are not parser curiosities; they are the serialized side effects of these session features being enabled.

Operationally, these fields should be treated as capability state, not a stable control ABI. The public controller surface is `TraceSetInformation` / `TraceQueryInformation` plus `ENABLE_TRACE_PARAMETERS.EnableProperty`; the private kernel fields are verification targets. A driver that wants to audit an EDR session can compare `PmcData`, `LbrData`, `StackCache`, `ContextRegisterTypes`, and `BinaryTrackingList` against the controller's intended configuration, but it must resolve offsets on the target build before doing so.

---

## 4. Providers

### 4.1 Four Provider Flavors

| Flavor | API | Schema location | Max concurrent sessions | Notes |
|--------|-----|-----------------|--------------------------|-------|
| Classic (MOF) | `RegisterTraceGuids` / `TraceEvent` | MOF class | **1** | Pre-Vista provider model; do not confuse it with the special NT Kernel Logger session |
| WPP | `DoTraceMessage` | TMF / PDB | 1 | Driver-debug focused; payload format not in the binary |
| Manifest-based | `EventRegister` / `EventWrite` | XML manifest in `WEVT_TEMPLATE` resource | 8 | The default since Vista |
| TraceLogging | `TraceLoggingWrite` | Self-describing in the event payload | 8 | Schema travels with the event; no manifest needed |

The "max concurrent sessions" column is the load-bearing distinction. A Classic or WPP provider can be enabled by only one **trace session** at a time; manifest and TraceLogging providers can be enabled by up to eight sessions. That provider-concurrency rule is separate from session-name ownership. A second `StartTrace` against an already-running session name typically fails with `ERROR_ALREADY_EXISTS`, while a second attempt to enable an already-owned Classic/WPP provider for another session can fail with `ERROR_INVALID_PARAMETER` or `ERROR_ACCESS_DENIED` depending on the path. NT Kernel Logger is a special system trace session, not just a Classic provider, but it has the same practical single-owner problem: two products that both want the historical `KERNEL_LOGGER_NAME` raw-kernel feed trip over each other unless they cooperate via System Trace Provider multiplexing (Windows 8+) or via the Windows 10 SDK 20348 SystemProvider-per-category split (§14.8).

### 4.2 Kernel Registration Flow

```text
EtwRegister(ProviderId, Callback, CallbackContext, OutRegHandle)
  └─ EtwpRegisterKMProvider()
       ├─ EtwpGetOrCreateGuidEntry(ProviderId)        // walks EtwpGuidHashTable
       ├─ allocate ETW_REG_ENTRY from NonPagedPool
       ├─ RegEntry->GuidEntry        = GuidEntry
       ├─ RegEntry->Callback         = Callback
       ├─ RegEntry->CallbackContext  = CallbackContext
       ├─ RegEntry->DbgKernelRegistration = 1
       ├─ insert RegEntry into GuidEntry->RegListHead
       └─ *OutRegHandle = RegEntry
```

If a session is already enabled for this GUID at registration time, `EtwRegister` invokes the provider's `EnableCallback` *before returning*. Provider callbacks must therefore be reentrant-safe. Any "first enable, alloc resources" pattern that does not lock will race with a concurrent disable. This is the source of several historical CVEs in third-party providers; the standard pattern is to guard the callback with a `KGUARDED_MUTEX` and to use a boolean to gate the alloc/free pair.

### 4.3 User-Mode Registration

User-mode follows `ntdll!EtwEventRegister` -> `NtTraceEvent` -> kernel `EtwpRegisterUMProvider`, which creates an `ETW_REG_ENTRY` with `DbgUserRegistration=1` and `Process` set to the calling `EPROCESS`. The user-mode REGHANDLE is an encoded representation of the kernel `ETW_REG_ENTRY` pointer (XOR/offset-based encoding rather than a raw pointer); the encoding survives across user-mode SEH and across process suspend/resume.

There are three pieces of state here, and confusing them leads to bad detectors:

1. **The process-local handle and wrapper state.** `EventRegister` gives the process a `REGHANDLE`; generated manifest code, TraceLogging, .NET `EventSource`, and many in-house wrappers cache that handle and cache "enabled" decisions around it. Patching this layer blinds only that process and only the code paths that use the patched wrapper.
2. **The kernel registration entry.** The kernel owns the `ETW_REG_ENTRY`, links it under the provider's `ETW_GUID_ENTRY`, and associates user-mode registrations with the owning process. This is the state a BYOVD attacker edits when it wants to silence a provider without touching `ntdll`.
3. **Optional registration metadata.** `EventSetInformation(EventProviderSetTraits)` attaches a binary trait blob to the registration. TraceLogging sets traits automatically during `TraceLoggingRegister`; manifest providers can opt in manually. The trait blob can include the UTF-8 provider name and one or more provider-group GUIDs. It is stored in kernel memory for the lifetime of the registration and can be serialized into events as `EVENT_HEADER_EXT_TYPE_PROV_TRAITS`.

`EventSetInformation` also exposes two details that matter to parsers. `EventProviderBinaryTrackInfo` lets ETW add the full path of the module that contains the provider callback, which helps decoders find a manifest resource even when the provider is not globally installed. `EventProviderUseDescriptorType` and `EventProviderSetTraits` tell ETW to honor the `Type` field inside `EVENT_DATA_DESCRIPTOR`; older providers that leave the old `Reserved` field uninitialized must not accidentally opt into this path.

The security implication is subtle but useful. A manifest installed under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers` tells consumers how to decode events; it does not prove the provider is live. A live `ETW_REG_ENTRY` proves a process registered the provider; it does not prove the manifest is installed. A robust runtime provider inventory therefore joins three views: registry manifest inventory, live `EnumerateTraceGuidsEx`/kernel hash-table registrations, and static TraceLogging/provider-trait extraction from binaries.

### 4.4 GUID Hash Table and Lookup

```c
enum ETW_GUID_TYPE {
    EtwpTraceGuidType        = 0,   // ordinary providers
    EtwpNotificationGuidType = 1,   // notification providers (bidirectional)
    EtwpGroupGuidType        = 2,   // group GUIDs (§13.3)
};

struct _ETW_HASH_BUCKET {
    LIST_ENTRY ListHead[3];   // one list per ETW_GUID_TYPE
};
```

The hash is computed from the GUID bytes with a XOR/add mix and reduced mod 64; the exact mix is private and changes occasionally, so reverse-engineering `nt!EtwpGetGuidEntry` is the only reliable way to compute the same bucket the kernel would. For enumeration there is no need to recompute the hash. Walking the 64 buckets across the three lists is fast and complete.

```javascript
// WinDbg DX - enumerate every registered provider GUID across all three categories
function EnumerateAllProviderGuids() {
    const silo = host.createTypedObject(
        host.getModuleSymbolAddress("nt", "PspHostSiloGlobals"),
        "nt", "_ESERVERSILO_GLOBALS");
    const table = silo.EtwSiloState.EtwpGuidHashTable;
    const out = [];
    for (const bucket of table) {
        for (let t = 0; t < 3; t++) {
            const entries = host.namespace.Debugger.Utility.Collections
                .FromListEntry(bucket.ListHead[t], "nt!_ETW_GUID_ENTRY", "GuidList");
            for (const e of entries) {
                out.push({ Guid: e.Guid.toString(),
                           Type: ["Trace","Notification","Group"][t],
                           Regs: e.RegListHead.NumEntries });
            }
        }
    }
    return out;
}
```

This is the only way to discover TraceLogging providers that have no manifest entry under `HKLM\...\WINEVT\Publishers` and `wevtutil ep` therefore does not list, including ad-hoc providers that a kernel driver or EDR registers at runtime under a randomized GUID.

---

## 5. Sessions

### 5.1 Slot Layout

| Slot | Reservation |
|------|-------------|
| 0 | NT Kernel Logger (`SystemTraceControlGuid`, Classic). Conventionally slot 0 on a freshly booted host. |
| 1 | Circular Kernel Context Logger (CKCL). Started during phase-1 init; commonly observed at slot 1 but the exact slot is not architecturally guaranteed and can shift depending on boot-time controller order. |
| 2 .. MaxLoggers-1 | General-purpose user/EDR sessions. The historic non-private limit was 64 sessions before Windows 10 1709; modern hosts should be queried with `TraceMaxLoggersQuery` instead of assuming a fixed slot count. |

CKCL is normally on and is what made InfinityHook's preferred target attractive. The offensive code identifies CKCL by its well-known GUID `{54dea73a-ed1f-42a4-af71-3e63d056f174}` and the matching `LoggerName`, not by a hardcoded slot index. NT Kernel Logger is started on demand by `xperf`, `tracerpt`, or an EDR. Windows 8 and later support up to eight system logger sessions using `EVENT_TRACE_SYSTEM_LOGGER_MODE`, and Windows 10 SDK 20348+ exposes many System Trace Provider categories through System Provider GUIDs (§14.8). This improves coexistence, but it does not mean arbitrary controllers can all mutate one shared slot-0 logger safely.

### 5.2 Special Session Types

- **AutoLogger.** Configured under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<name>`; started by the kernel during boot before user-mode services come up. Used by ELAM drivers, Defender, and `AutoLogger-Diagtrack-Listener` (telemetry).
- **GlobalLogger.** Configured under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\GlobalLogger`; started *during* `EtwpInitialize(0)`, so it catches events before any service runs - essential for boot-driver triage and for forensics where the rest of the boot chain may have been tampered with.
- **Private Logger.** Runs in the provider process rather than as a normal global session. Buffer memory comes from the process, private sessions cannot be used with real-time delivery, and they do not consume the global logger slots in the same way as ordinary sessions. The practical limits are easy to mix up: current documentation says private sessions can be up to eight per process, while the `EVENT_TRACE_PRIVATE_IN_PROC` sub-mode is limited to three in-process private sessions per process on the documented path.
   - **`EVENT_TRACE_PRIVATE_LOGGER_MODE`** - creates a user-mode private event tracing session whose buffers are process-backed.
   - **`EVENT_TRACE_PRIVATE_IN_PROC`** - used with private logger mode to require that only the process that registered the provider GUID can start the in-process private logger.
   Do not conflate this with `EventActivityIdControl` or `dotnet-trace`. `EventActivityIdControl` only manages the current thread's activity ID; `dotnet-trace` primarily speaks EventPipe and can also enable CLR ETW providers, but it is not "implemented by private logger mode" in the ETW sense.
- **System-Wide Private Logger** (`EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC`, V2 properties). A privileged private-logger variant that uses V2 session filters (`EVENT_FILTER_TYPE_PID` or executable-name scope filters) to target other processes. It is useful for "tail this suspicious PID for sixty seconds" collection, but because private sessions do not support real-time delivery, the artifact is a file/buffered diagnostic trace rather than a live consumer stream.

### 5.3 Session Lifecycle

```text
StartTraceW() -> NtTraceControl(EtwpStartTrace)
   EtwpStartLogger()
     ├─ acquire EtwpStartTraceMutex
     ├─ allocate WMI_LOGGER_CONTEXT from NonPagedPool
     ├─ initialize stream buffers (MinimumBuffers, MaximumBuffers, current buffer refs)
     ├─ PsCreateSystemThread for the Logger Thread
     └─ EtwpLoggerContext[loggerId] = ctx

EnableTraceEx2() -> NtTraceControl(EtwpEnableProvider)
   EtwpEnableProvider()
     ├─ EtwpGetOrCreateGuidEntry()
     ├─ EnableInfo[loggerId] = { IsEnabled=1, Level, MatchAny/All, LoggerId }
     ├─ recompute ProviderEnableInfo as union of EnableInfo[0..7]
     └─ for each ETW_REG_ENTRY on GuidEntry->RegListHead:
            invoke RegEntry->Callback(EVENT_CONTROL_CODE_ENABLE_PROVIDER, ...)
```

The crucial invariant: a provider's `EnableMask` is the *bitmask* of slots that have it enabled. The first event-time check is `if (RegEntry->EnableMask == 0) return STATUS_SUCCESS;`. This single byte is the fast-path predicate. Every offensive technique that touches kernel ETW eventually targets either this byte, the corresponding `EnableInfo[i].IsEnabled`, or the `Level`/`MatchAnyKeyword` filters.

The lifecycle has more states than `StartTrace` and `StopTrace`:

| Operation | Public API | Internal effect | Failure/tamper signal |
|-----------|------------|-----------------|-----------------------|
| Start | `StartTrace` | Allocates `WMI_LOGGER_CONTEXT`, buffers, logger worker, and a slot in `EtwpLoggerContext[]`. | Slot occupied but `LoggerStatus` or worker state does not match controller state. |
| Enable | `EnableTraceEx2` | Writes provider `EnableInfo[]`, recomputes aggregate provider state, invokes callbacks. | Controller believes provider enabled, but provider slot or callback state disagrees. |
| Update | `ControlTrace(EVENT_TRACE_CONTROL_UPDATE)` / `TraceSetInformation` | Mutates file path, flush timer, filters, stack settings, context-register/LBR/PMC options where supported. | Filter or capture settings differ from policy ledger. |
| Flush | `FlushTrace` / `ControlTrace(EVENT_TRACE_CONTROL_FLUSH)` | Forces dirty or partially filled buffers through the logger worker. | Flush returns success but `BuffersWritten`/consumer canary does not advance. |
| Disable | `EnableTraceEx2(..., EVENT_CONTROL_CODE_DISABLE_PROVIDER)` | Clears the provider slot and invokes disable callback. | Provider still emits after disable, or callback-owned state not released. |
| Stop | `ControlTrace(EVENT_TRACE_CONTROL_STOP)` | Flushes, unlinks the logger context, tears down buffers and consumer attachments. | Meta-provider has no stop event, but slot vanished or file closed. |

This table is the defender's reconciliation model. A product should know which sessions it started, which providers it enabled, which filters it intended, which file/real-time mode it requested, and when it last saw a canary. Anything else is guesswork dressed as monitoring.

---

## 6. The Lock-Free Event Path

ETW's event-write path is the single most performance-critical piece of code that touches every interesting kernel operation. The design decisions there explain both why the fast path is essentially free and why the slow path is non-trivial to bypass.

### 6.1 Buffer Header

```c
struct _WMI_BUFFER_HEADER {
    ULONG    BufferSize;
    ULONG    SavedOffset;
    volatile ULONG  CurrentOffset;     // Interlocked-updated
    volatile LONG   ReferenceCount;
    LARGE_INTEGER   TimeStamp;
    LONGLONG        SequenceNumber;    // event ordering across CPUs
    union { ULONG Filled; ULONG NextBuffer; };
    ULONG    LoggerId;
    ETW_BUFFER_STATE  State;           // FREE / DIRTY / FLUSH
    ULONG    Offset;
    USHORT   BufferFlag;
    USHORT   BufferType;               // GENERIC / RUNDOWN / CTX_SWAP ...
};
```

The buffer payload is a sequence of 8-byte-aligned event records, each prefixed by an `EVENT_HEADER` (modern) or `SYSTEM_TRACE_HEADER` (Classic). Events do not cross buffer boundaries. If a write would overflow, the writer rotates the buffer first. One public constraint matters in production: ETW does not support individual events larger than 64 KB including the event header. Increasing `EVENT_TRACE_PROPERTIES.BufferSize` above 64 KB can help throughput, but it does not make oversized events valid.

### 6.2 Per-CPU Buffers

Normal high-throughput sessions are stream-buffered, usually with one stream per logical processor unless `EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING` collapses the session to fewer streams. The public way to ask how many streams a session is using is `TraceQueryInformation(..., TraceStreamCount, ...)`; it is usually equal to the processor count, but not architecturally guaranteed. A write reserves space by interlocked-updating the active `WMI_BUFFER_HEADER.CurrentOffset` for the current stream. The per-stream design is what lets ETW survive being called from DPC-heavy paths without one global logging lock becoming the bottleneck.

### 6.3 Event Write - Fast Path vs. Slow Path

```c
NTSTATUS EtwpWriteEvent(PETW_REG_ENTRY reg, PEVENT_DESCRIPTOR desc,
                       EVENT_DATA_DESCRIPTOR* data, ...) {
    // FAST PATH - tiny predicate set
    if (!reg->EnableMask)
        return STATUS_SUCCESS;

    if (!reg->GuidEntry->ProviderEnableInfo.IsEnabled)
        return STATUS_SUCCESS;

    // SLOW PATH - for each enabled session, filter & reserve
    for (int i = 0; i < 8; i++) {
        TRACE_ENABLE_INFO* en = &reg->GuidEntry->EnableInfo[i];
        if (!en->IsEnabled) continue;
        if (desc->Level > en->Level) continue;
        if (en->MatchAnyKeyword && !(desc->Keyword & en->MatchAnyKeyword)) continue;
        if ((desc->Keyword & en->MatchAllKeyword) != en->MatchAllKeyword) continue;

        ULONG stream = EtwpGetCurrentStreamIndex();
        PWMI_LOGGER_CONTEXT ctx = EtwpLoggerContext[en->LoggerId];
        ULONG sz = ComputeEventSize(desc, data);
        PWMI_BUFFER_HEADER buf = EtwpGetCurrentBuffer(ctx, stream);
        ULONG off = InterlockedExchangeAdd(&buf->CurrentOffset, sz);
        if (off + sz > ctx->BufferSize) {
            EtwpBufferFull(ctx, stream);   // rotate, signal logger thread; may lose if pool exhausted
            continue;
        }

        WriteEventHeader(buf + off, desc, /* timestamp from ctx->GetCpuClock dispatch */);
        CopyEventData(buf + off, data);

        if (en->EnableProperty & EVENT_ENABLE_PROPERTY_STACK_TRACE)
            AttachStackTrace(buf + off);
    }
    return STATUS_SUCCESS;
}
```

Two operational properties follow:

- **Idle providers cost about ten cycles.** The fast-path miss is a load and a branch. This is why thousands of registered providers do not slow the system down - and why a tampered provider whose `EnableMask` has been forced to 0 is indistinguishable from a legitimately quiet provider unless you inspect `EnableInfo[]` or correlate against the controller's claimed subscription.
- **An overflowing session loses events.** The `EventsLost` field on `WMI_LOGGER_CONTEXT` is a monotonic loss counter; a sudden delta indicates either a buffer-size misconfiguration or a deliberate flood attempting to push attacker activity past the flusher. Defensive collectors must monitor this delta the way SOCs monitor "log source quiet" alarms.

IRQL: the kernel `EtwWrite` DDI is documented as callable at any IRQL, but the buffers described by `EVENT_DATA_DESCRIPTOR` must be valid for that IRQL. Above `APC_LEVEL`, that means nonpageable, system-addressable memory. Optional features such as stack walking have narrower practical constraints and may be omitted even when the event itself is delivered.

### 6.4 The Logger Thread

Each session has a logger worker that turns full buffers into durable or consumable output. The event-write path does not synchronously call a consumer and does not synchronously write the ETL file. It reserves space, copies the record, marks the buffer dirty when it fills or when a flush is requested, and wakes the logger. That separation is why ETW can be cheap in the hot path and still lose events under backpressure.

The worker wakes for four ordinary reasons:

| Wake reason | What happens |
|-------------|--------------|
| Buffer full | A per-CPU buffer reached its commit limit and moved to the dirty queue. |
| Flush timer | `EVENT_TRACE_PROPERTIES.FlushTimer` expired; partially filled buffers are eligible for flush. |
| Explicit flush | A controller called `FlushTrace` / `ControlTrace(EVENT_TRACE_CONTROL_FLUSH)` or stopped the session. |
| Real-time consumer pressure | A consumer attached or the real-time handoff path needs buffers delivered. |

File-mode and real-time sessions diverge at this point. In file mode, dirty buffers are written to the log file and recycled. In real-time mode, the logger makes buffers visible to attached consumers and tracks delivery progress; if the consumer is slow, the kernel-side playback path can become the bottleneck. A hybrid session (`EVENT_TRACE_REAL_TIME_MODE` plus file output) pays both costs, which is useful for evidence durability but dangerous if the consumer callback is slow.

The loss counters tell you which side is sick:

- `EventsLost` means events could not be written into a session buffer in the first place. This usually indicates buffer-pool exhaustion or an event larger than the available buffer.
- `LogBuffersLost` means dirty buffers could not be written to the file path fast enough, or the file path failed.
- `RealTimeBuffersLost` means buffers could not be delivered to real-time consumers fast enough.
- `BuffersWritten`, `NumberOfBuffers`, and `FreeBuffers` tell whether the session is merely busy or actually starved.

For detection engineering, the logger thread is a first-class tamper surface. Clearing provider state blinds the producer; wedging the logger blinds delivery while leaving provider state correct. A canary provider that is enabled, writes every N seconds, and is expected to arrive at the consumer within `FlushTimer + jitter` is the simplest end-to-end test. If the provider enable state is intact and the canary disappears while `RealTimeBuffersLost` or `EventsLost` grows, the failure is in session delivery, not provider registration.

### 6.5 Stack Walks

Stack capture is the most expensive optional feature of the event-write path and the one with the most version-sensitive behavior. Enabling it is a controller-side decision:

```c
ENABLE_TRACE_PARAMETERS params = {0};
params.Version          = ENABLE_TRACE_PARAMETERS_VERSION_2;
params.EnableProperty   = EVENT_ENABLE_PROPERTY_STACK_TRACE;
// or, with per-event-ID precision:
params.FilterDescCount  = 1;
params.EnableFilterDesc = &eventIdFilter;   // EVENT_FILTER_TYPE_STACKWALK
```

The kernel captures into an `EVENT_HEADER_EXT_TYPE_STACK_TRACE32` or `_TRACE64` extended item, up to 192 frames, in the same buffer as the event payload. The two halves of the stack, kernel and user, are captured into separate extended items and correlated by a shared `MatchId` field that the consumer reassembles. The cost is roughly 1,000-5,000 cycles per event; on a busy host enabling it globally is the most reliable way to push a session into `EventsLost`.

Three operational constraints shape what stack walks actually capture:

1. **IRQL and pageability still matter.** `EtwWrite` itself is documented as callable at any IRQL, but data passed above `APC_LEVEL` must be nonpageable and in system space. Stack capture is more constrained than the base write path; if the kernel cannot safely walk the requested stack, the event can still be delivered without the extended stack item. Defensive code that depends on a stack for attribution must therefore tolerate the absence of one.
2. **Kernel stack capture on x64 is not a free production default.** Microsoft documents `DisablePagingExecutive = 1` as a way to improve kernel stack walking, but also warns that it should be temporary diagnosis because it increases memory pressure. Production collectors should prefer targeted stack filters, measure loss, and consider the V2 `ExcludeKernelStack` option when user-mode attribution is enough.
3. **Kernel stack depth.** x64 kernel stacks are 24 KiB (six pages) by default; deep recursive paths can exhaust the stack-guard page during capture, which the kernel handles by truncating. The extended item carries however many frames fit before the truncation.

The single most useful filter from §13.2 in this context is `EVENT_FILTER_TYPE_STACKWALK`, which enables capture for an enumerated set of event IDs only. Wiring stack walks to the ETWTI behavioral events for executable allocation/protect/map, VM read/write, APC queue, set-thread-context, suspend/resume, impersonation, and driver/device topology is the canonical EDR configuration. These are exactly the events where the call-stack is forensically load-bearing, and the rest of ETW can run stack-walk-free. Handle open/duplicate analysis should use `Microsoft-Windows-Kernel-Audit-API-Calls` plus `ObRegisterCallbacks`; do not assume current ETWTI metadata carries the older duplicate-handle IDs.

For credible stack-walk attribution against modern adversaries you cannot stop at "enable the filter". Frame-spoofing techniques (§11.6) defeat naive walks; CET shadow-stack catches many of them but only on hardware that supports it. The end-to-end design pattern is: capture stack for the security-critical event IDs, verify shadow-stack consistency where available, and treat any spoofed-looking frame chain (`ntdll!RtlUserThreadStart` with no plausible inner frames, RSP deltas that imply an unwind beyond the bottom-of-stack page) as a high-confidence telemetry-tampering signal.

---

## 7. Event Format and ETL Files

### 7.1 Modern EVENT_HEADER

```c
struct EVENT_HEADER {
    USHORT           Size;
    USHORT           HeaderType;        // always 0 for modern
    USHORT           Flags;             // EVENT_HEADER_FLAG_*
    USHORT           EventProperty;
    ULONG            ThreadId;
    ULONG            ProcessId;
    LARGE_INTEGER    TimeStamp;         // QPC or system time per GetCpuClock dispatch
    GUID             ProviderId;
    EVENT_DESCRIPTOR EventDescriptor;   // {Id, Version, Channel, Level, Opcode, Task, Keyword}
    union { struct { ULONG KernelTime; ULONG UserTime; }; ULONG64 ProcessorTime; };
    GUID             ActivityId;
};
```

Useful header flags for forensics and provider classification:

- `EVENT_HEADER_FLAG_EXTENDED_INFO (0x0001)` - payload is followed by an `EVENT_HEADER_EXTENDED_DATA_ITEM` array
- `EVENT_HEADER_FLAG_PRIVATE_SESSION (0x0002)` - emitted by a private-logger session
- `EVENT_HEADER_FLAG_STRING_ONLY (0x0004)` - payload is a bare UTF-16 string
- `EVENT_HEADER_FLAG_TRACE_MESSAGE (0x0008)` - WPP `TraceMessage` (NOT TraceLogging - see §7.3)
- `EVENT_HEADER_FLAG_32_BIT_HEADER` / `_64_BIT_HEADER` - originating process bitness

### 7.2 Extended Data Items

```c
struct EVENT_HEADER_EXTENDED_DATA_ITEM {
    USHORT    Reserved1;
    USHORT    ExtType;       // EVENT_HEADER_EXT_TYPE_*
    USHORT    Linkage : 1;
    USHORT    Reserved2 : 15;
    USHORT    DataSize;
    ULONGLONG DataPtr;
};
```

| ExtType | Use |
|---------|-----|
| `RELATED_ACTIVITYID` (0x01) | parent-activity GUID (see §13) |
| `SID` (0x02) | user SID of the writer |
| `TS_ID` (0x03) | terminal-services session ID |
| `INSTANCE_INFO` (0x04) | instance correlation |
| `STACK_TRACE32` / `STACK_TRACE64` (0x05 / 0x06) | kernel + user call stack, up to 192 frames |
| `PEBS_INDEX` (0x07) | Intel PEBS sample index |
| `PMC_COUNTERS` (0x08) | hardware perfmon counters |
| `PSM_KEY` (0x09) | process state-management key |
| `EVENT_KEY` (0x0A) | per-event opaque key |
| `EVENT_SCHEMA_TL` (0x0B) | TraceLogging schema (used by §13.6 dynamic extraction) |
| `PROV_TRAITS` (0x0C) | provider traits blob |
| `PROCESS_START_KEY` (0x0D) | stable process identity surviving PID reuse |
| `CONTROL_GUID` (0x0E) | control GUID |
| `QPC_DELTA` (0x0F) | QPC delta value (used with `QpcDeltaTracking` V2 option) |
| `CONTAINER_ID` (0x10) | Silo / container ID |
| `STACK_KEY32` (0x11) | 32-bit stack-cache key (used when `TraceStackCachingInfo` deduplication is on) |
| `STACK_KEY64` (0x12) | 64-bit stack-cache key (same purpose) |

Stack-trace attachment is controlled through `EVENT_ENABLE_PROPERTY_STACK_TRACE` and `EVENT_FILTER_TYPE_STACKWALK`, with the kernel-stack capture caveats covered in detail in §6.5.

### 7.3 Identifying TraceLogging Correctly

A widely repeated piece of folklore says that TraceLogging events have **keyword bit 47 set**. This is wrong, in the precise sense that bit 47 (`0x0000800000000000`) is `MICROSOFT_KEYWORD_CRITICAL_DATA`, one of three Microsoft-reserved telemetry-classification keywords (bit 45 = `TELEMETRY`, bit 46 = `MEASURES`, bit 47 = `CRITICAL_DATA`). It is set on a wide range of *non-TraceLogging* manifest events that Microsoft classifies as critical telemetry, and clear on many TraceLogging events that have nothing to do with telemetry.

The robust test is TraceLogging metadata, not keyword 47. In the common case, `EVENT_HEADER.EventDescriptor.Channel == 11` (`WINEVENT_CHANNEL_TRACELOGGING`) identifies a normal TraceLogging event because TraceLogging defaults to channel 11. On Windows 10 and later, however, the runtime can also mark a provider as TraceLogging-compatible via provider traits / `EventSetInformation`, so a TraceLogging event is not required to use channel 11 forever. A parser should treat channel 11 as a strong hint, then confirm by finding the TraceLogging schema metadata (`EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` / provider metadata descriptors). Code that classifies events by keyword 47 will both miss TraceLogging events and misclassify telemetry ones; this is a common bug in homemade parsers.

### 7.4 ETL on Disk

An `.etl` file is not an EVTX-like database. It is a stream of flushed ETW buffers. Each buffer begins with `WMI_BUFFER_HEADER`; the bytes after that header are a sequence of variable-size event records. The first record in the file is normally the `WMI_LOG_TYPE_HEADER` system event: a `SYSTEM_TRACE_HEADER`, followed by a raw `TRACE_LOGFILE_HEADER`, followed by the logger name and log-file name strings. `OpenTrace` exposes a normalized version of that metadata through `EVENT_TRACE_LOGFILE.LogfileHeader`.

The fields that matter for low-level parsers are:

| Field | Practical meaning |
|-------|-------------------|
| `WMI_BUFFER_HEADER.BufferSize` | Size of the flushed buffer on disk; effectively the stride to the next buffer. |
| `WMI_BUFFER_HEADER.SavedOffset` / `CurrentOffset` | How many bytes in the buffer are valid. |
| `WMI_BUFFER_HEADER.SequenceNumber` | Monotonic buffer order within the session. |
| `WMI_BUFFER_HEADER.ClientContext` | Clock/timestamp context for the records in that buffer. |
| `TRACE_LOGFILE_HEADER.BootTime` / `PerfFreq` / `StartTime` | Needed to convert raw QPC/cycle timestamps into wall time. |
| `TRACE_LOGFILE_HEADER.EventsLost` / `BuffersLost` | File-level loss evidence captured at logger shutdown or header update time. |

Event ordering across CPUs is a merge problem, not a linked-list walk. The buffer sequence tells you flush order; the event timestamp tells you logical time; ties across processors are not stable. `ProcessTrace` tries to deliver events oldest to newest, but Microsoft explicitly allows out-of-order delivery when the clock moves backward, when two CPUs emit identical timestamps, or when a record is corrupt. A forensic parser that treats the callback order as a total order will eventually produce a false narrative.

A corrupted final buffer does not poison the whole file. The usual crash pattern is that every complete buffer before the torn write parses correctly, and the last buffer fails a progress or bounds check. Direct parsers should fail closed per buffer: verify `BufferSize`, verify that each event advances by at least its header size, stop at `SavedOffset`, and keep the earlier buffers. `OpenTrace` + `ProcessTrace` already handles many of these cases, but custom parsers used in memory forensics need those progress checks explicitly.

### 7.5 Compression

Beginning with Windows 8 (and exposed publicly through the `EVENT_TRACE_COMPRESSED_MODE` constant added to the Windows 10 1607 SDK), ETL writers can compress each buffer independently before flushing to disk. The important word is *independently*: compression is a per-buffer transform, not a whole-file archive. A torn write or corrupt compressed block should cost you that buffer, not the whole ETL.

XPRESS-Huffman is the modern useful mode. Compression ratios on typical heavy traces (System Trace Provider, CKCL, WPR CPU+disk profiles) often land around 5-7x; CPU overhead is concentrated in the logger worker, not in the event-write fast path. `wpr -compress` and `xperf -CompressMode 2` both enable XPRESS-Huffman; `CompressMode 1` is the older LZW path. `OpenTrace` decompresses transparently, so a normal consumer does not need a separate code path. A direct parser does.

Compression is a file-mode feature. It is not a magic way to reduce real-time consumer pressure, because the real-time consumer protocol receives event records rather than a compressed on-disk block stream. If a design needs both live detection and compact evidence, use a real-time session for detection and a separate compressed file-mode session for durable replay.

Note that `EVENT_TRACE_COMPRESSED_MODE` is a *semi-documented* logging-mode constant: it appears in the EVNTRACE.H header shipped from the Windows 10 1607 SDK onward but is absent from the public "Logging Mode Constants" table. Different sources report its numeric value (some give `0x04000000`); the safe practice is to use the SDK header definition where available rather than hard-coding.

---

## 8. Consumers

A consumer is where ETW stops being an operating-system mechanism and becomes an engineering problem. The kernel can deliver a correct event, but a slow callback, a schema-cache miss, a bad timestamp assumption, or a parser that trusts `UserDataLength` too much can still make the detection useless.

There are two consumption modes:

| Mode | API shape | Operational shape |
|------|-----------|-------------------|
| File replay | `OpenTrace(LogFileName)` + `ProcessTrace` | Up to 64 ETL files can be merged in one `ProcessTrace` call. Good for forensics and deterministic replay. |
| Real-time | `OpenTrace(LoggerName)` with `PROCESS_TRACE_MODE_REAL_TIME` | One real-time session per `ProcessTrace` call. Good for detection, but callback latency becomes backpressure. |

A real-time consumer creates an `EtwConsumer` kernel object, links itself onto the session's consumer list, and waits for buffer availability. `ProcessTrace` is blocking; the production pattern is to run it on a dedicated thread, do minimal work inside `EventRecordCallback`, and hand off decoded or partially decoded records to a bounded internal queue. If the callback formats strings, calls the network, touches a database, or synchronously uploads evidence, it is no longer a consumer; it is a denial-of-service surface against its own ETW session.

The callback receives an `EVENT_RECORD`:

```c
struct EVENT_RECORD {
    EVENT_HEADER                     EventHeader;
    ETW_BUFFER_CONTEXT               BufferContext;   // processor #, logger ID
    USHORT                           ExtendedDataCount;
    USHORT                           UserDataLength;
    PEVENT_HEADER_EXTENDED_DATA_ITEM ExtendedData;
    PVOID                            UserData;
    PVOID                            UserContext;
};
```

The consumer should be built around four rules:

1. **Use `PROCESS_TRACE_MODE_EVENT_RECORD`.** The legacy `EventCallback` format loses useful context. `EVENT_RECORD` carries the extended-data array, provider GUID, activity ID, user context, and the raw payload pointer that TDH expects.
2. **Choose timestamp mode deliberately.** By default, `ProcessTrace` converts timestamps to system time. `PROCESS_TRACE_MODE_RAW_TIMESTAMP` preserves the provider/session clock domain, which is better for high-resolution correlation and for validating QPC drift, but it pushes conversion onto the consumer.
3. **Do not assume total ordering.** `ProcessTrace` attempts chronological delivery, but equal timestamps across CPUs, clock adjustment, and corrupt records can produce out-of-order callbacks. Build detectors around windows, process-start keys, activity IDs, and monotonic per-source sequence where available.
4. **Treat `BufferCallback` as health telemetry.** It runs after a buffer is processed and gives the consumer a chance to cancel processing. More importantly, it is the natural place to sample `BuffersRead`, buffer fill, and loss evidence. Real-time consumers should report "alive but losing" separately from "dead".

TDH is correctness glue, not a free fast path. `TdhGetEventInformation` retrieves metadata for the `EVENT_RECORD`; for WPP and Classic events the caller may need a `TDH_CONTEXT`, and for manifest events TDH may have to look up publisher registration and load a `WEVT_TEMPLATE` resource from the provider binary. High-throughput consumers cache the result keyed by `(ProviderId, EventId, Version, Opcode, Task, Channel)` and invalidate on provider-binary change. For TraceLogging, the schema is carried in the event payload/metadata, so it is often faster and more reliable to parse the self-describing schema directly after a small amount of validation.

The metadata-source priority used by `TdhGetEventInformation` is: TraceLogging payload -> manifest publisher (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`) -> WMI MOF repository -> WPP (only with an external TMF / PDB). For events from providers whose manifest is not registered (e.g. random TraceLogging providers) the second/third sources fail; the consumer either uses the in-event schema or sees the raw byte payload.

Security consumers also need parser hardening. Every length in `EVENT_RECORD` and every extended-data item should be treated as untrusted input, especially when replaying ETL files acquired from another host. Verify `UserDataLength` before field extraction, verify every `EVENT_HEADER_EXTENDED_DATA_ITEM.DataSize`, reject zero-sized progress, and cap per-event allocation. This is not theoretical: malicious ETL replay is an easy way to wedge a collector or force it to spend seconds in metadata resolution for every event.

---

## 9. Microsoft-Windows-Threat-Intelligence (ETWTI)

### 9.1 Access Model

ETWTI is the kernel's purpose-built channel for security-relevant events that originate inside the kernel and cannot be patched out from user mode. GUID `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`. Access is gated at enable/query/consume time, with one important AutoLogger nuance:

- **Normal controller path:** a process calling `EnableTraceEx2` for `Microsoft-Windows-Threat-Intelligence` must satisfy the Antimalware-PPL access check. Non-AM-PPL callers get `ERROR_ACCESS_DENIED`. In practice, obtaining that identity normally means participating in the Microsoft antimalware/ELAM signing path, but the check the kernel enforces is the protection/signer level, not a generic "ELAM-signed caller" bit on the provider.
- **AutoLogger path:** AutoLogger provider enablement is performed by the kernel during boot rather than by a user-mode controller identity. When an AutoLogger requests ETWTI or `Microsoft-Windows-Kernel-Audit-API-Calls`, the session is marked with the `SecurityTrace` flag so later query/consume operations are supposed to be restricted to AM-PPL callers. Recent public research shows this boundary has had edge cases, including native-API consumption and stop-trace behavior that did not always apply the same checks as high-level APIs.
- **State tracking:** `ETW_SILODRIVERSTATE.EtwpSecurityLoggers[8]` tracks the logger slots that consume the security provider family, and `WMI_LOGGER_CONTEXT.Flags.SecurityTrace` marks protected sessions. Treat `EtwpSecurityProviderPID` as implementation detail, not a universal "the one ETWTI consumer PID" truth; multiple security sessions and AutoLogger paths can exist.

The runtime identity that matters here is `PsProtectedSignerAntimalware` plus the PPL-light protection type. Microsoft's protected antimalware-service model is not "admin plus a certificate"; it is a bootstrapped chain:

1. The vendor installs an ELAM driver.
2. The ELAM driver carries a resource section that registers the certificate hashes allowed to sign the user-mode antimalware service and its non-Windows DLLs.
3. The service is configured with `SERVICE_CONFIG_LAUNCH_PROTECTED` / `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`.
4. At service start, SCM and Code Integrity validate the registered certificate information and launch the service as protected.
5. In the kernel, the process protection byte resolves to a protected-light process with antimalware signer. Microsoft's own debugging example shows `_EPROCESS.Protection.Level = 0x31`, `Type = 0y0001`, `Signer = 0y0011` for an antimalware protected service.

That is the reason an ordinary administrator, an ordinary service running as `LocalSystem`, and even many other PPL levels cannot open ETWTI like a normal provider. The access check is not satisfied by `SeDebugPrivilege`; it is satisfied by the protected-process signer/protection level. ELAM is the enrollment and certificate-registration path. PPL-AM is the runtime property the ETWTI access path cares about.

Operational consequences:

| Case | ETWTI result |
|------|--------------|
| Ordinary admin controller with `EnableTraceEx2` | `ERROR_ACCESS_DENIED` on the normal path |
| `LocalSystem` service without AM-PPL | still denied; token privilege is not enough |
| Microsoft Defender / MDE AM-PPL component | can own or broker the security trace |
| Third-party AV with valid ELAM + protected-service registration | can qualify if it launches as AM-PPL |
| Anti-cheat without AM-PPL identity | cannot rely on direct user-mode ETWTI consumption; use a signed kernel component, an AM-PPL broker, or re-emission/test architecture |
| Research re-emitter driver such as SealighterTI | can wrap ETWTI in a lab, but creates a new trust boundary |

When debugging access failures, check both sides. User mode should verify service launch protection and signer registration; kernel/debugger inspection should verify `_EPROCESS.Protection` rather than just the image name. On the ETW side, query the session's `SecurityTrace` flag and `EtwpSecurityLoggers[]` slots; a security-trace session that exists but is consumed by a non-AM-PPL process is either using an edge case, a brokered path, or stale state that needs live validation.

This is why writing your own ETWTI consumer is a meaningful engineering project. You need an AM-PPL-qualified service/driver path, or you need a signed driver that wraps ETWTI and re-emits the events on a standard provider, which is the architecture *SealighterTI* uses for research environments.

### 9.2 Provider Metadata (Win11 25H2 build 26200.8524)

The current 25H2 provider metadata does **not** match the older sequential event-ID tables that circulate in ETW research notes. On this build, `wevtutil gp Microsoft-Windows-Threat-Intelligence /ge:true /gm:true` reports the following task/event/keyword shape:

| Behavior family | Event IDs | Primary keywords | Security use |
|-----------------|-----------|------------------|--------------|
| Remote executable allocation | 1 | `ALLOCVM_REMOTE` (`0x4`) | alloc-execute injection |
| Local executable allocation | 6 | `ALLOCVM_LOCAL` (`0x1`) | suspicious local RX/RWX staging |
| Executable allocation by kernel caller | 21 / 26 | `ALLOCVM_REMOTE_KERNEL_CALLER` (`0x8`), `ALLOCVM_LOCAL_KERNEL_CALLER` (`0x2`) | driver-assisted user-mode staging |
| Remote executable protection change | 2 (versions 1-3) | `PROTECTVM_REMOTE` (`0x40`) | alloc-then-protect injection |
| Local executable protection change | 7 (versions 1-3) | `PROTECTVM_LOCAL` (`0x10`) | local JIT/stager discrimination |
| Executable protection by kernel caller | 22 / 27 (versions 1-3) | `PROTECTVM_REMOTE_KERNEL_CALLER` (`0x80`), `PROTECTVM_LOCAL_KERNEL_CALLER` (`0x20`) | BYOVD / helper-driver staging |
| Remote executable section map | 3 | `MAPVIEW_REMOTE` (`0x400`) | section-mapping injection |
| Local executable section map | 8 | `MAPVIEW_LOCAL` (`0x100`) | local RX image/section mapping |
| Section map by kernel caller | 23 / 28 | `MAPVIEW_REMOTE_KERNEL_CALLER` (`0x800`), `MAPVIEW_LOCAL_KERNEL_CALLER` (`0x200`) | driver-assisted section mapping |
| Remote user APC queue | 4 | `QUEUEUSERAPC_REMOTE` (`0x1000`) | APC injection |
| APC queue by kernel caller | 24 | `QUEUEUSERAPC_REMOTE_KERNEL_CALLER` (`0x2000`) | kernel-assisted APC delivery |
| Remote set-thread-context | 5 | `SETTHREADCONTEXT_REMOTE` (`0x4000`) | thread hijacking |
| Set-thread-context by kernel caller | 25 | `SETTHREADCONTEXT_REMOTE_KERNEL_CALLER` (`0x8000`) | driver-assisted hijack |
| VM read | 11 local, 13 remote | `READVM_LOCAL` (`0x10000`), `READVM_REMOTE` (`0x20000`) | LSASS / game-process memory reads |
| VM write | 12 local, 14 remote | `WRITEVM_LOCAL` (`0x40000`), `WRITEVM_REMOTE` (`0x80000`) | cross-process code/data injection |
| Thread suspend/resume | 15 / 16 | `SUSPEND_THREAD` (`0x100000`), `RESUME_THREAD` (`0x200000`) | EDR/anti-cheat thread tampering |
| Process suspend/resume/freeze/thaw | 17 / 18 / 19 / 20 | `SUSPEND_PROCESS`, `RESUME_PROCESS`, `FREEZE_PROCESS`, `THAW_PROCESS` (`0x400000..0x2000000`) | whole-process tampering and lifecycle abuse |
| Driver/device events | 29 / 30 / 31 / 32 | `DRIVER_EVENTS` (`0x40000000`), `DEVICE_EVENTS` (`0x80000000`) | driver and device-object topology |
| Process impersonation | 33 / 34 / 36 | `PROCESS_IMPERSONATION_UP`, `PROCESS_IMPERSONATION_REVERT`, `PROCESS_IMPERSONATION_DOWN` | token-level privilege movement |
| Process syscall usage | 35 | `PROCESS_SYSCALL_USAGE` (`0x10000000000`) | suspicious syscall-profile state |

The keyword catalog is wider than the event rows above. Current 26200 metadata also exposes `CONTEXT_PARSE`, `EXECUTION_ADDRESS_VAD_PROBE`, `EXECUTION_ADDRESS_MMF_NAME_PROBE`, `READWRITEVM_NO_SIGNATURE_RESTRICTION`, VAD-fill keywords for read/write/protect events, and `QUEUEUSERAPC_AT_DPC`. Some of those keywords are not attached to distinct public manifest event rows on this host, so they should be treated as build-specific gates or versioned payload hints until verified against the target manifest/PDB.

Two corrections matter operationally. First, old notes that label event ID 8 as `SetThreadContext`, ID 16 as `DuplicateHandle`, or ID 21 as CET audit are wrong for current 26200 metadata: event 8 is local executable map-view, event 16 is thread resume, and event 21 is remote-kernel-caller alloc-VM. Second, ETWTI is not the right source for every handle or CET signal. For handle opens/duplicates, pair `Microsoft-Windows-Kernel-Audit-API-Calls` with `ObRegisterCallbacks`; for CET/shadow-stack anomalies, use the platform's CET/audit surfaces and stack-integrity telemetry rather than assuming an ETWTI event ID.

Exact build-by-build availability must be checked against `logman query providers Microsoft-Windows-Threat-Intelligence`, `wevtutil gp Microsoft-Windows-Threat-Intelligence /ge:true /gm:true`, or a per-build manifest archive. Defenders consuming ETWTI should include the remote-read keyword at minimum and filter the resulting events by target process. Any non-debugger process reading from LSASS or a protected game process is a high-confidence memory-theft signal.

### 9.3 Cannot Be Bypassed From User Mode

Because ETWTI events are emitted from inside the kernel routines that a user-mode attacker must invoke to perform the underlying action. A user-mode caller cannot write into another process's address space without eventually entering `MiReadWriteVirtualMemory` via a syscall. No amount of user-mode patching disables them. (An attacker who already has arbitrary kernel write can of course bypass these routines entirely; that case falls under DKOM below.) Defeating ETWTI in practice requires one of:

1. Kernel write (BYOVD -> DKOM on the ETWTI registration handle or `ProviderEnableInfo.IsEnabled`). This is the Lazarus *FudModule* approach.
2. Defeating the *consumer* or delivery path (starve the session, stop a misconfigured security trace, suspend the PPL-AM consumer with kernel help, or exploit an access-control edge case).
3. Avoiding the kernel path that triggers the event (e.g. using `NtContinue` to set thread context on the *current* thread, which doesn't traverse `PspSetContextThreadInternal` and therefore doesn't emit `EtwTiLogSetContextThread`). This is the Patchless category covered in §11.

---

### 9.4 AMSI Provider Chain and Defender's ETW Architecture

ETWTI handles the kernel-resident behavior signals. The user-mode scripting-and-content equivalent is AMSI (Antimalware Scan Interface), which is wired into ETW from both sides. AMSI emits events that consumers read, and AMSI internally uses ETW for its own internal correlation. Understanding both directions matters because the most-attacked detection path on the Windows platform runs through here.

#### 9.4.1 AMSI Architecture

AMSI is a broker pattern. Application hosts (PowerShell, WSH, Office, Edge, IIS, .NET) call `AmsiScanBuffer` / `AmsiScanString` on content they are about to execute or render. The AMSI runtime walks the providers registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}` and dispatches the scan request to each. The Defender-bundled provider is `MpOav.dll` (CLSID `{2781761E-28E0-4109-99FE-B9D127C57AFE}`); third-party AV/EDRs register their own providers under the same key.

```text
Application (PowerShell, etc.)
   │  AmsiScanBuffer(buffer)
   ▼
amsi.dll  ──->  load each provider CLSID
   │
   ├─ MpOav.dll (Defender)  ──ALPC──▶  MsMpEng.exe  ──cloud-detonate──▶  result
   ├─ ThirdParty.dll                    │
   └─ ...                               ▼
                                  AMSI_RESULT_*
   ▼
Application acts on result (run / block)
```

`MpOav.dll` communicates with the Defender engine over a private ALPC channel (the exact port name is internal and has changed across Defender platform versions, so production tooling should not depend on it); `MsMpEng.exe` runs as PPL-AM (`PsProtectedSignerAntimalware`) so its memory and tokens are protected against ordinary admin tampering. The Defender engine performs signature matching, ML inference, and (when MAPS cloud protection is enabled) cloud detonation, returning one of `AMSI_RESULT_CLEAN`, `AMSI_RESULT_NOT_DETECTED`, `AMSI_RESULT_DETECTED`, or `AMSI_RESULT_BLOCKED_BY_ADMIN`.

#### 9.4.2 ETW Emission

Independently of the scan result, `amsi.dll` emits an ETW event on every scan:

- **Provider:** `Microsoft-Antimalware-Scan-Interface` (`{2a576b87-09a7-520e-c21a-4942f0271d67}`)
- **Event ID 1101 - AmsiScanBuffer.** Payload: session GUID, SHA-256 of the buffer (first 32 bytes of `Hash`), `ContentSize`, `ContentName` (e.g. `"PowerShell"`, `"VBScript"`, `"JScript"`, `"Office_VBA"`), `AppName` (the calling host process name), `ScanResult`, `Duration` in milliseconds.

Event 1101 is the most useful single AMSI signal for SOCs because the SHA-256 lets a defender correlate the scanned content across hosts even when the content itself is not retained. Do not assume a broader public AMSI event set without checking the target manifest. On the live 26200 host used for this review, `wevtutil gp Microsoft-Antimalware-Scan-Interface /ge:true /gm:true` exposes only event 1101 (versions 0 and 1) in `amsi.dll`; older notes and private-provider traces that mention additional AMSI lifecycle or UAC-scan events should be treated as build/provider-specific until verified.

#### 9.4.3 Defender's Own Providers

Defender emits to several providers that an MDE SOC needs to know about. The GUIDs below come from public third-party research and should be re-verified on the target build with `logman query providers <name>` before deployment. Microsoft does not publish a canonical manifest for the AM providers.

| Provider | GUID (verify before use) | Use |
|---------|--------------------------|-----|
| `Microsoft-Antimalware-Engine` | `{0a002690-3839-4e3a-b3b6-96d8df868d99}` | Scan-started/completed, signature match, NRI/ML inference, remediation; the Defender engine's own behavioral telemetry |
| `Microsoft-Antimalware-Service` | `{751ef305-6c6e-4fed-b847-02ef79d26aef}` | `MpSvc.dll` / `MsMpEng.exe` service-lifecycle events |
| `Microsoft-Windows-WindowsDefender` | `{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}` | The Operational channel events surfaced under `Microsoft-Windows-Windows Defender/Operational` - events 1006/1007/1015/5007 used in most public Sigma rules |
| `Microsoft-Antimalware-AMFilter` | `{cfeb0608-330e-4410-b00d-56d8da9986e6}` | `MpFilter.sys` minifilter pre/post-create callbacks (filter altitude is in the AV range around 328000, verify the exact value with `fltmc instances`) |

`Microsoft-Antimalware-Engine` is not a "secure" provider. Any admin can subscribe, which makes it the canonical place to look for what Defender thought of an event in real time without going through the EventLog channel.

#### 9.4.4 AMSI Bypasses Beyond `AmsiScanBuffer` Patch

The classical `AmsiScanBuffer` first-bytes patch is well known; modern bypasses target the AMSI internal state directly because the API surface is harder to monitor for byte changes:

- **AMSI context corruption.** AMSI maintains a per-session `HAMSICONTEXT` (an opaque handle internally validated against the ASCII tag `"AMSI"` at the start of the structure). Corrupting the validation tag in the context that the host application (e.g. PowerShell) holds - without ever touching `amsi.dll` code bytes - causes subsequent `AmsiScanBuffer` calls to fail validation and return without scanning. Documented across S3cur3Th1sSh1t, Rastamouse, and others. The exact field name (`g_amsiContext` vs. host-process-local context handle) varies between writeups.
- **`CLR_AMSIContext` / .NET in-memory AMSI bypass.** The CLR (`clr.dll` / `coreclr.dll`) maintains its own AMSI context that is used when .NET code is loaded via `Assembly.Load(byte[])`. Replacing the static field with a no-op stub bypasses AMSI for in-memory .NET payloads (xpn, Flangvik).
- **Hardware-breakpoint + VEH (HellsHollow / AceLdr).** Same primitive as patchless ETW bypass (§11.3) applied to AMSI: set `Dr0` to `AmsiScanBuffer`, install VEH, force `AMSI_RESULT_CLEAN`. The bypass and the ETW patchless bypass are typically combined in the same loader because the targets are colocated.
- **In-process context recreation.** Some PoCs re-initialize the AMSI context with a fresh `amsi.dll!CAmsiAMScan::Init` call that points the context at a controlled provider list, effectively swapping out Defender for an attacker-controlled scanner. Requires more code than the byte-flip but leaves no inline patch.

**Detection signal:** AMSI bypass attempts are almost always visible in ScriptBlock (event 4104) of `Microsoft-Windows-PowerShell` because the bypass *itself* is PowerShell that has to compile through a ScriptBlock before patching anything. The combined heuristic looks for recent 4104 events containing strings like `etwProvider`, `AmsiUtils`, `g_amsiContext`, `MpOav`, or `[Ref].Assembly.GetType`, followed by a sustained absence of subsequent 4104/1101 events from the same runspace. This is the highest-confidence single signal for AMSI/ETW user-mode bypass.

---

## 10. Hooking ETW: InfinityHook and Its Heirs

### 10.1 Classical InfinityHook: Direct `GetCpuClock` Pointer Swap

The classical InfinityHook recipe targets CKCL because (a) it is always running and (b) it can be configured to log system calls. On a syscall-entry path, `KiSystemCall64` calls into `PerfInfoLogSyscallEntry`, which eventually timestamps the ETW record through the logger's clock source. On older builds the relevant `WMI_LOGGER_CONTEXT.GetCpuClock` member was a callable function pointer. Swapping it for an attacker-controlled function turned every captured syscall into a one-line hook:

```c
ULONG64 OriginalGetCpuClock;

ULONG64 HookedGetCpuClock(void) {
    PKTHREAD t = KeGetCurrentThread();
    ULONG syscallNum = *(PULONG)((UCHAR*)t + KTHREAD_SYSTEMCALLNUMBER_OFFSET);

    if (syscallNum == NTPROTECTVIRTUALMEMORY_NUMBER) {
        // intercept here - argument frame is in the caller's stack
    }

    return OriginalGetCpuClock();
}
```

The mechanism is reachable from a kernel driver that can find CKCL's `WMI_LOGGER_CONTEXT` (walk `PspHostSiloGlobals -> EtwSiloState -> EtwpLoggerContext[]`, or use debugger/PDB-derived ETW debugger data, then look for the `"Circular Kernel Context Logger"` name and the CKCL instance GUID). The attacker also has to configure CKCL's `EnableFlags` so that the desired hot event class is actually emitted. This is commonly done through the same `NtTraceControl`/`ZwTraceControl` family that backs `StartTrace` and `ControlTrace`, with the internal `WMI_LOGGER_INFORMATION` carrying the logger name, instance GUID, flags, and mode.

The point that must be precise: **the direct pointer swap is the old primitive, not the whole InfinityHook family**.

### 10.2 The Index Patch Did Not End the Family

Microsoft's mitigation changed `GetCpuClock` from a raw function pointer into a small clock-source selector. That breaks the direct "write my kernel pointer into `GetCpuClock`" recipe. It does **not** mean ETW is no longer usable as a hook surface.

Public reversing of Windows 11 24H2 shows the modern dispatch roughly as:

| `GetCpuClock` value | Observed timestamp path | Hook implication |
|--------------------:|-------------------------|------------------|
| `0` | `RtlGetSystemTimePrecise()` | Ordinary system-time path; not the common hook branch. |
| `1` | `KeQueryPerformanceCounter()` | Reaches the HAL registered timer / performance-counter backend; modern InfinityHook-like work focuses here. |
| `2` | `HalPrivateDispatchTable.HalTimerQueryHostPerformanceCounter()` | Older alternate HAL dispatch path; protection and viability are build-specific. |
| `3` | `__rdtsc()` | Fast cycle-counter path; no obvious writable callback in this branch. |
| `> 3` | fast-fail / bugcheck | Useful as a corruption signal, not as a hook. |

This is the correction to the common myth. Windows 11 22H2/24H2/25H2-era kernels do not let you directly store an arbitrary function pointer in `GetCpuClock`, but a controller with kernel write can still force CKCL into a clock mode that reaches a mutable downstream callback. Anže Lešnik described the post-index idea in the Windows 10 20H1 timeframe; Denis Skvortcov showed the same family in a Windows 11 22H2 Avast self-defense analysis; Archie's 2025 writeup tested the context-swap variant on Windows 11 24H2.

### 10.3 Modern HAL Timer / QueryCounter Hook

The modern branch is:

```text
ETW event write
  -> EtwpReserveTraceBuffer / EtwpLogKernelEvent
      -> LoggerContext->GetCpuClock == 1
          -> KeQueryPerformanceCounter()
              -> hal!_REGISTERED_TIMER.FunctionTable.QueryCounter(...)
                  -> attacker hook
```

The tradeoff is that `KeQueryPerformanceCounter` is not ETW-only. It is an extremely hot timing primitive used throughout the kernel and drivers. A working hook therefore has to distinguish "called from ETW for the logger I care about" from ordinary QPC calls. Public 24H2 reversing reported that the ETW-originating path had a pointer to the logger context in `r15`; older or different builds may require scanning the current stack for a plausible `WMI_LOGGER_CONTEXT` pointer. This is exactly the kind of per-build assumption a production defender should verify with symbols and live tests instead of copying from a blog post.

For syscall interception, the target is still the same conceptual frame as classical InfinityHook: `PerfInfoLogSyscallEntry` runs before the final `Nt*` handler is invoked, and the handler pointer or enough syscall context is still recoverable from the stack/register state on the tested builds. The hook does not "blind ETW"; it uses ETW's timestamp side path to run code at the moment ETW is recording the syscall.

The detection model changes from "is `GetCpuClock` a kernel pointer?" to:

1. Is CKCL unexpectedly configured to a clock mode that routes through QPC/HAL for the event class in question?
2. Does `hal!_REGISTERED_TIMER.FunctionTable.QueryCounter` resolve to the expected `hal.dll`/`ntoskrnl.exe` image range?
3. Is the pointer stable across boot and across CPU power-management transitions?
4. Does the caller filter inside the hook rely on an ETW-specific register or stack artifact that a defender can sample in a lab build?

The strongest artifact is not `GetCpuClock == 1` by itself; that can be legitimate. The stronger artifact is the HAL timer callback pointing outside the signed HAL/nt image range while CKCL is configured to route high-frequency events through that branch.

### 10.4 ETW Context-Swap Hooks

The 2025 context-swap variant moves the target event from syscall entry to scheduler transitions. CKCL can emit context-switch events, and the ETW path reaches `EtwpLogContextSwapEvent` before it reserves and timestamps the event. On the tested 24H2 build, the old/new thread pointers were still recoverable from registers or from the function prologue's saved copies before the timestamp hook ran.

That gives a driver a callback on every context switch without patching the scheduler, SSDT, or `KiSwapContext` directly:

```text
scheduler transition
  -> ETW context-switch emission
      -> EtwpLogContextSwapEvent
          -> EtwpReserveTraceBuffer timestamp path
              -> HAL QueryCounter hook
```

This is broader than syscall hooking. It can observe thread transitions that never involve a user-mode syscall boundary, and it can be used defensively or offensively: anti-cheats can inspect the outgoing thread's stack for unsigned execution, while cheats can use the transition to swap page-table or memory-visibility state for selected threads. It is also more fragile: it runs at scheduler-sensitive timing, it is vulnerable to IRQL/performance mistakes, and it depends on exact register/stack layout around `EtwpLogContextSwapEvent`.

### 10.5 Defensive Takeaway

The correct 2026 statement is:

```text
Classical GetCpuClock direct-pointer InfinityHook is gone on modern builds.
InfinityHook-style ETW hot-path hooking survived by moving to downstream
timestamp backends and to other ETW-emitted hot events such as context switches.
```

For defenders, that means a kernel ETW verifier must include the clock backend, not just the logger context. Verify `WMI_LOGGER_CONTEXT.GetCpuClock`, CKCL `EnableFlags`, `HalPrivateDispatchTable` timer callbacks where used, `hal!_REGISTERED_TIMER.FunctionTable.QueryCounter`, and whether those pointers land in trusted image ranges. If KDP/HVCI is enabled, also verify whether the relevant timer/dispatch pages are protected on the actual build; do not assume they are protected because the machine is "VBS on".

---

## 11. Tampering ETW: From User-Mode Patch to BYOVD DKOM

### 11.1 User-Mode Patches (`ntdll!Etw*`)

The simplest bypass: patch the first bytes of `ntdll!EtwEventWrite` or `ntdll!NtTraceEvent` to `C3` (ret), or, slightly more subtly, patch `EtwEventEnabled` to `33 C0 C3` (xor eax, eax; ret) so the *provider* believes it is disabled and skips the event-write path. Variants exist for `NtTraceEvent` itself, with the same effect.

These patches affect only the patched process. They do not touch kernel ETW providers. `Microsoft-Windows-Kernel-Process` keeps emitting process-create events from inside the kernel regardless of how aggressively user-mode ntdll has been patched, because the kernel side calls `EtwWrite` directly. So:

- User-mode ETW patches *do* bypass `Microsoft-Windows-PowerShell` event 4104 inside a single PowerShell instance, because the writer lives in user mode.
- They *do not* bypass `Microsoft-Windows-Kernel-Process` event 1 (process creation), because the writer lives in the kernel.
- A modest EDR detection: periodically verify the first bytes of `EtwEventWrite` in its own process against the known good prologue. Anything else is tampering.

### 11.2 Kernel DKOM Once an Attacker Has Kernel Write

With BYOVD or a kernel exploit, every ETW state byte becomes writable. The smallest possible primitives:

```c
// (1) Nullify the ETWTI registration handle in ntoskrnl.exe .data
*(PVOID*)EtwThreatIntProvRegHandle = NULL;
// -> every EtwTiLog* call sees a NULL handle and short-circuits via its
//   own NULL check (or via the EnableMask test inside EtwpWriteUserEvent)

// (2) Disable a specific provider
GuidEntry->ProviderEnableInfo.IsEnabled = 0;

// (3) Disable one enable slot. The array index is 0..7, not LoggerId.
GuidEntry->EnableInfo[slot].IsEnabled = 0;

// (4) Starve one slot by using an impossible keyword for this provider.
// MatchAnyKeyword = 0 usually means "match all", so do not use zero.
GuidEntry->EnableInfo[slot].MatchAnyKeyword = ImpossibleKeywordBit;

// (5) Clear a registration's session-bitmask
RegEntry->EnableMask = 0;
```

Each primitive is between 1 and 8 bytes and runs in nanoseconds. None of them creates a noisy artifact like "ETW session terminated"; they merely silence the path. The only ways to detect any of them are (a) consistency cross-check against the controller's expected state, (b) KDP/HVCI making the underlying page non-writable, or (c) PatchGuard/KPP eventually noticing protected state corruption on builds where the touched field is in its sampled set. Do not rely on PatchGuard as a deterministic detector; it is randomized, build-specific, and intentionally underdocumented.

Lazarus's *FudModule* is the canonical implementation of (1) for ETWTI specifically: scan `ntoskrnl!.text` for `call EtwRegister` sites, walk back to the argument that stores the resulting handle into a global, follow the global to its `.data` address, write `NULL`. The technique is generic. It works for every provider whose registration handle ends up in writable kernel `.data`, which is essentially all of them.

A particularly heavy-handed variant is to write zero into `EtwpActiveSystemLoggers`, the bitmask of currently running system loggers, which retires NT Kernel Logger and CKCL in one stroke. The signal is severe enough that even amateur defenders notice; the more sophisticated implementations of the FudModule family selectively zero only the ETW handles of providers the attacker dislikes (ETWTI, Kernel-Process) and leave the rest alone so that idle-traffic statistics keep flowing.

### 11.3 Patchless Bypass: Hardware Breakpoints + VEH

Once EDRs began verifying `ntdll!Etw*` byte integrity, offensive research moved to *not modifying memory at all*. The Turla "Kazuar v3" malware (publicly reported in 2023 by Lab52 / Sentinel Labs analyses, with subsequent open-source PoC implementations refining the technique through 2024) is illustrative:

```text
1. GetThreadContext on the current thread.
2. Set Dr0 = NtTraceEvent_addr, Dr1 = AmsiScanBuffer_addr, Dr7 to enable both.
3. NtContinue(&ctx, FALSE)      ← NOT SetThreadContext.
4. AddVectoredExceptionHandler(1, MyVEH).
5. MyVEH on EXCEPTION_SINGLE_STEP at NtTraceEvent:
     adjust ctx->Rip to a RET, set Rax=STATUS_SUCCESS;
     return EXCEPTION_CONTINUE_EXECUTION.
```

Two design choices justify the awkwardness:

- **`NtContinue` instead of `SetThreadContext`** - `SetThreadContext` flows through `PspSetContextThreadInternal`, which emits the ETWTI set-thread-context event (`SETTHREADCONTEXT_REMOTE`, event ID 5 on current 26200 metadata). `NtContinue` restores a context onto the calling thread directly without traversing that path, so no cross-thread ETWTI set-context event fires. The trade-off is that `NtContinue` only works on the current thread.
- **Vectored exception handler instead of inline patching** - the hardware-breakpoint approach leaves the target instruction untouched. EDRs that hash-check function prologues see nothing wrong; only inspecting `Dr0..Dr7` on every thread reveals the trick.

Limitations the defender can lean on: x86/x64 has only four debug registers, the breakpoints are per-thread (a new thread spawned by the same process gets `Dr0..Dr7 = 0`), and VEH registration is observable through `RtlpCallVectoredHandlers` instrumentation or via `Microsoft-Windows-Kernel-Process` image-load events for `KERNELBASE.dll` followed by RIP heuristics. *White Knight Labs'* `LayeredSyscall` (2024) raises this further by using two layers of VEH. The first handles the attacker's own single-step exceptions, the second is a decoy chain installed to confuse EDRs that walk `RtlpCallVectoredHandlers`.

### 11.4 Argument-Spoofing Bypasses (TamperingSyscalls and Heirs)

`TamperingSyscalls` (rad9800, 2022-2024) targets not ETW itself but the *story* a user-mode EDR builds from ETW events. The technique:

```text
1. Caller builds a "benign" argument frame on the stack.
2. Sets a hardware breakpoint at the syscall instruction inside the ntdll stub.
3. VEH fires immediately before SYSCALL: rewrites the argument registers
   (RCX, RDX, R8, R9) and the stack to the malicious values.
4. SYSCALL executes with the real, dangerous arguments.
5. Kernel performs the operation and emits ETW/ETWTI events with the real values.
6. On return, VEH restores the original "benign" frame so any post-call
   user-mode telemetry sees the lie.
```

The technique disrupts EDRs that infer event semantics by tailing the syscall stub or by mirroring its arguments to a user-mode logger. **Kernel ETWTI is unaffected**. `EtwTiLogProtectExecVm` fires from inside `MiProtectVirtualMemory` after the kernel has already received the real arguments, so the event payload contains the actual `PAGE_EXECUTE_READWRITE` mask. The bypass therefore only hurts EDRs whose detection logic lives in user mode or which correlate against user-mode argument captures.

Detecting it: correlate ETWTI's kernel-side payload against any user-mode "shadow" of the same syscall and alert on divergence; or hook the IDT `#DB` handler to observe hardware-breakpoint activity at the syscall boundary; or scan `Dr0..Dr7` periodically on every thread (the same defense as patchless ETW bypass).

### 11.5 RPC Provider Bypass (`rpcrt4!_g_fProfile`)

`Microsoft-Windows-RPC` (`{6ad52b32-d609-4be9-ae07-ce8dae937e39}`) emits interface-UUID-attributed call events that detection rules for lateral movement (`IRemoteWinspoolSvc`, `ITaskScheduler2`, `lsarpc` credential dumps, DRSUAPI / DCSync) depend on. Inside `rpcrt4.dll` a process-local enable cache derived from `EtwEventEnabled` controls whether the provider emits events at all (the exact symbol name varies by build. Pre-public-symbols literature has referred to it as `_g_fProfile`, but the canonical mechanism is the per-process provider state cached by ntdll/rpcrt4 after the first `EtwEventEnabled` call). The bypass:

```c
// (cross-process variant) - kill RPC telemetry inside the target server
PVOID target = GetProcAddress(GetRpcrt4InRemoteProcess(pid),
                               "rpcrt4_g_fProfile_or_equivalent");
ULONG zero = 0;
WriteProcessMemory(hRemote, target, &zero, sizeof(zero), NULL);
// the inbound RPC server no longer emits ETW events for any call
```

The effect is process-local. The rest of the system's RPC telemetry continues, but it removes the inbound-call attribution from the specific server (e.g., `lsass.exe`, `spoolsv.exe`, `services.exe`) the attacker is moving through. Detection requires correlating *kernel-side* signals against the *absence* of expected `Microsoft-Windows-RPC` events for the same time window: `Microsoft-Windows-Kernel-Network` TCP-receive on RPC ports, `Microsoft-Windows-Kernel-File` named-pipe creates for the named-pipe transport, and `Microsoft-Windows-Kernel-Audit-API-Calls` `NtOpenProcess` against `lsass.exe`.

### 11.6 Call-Stack Spoofing

Once an EDR is collecting stacks via `EVENT_FILTER_TYPE_STACKWALK`, the next move is to make those stacks lie. Three publicly documented techniques are widely adopted:

- **`SilentMoonwalk` / `klezVirus`**. Desynchronizes the stack by JOP-chaining through `__C_specific_handler` to forge a fake `RUNTIME_FUNCTION` chain. ETW's stack walk produces an attribution to `ntdll!RtlUserThreadStart` instead of the malicious frame. Defeats every walker that relies on `.pdata` for unwind.
- **`CallStackSpoofer` / `VulcanRaven` (mgeeky)**. Pushes synthetic frames and registers attacker-supplied unwind info via `RtlAddFunctionTable`. ETWTI's captured chain attributes to whichever benign function the unwind info names.
- **Kernel-side variants** abusing `KeUserModeCallback` to dirty the kernel stack such that `RtlWalkFrameChain` returns truncated frames. Production anti-cheat drivers (publicly seen in Vanguard) sanity-check the RSP delta between captured frames against the actual stack page layout and flag implausibly large deltas.

The systemic defense is Intel CET shadow-stack. With CET enforced (Tiger Lake+ CPUs, 24H2/25H2 SystemGuard-eligible boxes), every spoofed return can mismatch the shadow stack, producing either a `#CP` exception or an audit signal through CET/platform telemetry. Do **not** hard-code this as ETWTI event ID 21; on current 26200 metadata, ID 21 is an alloc-VM kernel-caller event. On CET-incapable hardware the practical fallback is to treat any stack ending in `ntdll!RtlUserThreadStart` with no plausible inner frames, or any chain with implausibly small page deltas between frames, as a tampering signal worth escalating to a memory scan.

### 11.7 ProcessInstrumentationCallback Redirection

`NtSetInformationProcess(ProcessInstrumentationCallback)` installs a per-process callback that the kernel invokes on every syscall return into user mode. Originally a Wow64 thunk facility, the primitive is documented enough that offensive use is now standard:

```c
PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = {0};
info.Callback = my_user_mode_callback;   // RIP that the kernel jumps to
info.Version  = 0;
NtSetInformationProcess(GetCurrentProcess(),
                        ProcessInstrumentationCallback,
                        &info, sizeof(info));
```

After installation, when the kernel returns to user mode at the end of any syscall, control jumps to `my_user_mode_callback` *instead* of resuming the original return address; the original RIP is passed to the callback via a CPU register (R10 on x64 in publicly documented PoCs, though the precise calling convention is internal and not officially documented), and the callback is expected to jump back to it after running. The callback can inspect or modify return values, gate which syscalls produce "visible" effects, or rewrite event-emission state. Two distinct offensive uses against ETW:

1. **Suppress event emission by detecting the syscall return and short-circuiting before any user-mode side effect.** Because the callback runs after the kernel has already emitted its ETW events, this does *not* defeat ETWTI or kernel ETW - those events are already in the buffer. It does, however, defeat any user-mode "post-syscall" telemetry that an EDR's user-mode component attempts.
2. **Spoof return values to defeat consistency checks.** Elastic Security Labs' 2023 detection content explicitly looks for unusual `ProcessInstrumentationCallback` installation because it is a documented EDR-evasion primitive - almost no benign software installs it.

The kernel keeps the callback pointer in `EPROCESS.InstrumentationCallback`. Detection: monitor `NtSetInformationProcess` callers via ETWTI keywords, or sample `EPROCESS.InstrumentationCallback` for every process and alarm on a non-NULL value outside the Wow64-on-x64 emulation set.

### 11.8 Filter-Inversion Tampering

A subtler primitive: an attacker with controller-level access to an existing session (`TRACELOG_GUID_ENABLE` rights on the session's GUID, typically requiring `SeSystemProfilePrivilege` or session ownership) can try to re-enable a provider with a narrower `ENABLE_TRACE_PARAMETERS` filter such as `EVENT_FILTER_TYPE_PID` or `EVENT_FILTER_TYPE_EXECUTABLE_NAME`. For providers and session types that honor the filter at delivery time, the EDR consuming that session can see a clean stream while every other process continues to emit normally. This requires admin or `SeSystemProfilePrivilege`, but not kernel write.

Detection is trickier than many writeups imply. `TraceProviderBinaryTracking` is for mapping provider events back to image binaries; it is not a general "list all active filters/controllers" API. The reliable production pattern is to own the session handle lifecycle, record the exact `ENABLE_TRACE_PARAMETERS` applied by the EDR, subscribe to `Microsoft-Windows-Kernel-EventTracing` for enable/disable metadata, periodically re-query provider/session state where public APIs expose it, and treat any external `EnableTraceEx2` against a protected session/provider as tampering. A kernel-side verifier can also compare `ETW_GUID_ENTRY.EnableInfo[i]` and `FilterData` against its expected baseline, but that is inherently offset-sensitive.

### 11.9 Consumer and Delivery-Path Tampering

Provider DKOM is not the only way to blind an ETW-dependent product. A real-time EDR has two separate trust edges: provider-to-session and session-to-consumer. The first is `ETW_GUID_ENTRY.EnableInfo[]`; the second is `WMI_LOGGER_CONTEXT.Consumers` plus the real-time buffer handoff state. An attacker with kernel write can leave provider enablement intact while making the consumer stop receiving buffers:

```text
Provider is still enabled
    EnableInfo[i].IsEnabled == 1
    RegEntry.EnableMask bit set

Session is no longer useful
    WMI_LOGGER_CONTEXT.AcceptNewEvents = 0
    WMI_LOGGER_CONTEXT.LoggerStatus changed
    WMI_LOGGER_CONTEXT.Consumers unlinked or poisoned
    ETW_REALTIME_CONSUMER.DataAvailableEvent never signaled
    RealTimeBuffersLost / EventsLost climb rapidly
```

This is operationally attractive because controller-side checks that only ask "is my provider enabled" still pass. File-mode sessions are more resilient to consumer unlinking because the flusher writes ETL buffers to disk, but they can still be starved by setting session state, exhausting buffers, corrupting the flush queues, or forcing loss through pathological event rates. Real-time sessions are easier to blind because delivery depends on the consumer object and its notification path staying healthy.

The defensive check must therefore validate the entire path:

1. Provider state: expected `ETW_GUID_ENTRY.EnableInfo[i]`, `TRACE_ENABLE_INFO`, `ETW_REG_ENTRY.EnableMask`, and filter data.
2. Session state: `AcceptNewEvents`, `LoggerStatus`, `EventsLost`, `LogBuffersLost`, `RealTimeBuffersLost`, `NumberOfBuffers`, `FreeBuffers`, and `Consumers`.
3. Consumer state: expected PID / process object on `WMI_LOGGER_CONTEXT.Consumers`, live process handle, callback liveness, and an application-layer heartbeat.
4. End-to-end delivery: a defender-owned canary provider emits a periodic event, and the user-mode consumer proves it received that exact sequence number within a bounded interval.

The canary matters because every individual internal field can be spoofed. End-to-end delivery is the only check that crosses all three layers: provider wrote, session accepted, buffer flushed, consumer processed.

### 11.10 Hooking and Bypass Techniques Mapped to ETW Layers

The references in the "Hooking and bypass" section are often grouped together, but they do not attack the same thing. Some use ETW as a hook delivery mechanism, some corrupt ETW's provider state, some bypass only user-mode ETW emission, some lie to stack enrichment, and some do not bypass ETW at all. They bypass the EDR's interpretation of ETW.

The useful way to read them is by ETW layer:

| Technique / family | ETW layer attacked | What it bypasses | What it does **not** bypass |
|--------------------|-------------------|------------------|-----------------------------|
| Classical InfinityHook | Session hot path (`WMI_LOGGER_CONTEXT.GetCpuClock` direct pointer) | Uses CKCL/NT Kernel Logger timing path as a syscall hook point | Not an ETW blinding technique; the direct pointer field is gone on modern builds |
| Modern InfinityHook family | Downstream timestamp backend (`KeQueryPerformanceCounter` / HAL timer `QueryCounter`) | Restores ETW hot-path control after the `GetCpuClock` index patch | Still does not stop ETW events from being written; high false-positive risk if defender checks only `GetCpuClock == 1` |
| ETW context-swap hooks | CKCL context-switch event path / timestamp backend | Uses ETW's always-on scheduler trace path for kernel control on thread transitions | Does not stop ETW events from being written; depends on fragile scheduler-path register/stack layout |
| Wavestone / Binarly / EDRSandBlast-style ETW DKOM | Provider registration / enable state | ETWTI, Kernel-Process, or vendor provider emission | Non-ETW callbacks, minifilters, WFP, memory scans |
| `ntdll!Etw*` patching / White Knight Labs-style user-mode patch | User-mode producer stub | Manifest / TraceLogging events emitted by that process | Kernel providers, other processes, AutoLogger file traces |
| Patchless hardware-breakpoint + VEH | User-mode call transition to `NtTraceEvent` / `AmsiScanBuffer` | Inline-patch detection and user-mode provider emission on that thread | Kernel ETW / ETWTI for operations that actually enter the kernel |
| `LayeredSyscall` | User-mode EDR hook and VEH/call-stack inspection layer | Hook-based syscall monitors and naive VEH walkers | Kernel-side ETWTI payloads |
| `TamperingSyscalls` | User-mode syscall-argument shadowing | EDRs that record "benign" arguments before syscall entry | ETWTI's kernel-side event payload after argument validation |
| `SilentMoonwalk`, `CallStackSpoofer`, `VulcanRaven` | ETW stack enrichment / unwind trust | Stack-based attribution rules using `EVENT_HEADER_EXT_TYPE_STACK_TRACE64` | The base ETWTI or Kernel-Process event itself |
| RPC ETW evasion | Provider-specific producer state inside `rpcrt4.dll` | `Microsoft-Windows-RPC` interface/call telemetry in the patched process | Kernel network, SMB/named-pipe, Audit-API, process/handle telemetry |
| `EVENT_FILTER_TYPE_EXECUTABLE_NAME` filter inversion | Controller/session filter state | Delivery to a protected session for selected process names | Provider emission to other sessions, controller/meta-provider audit if intact |

#### 11.10.1 ETW as a Hook Surface: InfinityHook and Context-Swap Hooks

InfinityHook is not primarily a "hide from ETW" technique. It is the opposite: it abuses the fact that ETW is everywhere. In the classical form, CKCL's `WMI_LOGGER_CONTEXT.GetCpuClock` was a callable function pointer. Because CKCL logs syscall-related and scheduler-related events, swapping that pointer gave an attacker-controlled kernel routine execution on a hot path. The attacked object is the **session control block**, not a provider.

The primitive is powerful because it does not need to patch `KiSystemCall64`, the SSDT, or `nt!Nt*` routines. The attacker rides a legitimate ETW timestamp callback:

```text
syscall entry
  -> PerfInfoLogSyscallEntry
      -> CKCL WMI_LOGGER_CONTEXT.GetCpuClock()
          -> attacker hook
```

Modern Windows changed the load-bearing field. `GetCpuClock` is now treated as a small clock-source selector, not an arbitrary kernel pointer. That closes only the direct `GetCpuClock = attacker_function` path. The successor families move one layer down or sideways: HAL performance-counter function-pointer swaps target the timestamp backend reached by selected clock modes, while context-swap hooks target the ETW/scheduler path that emits `CSwitch`-style events.

Detection logic should not ask "did ETW stop?". It should ask whether a supposedly boring ETW timing or scheduler path now points outside the expected kernel/HAL image interval. A CKCL session with unexpected clock configuration, a HAL counter callback outside the signed HAL/nt image range, or a context-switch hook target outside a loaded module is hook evidence, not telemetry-loss evidence.

#### 11.10.2 Provider-State DKOM: Wavestone, Binarly, EDRSandBlast, FudModule

The Wavestone/Binarly/EDRSandBlast/FudModule family attacks the **provider enablement and registration layer**. This is the cleanest ETW blinding primitive once the attacker has kernel write.

The target fields are the ones that make the fast path cheap:

```text
ETW_REG_ENTRY.EnableMask
ETW_REG_ENTRY.GroupEnableMask
ETW_GUID_ENTRY.ProviderEnableInfo.IsEnabled
ETW_GUID_ENTRY.EnableInfo[i].IsEnabled
ETW_GUID_ENTRY.EnableInfo[i].Level / MatchAnyKeyword / MatchAllKeyword
kernel global registration handles such as EtwThreatIntProvRegHandle
```

The bypass effect depends on which byte is changed. Clearing a provider's kernel registration handle makes every `EtwTiLog*` call take the "provider not registered" path. Clearing `ProviderEnableInfo.IsEnabled` makes the provider appear globally disabled. Clearing one `EnableInfo[i]` slot blinds only one logger. Rewriting `MatchAnyKeyword` to an impossible keyword starves one session without obviously disabling the provider.

This is why these techniques are dangerous: they do not stop the EDR service, do not necessarily stop the ETW session, and do not need to patch executable code. The session can still look alive while the provider is no longer feeding it.

The defensive answer is the integrity sweep in §12.2 plus a canary event. Querying `ControlTrace` alone is not enough, because public session state can remain normal while the provider's private enable slots are corrupted. A production anti-cheat should compare expected provider GUID, registration handle, `EnableMask`, `ProviderEnableInfo`, `EnableInfo[]`, filters, and canary delivery as one invariant.

#### 11.10.3 User-Mode Producer Patching: `ntdll!Etw*`

The classic White Knight Labs-style user-mode ETW bypass attacks the **producer stub** inside the process. Patching `ntdll!EtwEventWrite`, `ntdll!NtTraceEvent`, or `EtwEventEnabled` affects providers whose write path runs in that process. PowerShell, .NET runtime, RPC client/server code, AMSI-facing user-mode components, and many TraceLogging providers are in this category.

The boundary is strict:

```text
patched powershell.exe:
    Microsoft-Windows-PowerShell 4104 may disappear
    Microsoft-Windows-DotNETRuntime events from that process may disappear

kernel:
    Microsoft-Windows-Kernel-Process still emits process start
    ETWTI still emits remote VM write / protect / set-context events
    AutoLogger file-mode sessions still receive kernel-originated events
```

So this class bypasses **local user-mode event emission**, not ETW as a system. A detector that treats "no PowerShell ETW" as "nothing happened" is weak; a detector that correlates PowerShell process activity, AMSI 1101, Kernel-Process, ETWTI, image loads, command-line lineage, and zero-event silence can still catch it.

#### 11.10.4 Patchless User-Mode Suppression: Hardware Breakpoints, `NtContinue`, VEH

Patchless ETW/AMSI bypasses attack the same producer boundary as inline patching, but avoid changing bytes. The usual recipe is hardware breakpoints plus a vectored exception handler:

```text
Dr0 = ntdll!NtTraceEvent
Dr1 = amsi!AmsiScanBuffer
VEH handles EXCEPTION_SINGLE_STEP
VEH rewrites RIP/RAX/result state
execution resumes as if the call succeeded
```

The ETW-specific target is the transition into `NtTraceEvent`. If the thread never actually enters the syscall, the user-mode provider's event is never handed to the kernel ETW writer. `NtContinue` matters because it restores the current thread context without going through the same cross-thread `SetThreadContext` path that ETWTI logs via `PspSetContextThreadInternal`.

This bypasses inline-hook detection because `ntdll` and `amsi.dll` bytes remain clean. It does not bypass kernel ETW for real kernel operations. If the process later calls `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, or `NtMapViewOfSection`, ETWTI still sees the kernel-side behavior.

Detection lives outside the patched bytes: debug registers, suspicious VEH chains, `NtContinue` context restoration patterns, a sudden loss of user-mode provider events from a still-active process, and disagreement between user-mode event silence and kernel event activity.

#### 11.10.5 LayeredSyscall and Argument Tampering: Bypassing the EDR Story, Not ETW

`LayeredSyscall` and `TamperingSyscalls` are frequently described as ETW bypasses, but the more precise statement is that they bypass **EDR interpretation layers around syscalls**.

`LayeredSyscall` complicates user-mode hook and VEH inspection by stacking exception layers and syscall transitions so that an EDR walking the obvious handler list or return path sees a decoy. `TamperingSyscalls` builds a benign-looking argument frame, then rewrites registers immediately before `syscall`. The EDR's user-mode sensor may record "benign" arguments; the kernel receives the real ones.

For ETWTI, this distinction matters:

```text
user-mode sensor sees:
    NtProtectVirtualMemory(Base=X, Protect=PAGE_READONLY)

kernel receives:
    NtProtectVirtualMemory(Base=X, Protect=PAGE_EXECUTE_READWRITE)

ETWTI logs:
    executable-memory transition, because MiProtectVirtualMemory saw the real value
```

The attacked layer is therefore not `ETW_GUID_ENTRY`, not `WMI_LOGGER_CONTEXT`, and not `EtwWrite`. It is the **pre-syscall narrative**. The correct detector compares kernel-originated ETWTI payloads against any user-mode shadow telemetry. If they disagree, the user-mode story is the suspect one.

#### 11.10.6 Stack-Spoofing: Attacking ETW Enrichment

`SilentMoonwalk`, `CallStackSpoofer`, and `VulcanRaven` attack the **stack enrichment** that many EDRs attach to ETW events. They do not usually suppress the event. Instead, they make the event less useful.

When a controller enables `EVENT_ENABLE_PROPERTY_STACK_TRACE` or a stack-walk filter, ETW can attach `EVENT_HEADER_EXT_TYPE_STACK_TRACE64` or a stack-cache key to the event. EDR rules then ask questions such as:

```text
Who called NtAllocateVirtualMemory?
Does the stack contain an unbacked RX region?
Does the stack cross from a known module into private executable memory?
Does the chain end at a plausible thread start?
```

Stack spoofing attacks those questions. `SilentMoonwalk` abuses exception/unwind mechanics to desynchronize the real stack from the unwind-visible stack. `CallStackSpoofer` and `VulcanRaven` create synthetic frames or attacker-controlled unwind metadata so that the ETW-captured stack points at benign modules.

The event still exists. The memory allocation, thread context change, or handle operation still reaches ETWTI. What changes is the call-chain attribution. Defenders should treat stack data as high-value but not self-authenticating: validate frame addresses against VADs and loaded modules, check unwind metadata ownership, use CET shadow-stack audit where available, and use LBR/context-register capture in suspicion-scoped traces when a normal stack looks too clean.

#### 11.10.7 Provider-Specific Producer State: RPC ETW Evasion

RPC ETW evasion attacks a provider-specific cache inside `rpcrt4.dll`, not the global ETW subsystem. `Microsoft-Windows-RPC` emits useful interface/call telemetry for lateral movement and credential-access paths. The RPC runtime caches whether profiling/ETW is enabled so that hot RPC paths do not call into ETW machinery unnecessarily on every call.

If an attacker patches that process-local cache in `lsass.exe`, `spoolsv.exe`, or another RPC server, the RPC provider stops producing events in that process. The ETW session may still be healthy, and other providers may still emit normally.

This makes the bypass narrow but operationally valuable. It blinds rules that depend on `Microsoft-Windows-RPC` interface UUID events, while leaving transport reality untouched. The defensive cross-view is:

```text
Kernel-Network sees RPC traffic
Kernel-File sees named-pipe transport
Audit-API sees process/handle access
Service Control / DCOM / SMB telemetry sees lateral movement context
Microsoft-Windows-RPC is silent for the same server and interval
```

That absence is the signal.

#### 11.10.8 Filter Inversion: Attacking the Controller Contract

`EVENT_FILTER_TYPE_EXECUTABLE_NAME` and related filters are legitimate controller features. A controller can ask ETW to deliver only selected PIDs, executable names, event IDs, payload patterns, or stack-walk targets. Filter-inversion abuse happens when an attacker with controller-level rights narrows or excludes the process the defender cares about.

This attacks **session configuration**, not provider code. The provider still emits. Other sessions may still receive events. Only the protected session's view is shaped.

The dangerous case is subtle:

```text
provider enabled: yes
session running: yes
consumer alive: yes
events from benign processes: yes
events from target process: no
```

The defense is to treat filters as part of the integrity baseline. Record the exact `ENABLE_TRACE_PARAMETERS` used by the defender, subscribe to `Microsoft-Windows-Kernel-EventTracing` for enable/disable changes, and verify the private `ETW_GUID_ENTRY.EnableInfo[i].FilterData` when a kernel verifier is available. `TraceProviderBinaryTracking` helps correlate provider events to binaries; it does not reconstruct arbitrary hostile filters after the fact.

---

## 12. Defense and Detection

### 12.1 The Hardware Backstops: PatchGuard, KDP, HVCI

- **PatchGuard (KPP)** periodically samples kernel `.text` and selected kernel data structures. Some ETW-adjacent state is known to be guarded on modern builds, but the exact coverage is intentionally undocumented and shifts over time. Treat bug-check 0x109 as a useful post-incident artifact, not as an engineering guarantee that every ETW DKOM byte will be caught quickly.
- **KDP** (Kernel Data Protection), available where VBS/HVCI is on, allows a driver to call `MmProtectDriverSection` on its own `.data` to mark pages read-only at the SLAT level. The hypervisor enforces the read-only-ness; an attempted write triggers an EPT violation and a crash. The trick for ETW is that protected pages must actually cover the state you rely on. KDP-protecting a driver's own registration-handle storage helps; assuming every ntoskrnl ETW global is KDP-protected on every build is not safe without live verification.
- **HVCI** restricts the kernel from executing unsigned pages, which (combined with WDAC driver-block-lists) is the principal countermeasure to BYOVD. HVCI's *gap* historically has been signed-but-vulnerable third-party drivers; Microsoft's driver-blocklist updates have closed many but not all of these.

None of these are sufficient on their own; each is a layer with known gaps. The composite system (Secure Boot + ELAM + HVCI + KDP + driver-blocklist + measured boot via TPM 2.0) is what current high-stake anti-cheat (Vanguard 2024+) is asking for, because it is the only configuration on consumer Windows where kernel ETW state is meaningfully tamper-resistant.

### 12.2 Kernel ETW Integrity Checks

An EDR or anti-cheat driver that wants to detect FudModule-class tampering walks its known-good provider registration handles every few seconds and compares to expected state:

```c
VOID PeriodicEtwIntegrityCheck(void)
{
    PETW_REG_ENTRY etwti = *(PETW_REG_ENTRY*)EtwThreatIntProvRegHandle;
    if (!etwti) { Report(ETW_TI_HANDLE_NULLED); return; }
    if (!MmIsAddressValid(etwti) || !MmIsAddressValid(etwti->GuidEntry)) {
        Report(ETW_TI_INVALID_POINTER); return;
    }

    PETW_GUID_ENTRY g = etwti->GuidEntry;
    if (!g->ProviderEnableInfo.IsEnabled)
        Report(ETW_TI_DISABLED);

    BOOLEAN ours = FALSE;
    for (int i = 0; i < 8; i++) {
        if (g->EnableInfo[i].LoggerId == g_OurLoggerId &&
            g->EnableInfo[i].IsEnabled) {
            ours = TRUE;
            if (g->EnableInfo[i].Level < g_ExpectedLevel)
                Report(ETW_LEVEL_DOWNGRADED);
            break;
        }
    }
    if (!ours) Report(ETW_SESSION_DETACHED);

    PWMI_LOGGER_CONTEXT ctx = EtwpLoggerContext[g_OurLoggerId];
    if (!ctx || ctx == (PVOID)1) { Report(ETW_CONTEXT_FREED); return; }
    if (!ctx->AcceptNewEvents) Report(ETW_NOT_ACCEPTING);

    LONG lostDelta = ctx->EventsLost - g_LastEventsLost;
    if (lostDelta > THRESHOLD) Report(EVENTS_LOST_SPIKE);
    g_LastEventsLost = ctx->EventsLost;
}
```

The interesting thing about this check is what it does *not* require: it does not need the events themselves to be flowing. The integrity of the configuration is observable independently of the event stream, which means tampering that silences events still leaves a kernel-visible diff against expected state.

### 12.3 Zero-Event Detection

The dual of the integrity check is the behavioral signal. A process with substantial activity, such as outbound network connections, file writes, and executable-memory allocations, that produces *zero* events on a provider that should be talking about it is, by elimination, either pre-instrumented (a tool that genuinely doesn't trigger that provider) or actively bypassing ETW. The detector:

```c
typedef struct {
    ULONG Pid;
    LARGE_INTEGER FirstSeen;
    LONG  EtwEventCount;       // ETW path
    LONG  NetworkConnects;     // WFP
    LONG  FileOperations;      // minifilter
    LONG  RegistryWrites;      // CmRegister callbacks
    LONG  ModuleLoads;         // PsSetLoadImageNotify
} PROC_BEHAVIOR;

BOOLEAN SuspiciousZeroEvent(PROC_BEHAVIOR* b)
{
    ULONG activity = b->FileOperations + 5*b->NetworkConnects
                   + b->RegistryWrites + 2*b->ModuleLoads;
    if (activity > 100 && b->EtwEventCount < 5) return TRUE;
    return FALSE;
}
```

The signal is high-confidence for two reasons. First, the cross-source baseline is genuinely independent: WFP callouts, minifilter operations, and `PsSetLoadImageNotifyRoutine` are not affected by ntdll patching or by `EtwEventWrite` neutering. Second, the false-positive surface is small. Most processes that do real work emit *some* ETW events; the ones that do not are either trivial (cmd, calc) or hostile.

PowerShell is a particularly instructive special case. A live PowerShell that is engaged in any activity but produces no event 4104 (script-block compile) is almost certainly running the `[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')` bypass, which sets the static `etwProvider` field to `null`. The bypass *script* is itself usually visible in 4104 of its own attempt (since the patch must compile a block), so the strongest detector is "4104 events seen, followed by 4104 silence inside a still-alive runspace". Similarly, AMSI scan events from `Microsoft-Antimalware-Scan-Interface` (event 1101) absent for a powershell.exe that is actively running commands implies `AmsiScanBuffer` has been patched to early-return.

### 12.4 Defense in Depth - The Right Layering

```text
Layer 1 - user-mode ETW (ntdll)            cheap to bypass; coarse signal
Layer 2 - kernel ETW (Microsoft-Windows-Kernel-*)  bypassable by DKOM
Layer 3 - ETWTI                                bypassable only by BYOVD or path-avoidance
Layer 4 - hypervisor / VBS (CET, KDP, HVCI)    bypassable only by hypervisor-level work
```

The composite operational pattern that survives in production: ETWTI for the high-value behavioral events; kernel-mode provider ETW for breadth; `PsSetCreateProcessNotifyEx` / `PsSetLoadImageNotifyRoutine` / WFP / minifilter callbacks as redundant signals immune to ETW tampering; a periodic ETW configuration integrity check; and Zero-Event behavioral correlation. No single layer is sufficient; the *unanimity* of the layers, multiple independent signals saying the same thing about the same PID, is what produces high-confidence detections.

### 12.5 Production Anti-Cheat Patterns

Three concrete patterns recur in publicly documented kernel anti-cheats and high-stakes EDRs and are worth naming because they tighten the cost-curve against the techniques in §11:

**Dual-slot ETWTI subscription.** Because `EnableInfo[8]` admits up to eight session subscribers per provider, occupying *two* of the eight slots from independent kernel components and cross-checking that both receive the same event stream forces an attacker to enumerate and clear *every* slot to silence the signal. The cost of dual subscription is small (the events are filtered the same way); the cost to the attacker doubles per slot. Sealighter's PPL-signed re-emitter variant is the user-mode mirror of the same idea: a second consumer that the attacker has to discover and silence separately.

**Tight-loop integrity sweeps.** A periodic check that re-reads `EtwThreatIntProvRegHandle`, `g->ProviderEnableInfo.IsEnabled`, the relevant `EnableInfo[i]` slot, and `WMI_LOGGER_CONTEXT.AcceptNewEvents` from a high-priority kernel timer, typically sub-second, narrows the window in which a "patch-then-restore" attacker can run without tripping detection. Pair this with **canary-event emission**: have your driver call `EtwWrite` on a heartbeat schedule and have your consumer observe that the heartbeat arrives. Drop-outs are direct evidence of tampering between producer and consumer.

**Provider/group-GUID redundancy.** Subscribe by *both* the provider GUID and any group GUID the provider belongs to (§13.3). Because `EnableMask` and `GroupEnableMask` are independent bytes in `ETW_REG_ENTRY`, an attacker that clears one and not the other still leaves the event flowing. The cost-attacker is two writes per session per provider instead of one; the defender pays nothing.

The aggregate of these three patterns is the right floor for any anti-cheat or EDR that takes ETW tampering seriously. On a HVCI+KDP host the design floor rises further: if the defender's own registration-handle storage and expected-state ledger are KDP-protected, a FudModule-style null-out against those pages faults instead of silently succeeding. That still does not prove every ntoskrnl ETW global is protected; verify the actual protected ranges on the build you ship against.

---

## 13. Activity Tracking, Filtering, and Provider Groups

### 13.1 Activity IDs

`EventActivityIdControl` manages a per-thread GUID. The user-mode side keeps it in ntdll-managed per-thread state; the exact storage offset is private and has shifted between feature updates, so never hard-code it. `EventWriteTransfer` accepts both an `ActivityId` (the activity this event belongs to) and a `RelatedActivityId` (the activity that *caused* it). The combination encodes a parent-child graph across asynchronous operations: an HTTP-handler `Start` event creates `ActivityId = A`, the SQL query it makes during processing emits `ActivityId = B, RelatedActivityId = A`, and so on.

For security analysts the most useful property is that ETW can preserve correlation across threads, processes, and IRP boundaries **when the instrumented component propagates the IDs**. ETW does not magically assign one activity ID to an arbitrary injection chain; providers must call `EventWriteTransfer`, copy the current activity ID, or explicitly set a related ID. The `IoSetActivityIdIrp` / `IoGetActivityIdIrp` pair (header: `ntddk.h`, Windows 8+) extends the same primitive into the IRP path, so a storage or USB request can be reconstructed across driver-stack transitions when drivers preserve the activity context.

Three failure modes matter in practice:

1. **Thread-local leakage.** User-mode activity state is thread-local. A library that calls `EventActivityIdControl(EVENT_ACTIVITY_CTRL_CREATE_SET_ID)` and forgets to restore the previous value will accidentally reparent later events emitted on the same thread. This is why activity-aware libraries usually save/restore with `GET_SET_ID` style operations.
2. **Async discontinuity.** A thread-pool hop, APC, IOCP completion, or RPC callback has no automatic ETW parent unless the framework explicitly propagates it. Well-instrumented Windows components do this; random third-party services often do not.
3. **Adversarial spoofing.** Activity IDs are GUIDs, not capabilities. A malicious process can choose an activity ID that looks related to a benign chain. Treat activity correlation as context, not proof of causality, unless it is backed by a stronger source such as ProcessStartKey, token SID, handle lineage, or a kernel callback ledger.

For anti-cheat and EDR work, activity IDs are most useful after the detector has already identified a strong event. Example: ETWTI reports a remote `WriteVm` into a protected process; the consumer uses activity/related IDs to pull the surrounding RPC, COM, PowerShell, or installer activity into the same investigation bundle. The ID graph explains "what else was happening", but the root detection should not depend on it.

### 13.2 Filters

`EVENT_FILTER_DESCRIPTOR.Type` admits several filter types; the security-relevant ones are:

| Type | Meaning |
|------|---------|
| `EVENT_FILTER_TYPE_PID` (0x80000004) | up to 8 PIDs; session-level enforcement |
| `EVENT_FILTER_TYPE_EXECUTABLE_NAME` (0x80000008) | image-name pattern |
| `EVENT_FILTER_TYPE_EVENT_ID` (0x80000200) | include / exclude event IDs |
| `EVENT_FILTER_TYPE_EVENT_NAME` (0x80000400) | TraceLogging event-name include / exclude |
| `EVENT_FILTER_TYPE_STACKWALK` (0x80001000) | enable stack capture only for named event IDs |
| `EVENT_FILTER_TYPE_STACKWALK_NAME` (0x80002000) | TraceLogging event-name stack capture |
| `EVENT_FILTER_TYPE_STACKWALK_LEVEL_KW` (0x80004000) | stack capture by level/keyword |
| `EVENT_FILTER_TYPE_PAYLOAD` (0x80000100) | provider-cooperative content filter |
| `EVENT_FILTER_TYPE_CONTAINER` (0x80008000) | container/Silo ID filter |

PID and executable-name filters are session-level filters and are bounded by documented limits (`MAX_EVENT_FILTER_PID_COUNT` is 8; `MAX_EVENT_FILTER_EVENT_ID_COUNT` is 64; total descriptors per enable call are capped by `MAX_EVENT_FILTERS_COUNT`, currently 13 in the 26100 SDK). PID filters are also literal PID filters, not process-identity filters; a long-lived controller should rebuild them after process exit to avoid PID-reuse mistakes. Payload filters require TDH/provider cooperation and only work for providers whose payload can be described and evaluated by the filtering path.

The event-ID and event-name pairs are not interchangeable. `EVENT_FILTER_TYPE_EVENT_ID` / `EVENT_FILTER_TYPE_STACKWALK` are for manifest/classic events with stable IDs; TraceLogging events should use `EVENT_FILTER_TYPE_EVENT_NAME` / `EVENT_FILTER_TYPE_STACKWALK_NAME` because the event name is the schema key. The `STACKWALK` filter is a meaningful performance lever. Kernel + user stack capture costs roughly 1000-5000 cycles per event, so enabling it globally is expensive, but enabling it only for the ETWTI IDs that matter most for behavioral detection costs almost nothing.

### 13.3 Provider Groups

A provider can register itself into a *group GUID* via `EtwSetInformation(EventProviderSetTraits)`. The group GUID has its own `ETW_GUID_ENTRY` with `Type = EtwpGroupGuidType`, sitting in the same hash bucket but on a different list head. A controller that enables the group GUID enables every member provider in one call; each member ends up with both `EnableMask` (own GUID) and `GroupEnableMask` (group GUID) bits set, and is enabled when either is non-zero.

Well-known group GUIDs include the EventSource group `{8FE0B58E-CB14-4DBD-A93D-1B11E20A1A9F}` (.NET `EventSource`), the .NET Runtime group `{D5C8460C-83BC-27D0-95D8-1E5B9C6C0AB1}`, and the DiagnosticSource group `{C861D0E2-A2C1-44C2-AA12-D9F08FA8C7DC}` used by OpenTelemetry. From a defensive perspective, the existence of independent `EnableMask` and `GroupEnableMask` is a feature: an attacker who clears one but not the other still leaves the provider enabled, so a defense that enables both individual and group GUIDs requires two writes to silence per session.

### 13.4 The Enable Callback

The `PENABLECALLBACK` signature is:

```c
VOID NTAPI EnableCallback(
    LPCGUID                   SourceId,
    ULONG                     IsEnabled,         // MSDN name; actually an EVENT_CONTROL_CODE_*
                                                 // value: 0 = DISABLE_PROVIDER,
                                                 //        1 = ENABLE_PROVIDER,
                                                 //        2 = CAPTURE_STATE
    UCHAR                     Level,
    ULONGLONG                 MatchAnyKeyword,
    ULONGLONG                 MatchAllKeyword,
    PEVENT_FILTER_DESCRIPTOR  FilterData,
    PVOID                     CallbackContext);
```

`CAPTURE_STATE` is the under-used third value. It asks the provider to immediately emit a "current state snapshot": for a file-handle tracker, the list of currently open files; for a thread tracker, the list of currently running threads. This is how a late-started session reconstructs initial state. Providers that fail to implement `CAPTURE_STATE` produce a session with a permanent blind spot on its first second of data; on the consumer side, a session that does not request `CAPTURE_STATE` after starting is similarly broken.

The callback is a control-plane hook, not an event-write hook. It is invoked when a provider is enabled, disabled, asked to capture state, or when a provider registers into a GUID that is already enabled. It should do four things and almost nothing else:

1. Cache the enabled `Level`, `MatchAnyKeyword`, `MatchAllKeyword`, and filter pointer contents under a lock.
2. Allocate or release provider-owned resources idempotently.
3. Emit `CAPTURE_STATE` rundown records if requested.
4. Return quickly.

The classic provider bug is to treat enable/disable as a single-threaded lifecycle. Two controllers can change state close together, a provider can register while a session is already enabled, and a capture-state request can arrive while ordinary events are being written. A safe provider copies filter data it needs, protects alloc/free with a mutex or rundown reference, and makes disable wait until outstanding writes have stopped touching provider-owned state.

For defenders, the callback is also a signal source. A high-value provider that never receives `CAPTURE_STATE`, or whose callback observes a filter set different from the controller's intended filter ledger, indicates a controller-path or filter-inversion problem rather than a producer-path patch.

### 13.5 Notification Providers

Notification providers (`EtwpNotificationGuidType` in the hash table) admit *bidirectional* communication. A controller calls `EtwSendNotification`, the kernel walks the provider's registrations and invokes each `Callback`, and, if the call requested a reply, collects up to four reply slots before returning. The legitimate uses are bounded: Perflib counter libraries, audio service device-change notifications, host-container telemetry synchronization. The interesting offensive surface is that, historically, `EtwSendNotification` had an info-leak path through partially-uninitialized reply buffers (Winsider's 2023 analysis turned this into a step in a 35-stage exploitation chain), and that, like any cross-thread callback dispatch, provider callbacks must be defensively coded against re-entrancy.

The `ETW_NOTIFICATION_TYPE` enumeration is much wider than commonly documented; Geoff Chappell's and NTETW.H's values across builds give:

| Value | Name | Use |
|-------|------|-----|
| 0x01 | `NoReply` | one-way notification |
| 0x02 | `LegacyEnable` | MOF provider enable |
| 0x03 | `Enable` | modern provider enable (= ETW Enable) |
| 0x04 | `PrivateLogger` | private logger notification |
| 0x05 | `PerfLib` | perf counter library |
| 0x06 | `Audio` | audio device notifications |
| 0x07 | `Session` | session-state notifications |
| 0x09 | `CredentialUI` | consent.exe credential UI transitions |
| 0x0A | `InProcSession` | Win8.1+ in-process session notifications |
| 0x0B | `FilteredPrivateLogger` | filtered private logger (Win10 1703+) |

(Some sources state these values off by one; the table above is the correct mapping aligned to `NTETW.H` and to kernel symbol type information.)

### 13.6 TraceLogging - How the Macros Become Self-Describing Events

`TraceLoggingWrite` is implemented entirely through preprocessor macros that expand into a statically-initialized metadata structure (event name, field names, field types, packed and placed in `.rdata`) plus a small runtime stub that bundles the metadata pointers and the actual values into an `EVENT_DATA_DESCRIPTOR` array and calls `EventWriteTransfer`. The two TraceLogging-specific data-descriptor types are the trick:

```c
#define EVENT_DATA_DESCRIPTOR_TYPE_NONE              0
#define EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA    1
#define EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA 2
```

When `EtwpWriteUserEvent` sees a descriptor with `Reserved == 1` or `2`, it inlines that data into the event header's metadata area instead of into the payload. The event then carries its own schema, and a consumer can parse it by walking the metadata blob: provider name (null-terminated UTF-8), event name, then field tuples of (name, in-type, out-type), followed by the payload values. There is no manifest, no PDB, no TMF. Just the event itself.

The implication for security analysis is that TraceLogging providers cannot be discovered by enumerating `HKLM\...\WINEVT\Publishers` (they have no manifest installed) but they *can* be discovered by walking `EtwpGuidHashTable` in WinDbg (their `ETW_GUID_ENTRY` exists like any other) and their schemas can be extracted at runtime by hooking `EventRecordCallback` and reading the metadata items off the event. Many EDR drivers self-instrument with TraceLogging. Many of them therefore leak their internal event vocabulary to a sufficiently determined analyst.

### 13.7 Runtime Provider Discovery (`EnumerateTraceGuidsEx`, `TraceQueryInformation`)

The classical way to enumerate ETW providers, `wevtutil ep` and the manifest registry under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`, only see providers that have an installed manifest. It misses TraceLogging providers (which carry their schema in events rather than a manifest), TraceLogging Dynamic providers (which create their GUID at runtime), and any provider that an EDR or rootkit registers under a randomized GUID. Two APIs let a user-mode caller (with appropriate privileges) walk the *live* registration state from outside the kernel debugger:

```c
// advapi32.dll - enumerate providers currently registered in the kernel
ULONG EnumerateTraceGuidsEx(
    TRACE_QUERY_INFO_CLASS InformationClass,  // TraceGuidQueryList, TraceGuidQueryInfo,
                                              // TraceGuidQueryProcess
    PVOID                  InBuffer,
    ULONG                  InBufferSize,
    PVOID                  OutBuffer,
    ULONG                  OutBufferSize,
    PULONG                 ReturnLength);

// TraceGuidQueryList -> returns flat GUID array of every registered provider
// TraceGuidQueryInfo -> for a specific provider GUID, returns TRACE_PROVIDER_INSTANCE_INFO[]
//                      with the PID, process-token, and session-bitmap of every registration
// TraceGuidQueryProcess -> for a specific PID, returns the provider GUIDs it owns
```

`TraceGuidQueryInfo` is the load-bearing primitive for hunt and incident-response work because it answers the question "which process registered this provider GUID, and which sessions are it enabled on" without requiring a kernel debugger. That is exactly the question you ask when you find an unfamiliar GUID in an ETL or in a `logman query providers` dump.

`TraceQueryInformation` (a sibling API) reports session-side state and supports a richer set of info classes:

```c
ULONG TraceQueryInformation(
    TRACEHANDLE               SessionHandle,    // or 0 for system-wide
    TRACE_QUERY_INFO_CLASS    InformationClass,
    PVOID                     TraceInformation,
    ULONG                     InformationLength,
    PULONG                    ReturnLength);

// Notable classes:
// TraceProfileSourceConfigInfo          - PMC counter configuration
// TraceSystemTraceEnableFlagsInfo       - read/write PERFINFO_GROUPMASK (§14.7)
// TraceMaxLoggersQuery                  - current MaxLoggers value
// TraceLbrConfigurationInfo             - Last Branch Record sampling
// TraceStackCachingInfo                 - stack-walk cache state
// TraceUnifiedStackCachingInfo          - stack cache for modern EventRegister events too
// TraceContextRegisterInfo              - register capture for selected system events
// TracePmcSessionInformation            - query all active PMC session configuration
// TracePeriodicCaptureStateInfo         - request periodic CAPTURE_STATE replays
// TraceProviderBinaryTracking           - image-binary correlation for provider events
```

Production EDRs use `TraceProviderBinaryTracking` to map provider events back to loaded image binaries without requiring a full stack trace; `TracePeriodicCaptureStateInfo` is how a long-running session can request recurring provider state capture when supported.

These APIs are useful for live inventory, but they are not a complete controller-audit interface. `EnumerateTraceGuidsEx(TraceGuidQueryInfo)` tells you which provider instances exist and which logger IDs they are enabled for; `TraceQueryInformation` reports specific session configuration classes. Neither one reliably reconstructs every `ENABLE_TRACE_PARAMETERS.FilterDesc` blob that a hostile co-controller may have applied. For protected sessions, keep an expected-state ledger at the controller, subscribe to `Microsoft-Windows-Kernel-EventTracing` for enable/disable metadata, and use a kernel-side verifier when the public APIs cannot expose enough detail.

### 13.8 Hardware Performance Counters Through ETW

CPU performance-monitoring counters (PMCs) and Intel PEBS (Precision Event-Based Sampling) integrate with ETW in two distinct modes, both of which are useful in advanced research scenarios: hot-path profiling for performance work and instruction-level attribution for security research.

**Mode 1: Correlated PMC.** When a session enables `EVENT_ENABLE_PROPERTY_PMC_COUNTERS` (via `ENABLE_TRACE_PARAMETERS.EnableProperty`) and provides a set of counter IDs via `SourceIds`, each event that fires under that session carries an attached `EVENT_EXTENDED_ITEM_PMC_COUNTERS` extended item with the current PMC values sampled at event time. The classical use is correlating context-switch (`CSwitch`) events with LLC-miss and branch-mispredict counters to understand scheduler-induced cache effects, but it generalizes. Any ETW event can be annotated with hardware counter readings.

```c
struct EVENT_EXTENDED_ITEM_PMC_COUNTERS {
    ULONGLONG CounterValues[1];  // length is DataSize / sizeof(ULONGLONG)
};
```

**Mode 2: PMC overflow sampling.** A configurable counter threshold triggers a PMU overflow interrupt that the kernel converts into a synthetic `PerfInfoPMCSample` ETW event, carrying the precise instruction pointer at the overflow time. Configured through WPR `.wprp` profiles:

```xml
<HardwareCounters>
    <HardwareCounter Name="InstructionsRetired" Interval="65536"/>
    <HardwareCounter Name="CacheMisses"         Interval="4096"/>
</HardwareCounters>
```

Combined with Intel PEBS (`EVENT_HEADER_EXT_TYPE_PEBS_INDEX`), this produces *instruction-level* event attribution: not just "this thread had a cache miss" but "the cache miss happened at this exact RIP, reading from this exact address". For security research the resulting capability is highly granular post-hoc analysis of side-channel-adjacent behaviors. Code that systematically generates cache misses at addresses corresponding to victim secrets becomes visible without needing a custom hypervisor instrumentation.

Practical limitations: PMC counters are CPU-vendor and -generation specific (Intel and AMD use different MSRs and event IDs); the counter set is finite (8-12 on modern Intel cores, fewer on virtual machines); and enabling PMC sampling globally produces a high event rate that requires generous buffer sizing per §17.9. `wpr -start CPU+PMC -filemode` is the canonical PMC-aware trace start.

### 13.9 Context Registers, LBR, IPT, and Stack Caching

The 25H2 kernel layout makes four advanced capture modes visible in one place: `PmcData`, `LbrData`, `IptData`, `StackCache`, and the `ContextRegister*` fields inside `WMI_LOGGER_CONTEXT`. They are easy to confuse because all of them attach "extra" data to ordinary ETW events, but they answer different questions.

**Context-register tracing** is controlled through `TraceSetInformation(..., TraceContextRegisterInfo, ...)`. The input is a `TRACE_CONTEXT_REGISTER_INFO` header followed by a bounded array of `CLASSIC_EVENT_ID` records naming the System Trace Provider events whose register state should be captured. The 26100/28000 SDK defines two register classes: `EtwContextRegisterTypeControl` and `EtwContextRegisterTypeInteger`; Microsoft's current documentation notes that both must be set for the API to operate correctly. The resulting state is reflected internally in `WMI_LOGGER_CONTEXT.ContextRegisterTypes`, `ContextRegisterHookCount`, and `ContextRegisterHookIdMap[]`.

```c
typedef struct TRACE_CONTEXT_REGISTER_INFO {
    ETW_CONTEXT_REGISTER_TYPES RegisterTypes; // Control | Integer
    ULONG Reserved;
} TRACE_CONTEXT_REGISTER_INFO;
```

Security value: it lets a short-lived forensic trace capture the register context at selected kernel-event hook IDs without installing a custom hook. Operational caveat: it is expensive and privacy-sensitive. Do not enable it globally on always-on sessions; use it as a targeted, time-bounded forensic mode after an alert.

**Last Branch Record (LBR)** tracing is the branch-history sibling of stack walking. `TraceLbrConfigurationInfo` configures the branch filter, and `TraceLbrEventListInfo` / `TraceConfigureLastBranchRecord` choose the kernel events that trigger a snapshot. The SDK exposes filters such as "exclude kernel", "exclude user", "exclude returns", and "callstack mode"; `TRACE_LBR_MAXIMUM_EVENTS` is 4. This is useful when a normal stack is spoofed or truncated: LBR shows the recent branch edges that led to the sampled point, not merely the unwind metadata the attacker wants the stack walker to believe. The trade-off is hardware dependence and virtualization fragility; many VMs either do not expose LBR or expose it with limited fidelity.

**Intel Processor Trace / IPT** appears in the 25H2 session layout as `IptData`, but it is not exposed through a broad, stable public controller API in the same way as PMC/LBR/context-register tracing. Treat it as a kernel-internal capability used by specific Microsoft trace profiles and hardware paths, not as a feature a third-party EDR can rely on without per-build validation.

**Stack caching** is controlled by `TraceStackCachingInfo` and `TraceUnifiedStackCachingInfo`. Instead of attaching a full stack to every event, ETW can emit `STACK_KEY32` or `STACK_KEY64` extended items and cache the actual stack separately. This reduces ETL size and real-time bandwidth for stack-heavy traces, but it changes parser requirements: a consumer must resolve stack keys against the session's stack cache and tolerate cache misses. A parser that expects every stack-bearing event to contain `STACK_TRACE64` directly will silently lose context on modern traces.

---

## 14. WPP, Manifest Binary Format (WEVT_TEMPLATE / CRIM), Crimson Channels

### 14.1 WPP

Windows Software Trace Preprocessor is the driver-debug specialization. `tracewpp.exe` preprocesses C source files annotated with `DoTraceMessage(FLAG, fmt, ...)` macros; the generated `.tmh` header expands each macro into WPP/ETW write code. The source-level format string is not intended to be a public runtime schema. The formatter information is emitted into PDB data and can be extracted into TMF files, so decoding WPP events requires either the matching PDB or a `.tmf`. Without one of them, the event still exists, but the payload is mostly opaque bytes.

The WPP control model is flag-centric. A provider defines a control GUID and up to 31 `WPP_DEFINE_BIT(...)` flags. The default `DoTraceMessage` path is enabled by flag, and custom macros add level or other conditions by generating `WPP_<conditions>_ENABLED` / `WPP_<conditions>_LOGGER` helpers. This is why WPP code often looks like ordinary debug printing, but the generated code is actually asking "is this flag enabled for my logger handle?" before formatting or writing.

Operationally, WPP differs from manifest ETW in three ways:

| Property | WPP consequence |
|----------|-----------------|
| Schema storage | TMF/PDB is needed for human-readable decoding; `wevtutil gp` will not give you the payload layout. |
| Session fanout | WPP behaves like a classic provider for control purposes: one active tracing session can control a given WPP provider/control GUID at a time. |
| Security boundary | Hiding the control GUID or TMF is not real access control, but it does raise the reverse-engineering cost for third-party consumers. |

The SOC implication is awkward. Drivers that use WPP can contain very useful security telemetry, but the event content is effectively private unless you have symbols or TMFs. The analyst path is `tracefmt`, `TraceView`, `!wmitrace`, or a TDH consumer supplied with the right WPP context. The engineering path for a product that wants stable, supported telemetry is different: use manifest ETW or TraceLogging for events that are meant to be consumed outside the owning team, and reserve WPP for high-volume driver diagnostics.

### 14.2 Manifest Binary Format - CRIM and WEVT_TEMPLATE

A manifest-based provider stores its compiled manifest as a `WEVT_TEMPLATE` resource inside its DLL or EXE. The format is informally called CRIM (Compiled Resource Instrumentation Manifest):

```text
"CRIM"  Size  MajorVer  MinorVer  NumberOfProviders
  [GUID, ProviderDataOffset] xN
  ┌─ WEVT_PROVIDER (per provider)
  │    "WEVT"  Size  MessageId  NumElements  Reserved
  │    [ElementOffset, Unknown] xNumElements
  └─ each element is one of:
         "CHAN"  Channel definitions
         "LEVL"  Custom levels
         "TASK"  Tasks
         "OPCO"  Opcodes
         "KEYW"  Keywords (each 16 bytes; 64-bit bitmask)
         "EVNT"  Event definitions (48 bytes each; references template by offset)
         "MAPS"  Container for value/bitmap maps
         "BMAP"  Bitmap (for flag enums)
         "VMAP"  Value map (for ordinary enums)
         "TTBL"  Template Table (container for individual templates)
         "TEMP"  Individual templates (BinXml + property descriptors)
         "PRVA"  Private/undocumented
```

(Sources that list `FLTR` as a top-level magic do not match the libfwevt specification. Filter metadata defined in the `.man` XML's `<filters>` element is compiled into other parts of the resource, not into a dedicated `FLTR` table.)

The `WEVT_TEMPLATE` resource is the canonical source of truth for "what events does this provider emit", and tooling like `EtwExplorer` (zodiacon), `wevt_template` (williballenthin), `libfwevt` (libyal), and `PerfView` all parse it. For research, *diffing* the manifests between Windows builds is the standard way to catch new security events before Microsoft documents them. `Microsoft-Windows-Threat-Intelligence` is a good example of why the diff must be per-build: current 26200 metadata maps event 26 to an alloc-VM kernel-caller variant, while older notes and extracted manifests sometimes attach different semantic names to later IDs. Treat ETWTI event IDs as build-scoped, not as a universal taxonomy.

### 14.3 TraceLogging Dynamic - Runtime Self-Describing Events

The macro-based TraceLogging path (§13.6) commits its schema to `.rdata` at compile time. **TraceLogging Dynamic** (header: `TraceLoggingDynamic.h`; companion C++ library at `github.com/microsoft/tracelogging`) exposes the same self-describing mechanism at *runtime*. A scripting language host, a managed-language runtime, or any other producer that does not know its event schema until execution time can build provider metadata, event metadata, and the corresponding `EVENT_DATA_DESCRIPTOR` array on the heap and emit through `EventWriteTransfer` as a normal TraceLogging event.

The C++ API surface is small:

```cpp
#include <TraceLoggingDynamic.h>

tld::Provider provider("MyDynamic.Provider",
                        tld::Guid("12345678-1234-1234-1234-1234567890AB"));
provider.Register();

tld::EventBuilder<std::vector<BYTE>> eb;
eb.Reset("EventName", tld::EventDescriptor(/*level*/3, /*keyword*/0x1));
eb.AddField("PID",       processId, tld::InType::UInt32);
eb.AddField("ImagePath", imagePath, tld::InType::CountedUtf16String);
eb.Write(provider);
```

The bytes the kernel sees are identical in shape to the static macro path: provider metadata, event metadata, and event values, with `EVENT_DATA_DESCRIPTOR.Reserved` flagged as `EVENT_DATA_DESCRIPTOR_TYPE_PROVIDER_METADATA` (2) or `EVENT_DATA_DESCRIPTOR_TYPE_EVENT_METADATA` (1) for the schema slots. Consumers (PerfView, `dotnet-trace`, custom TDH-free parsers) decode it identically.

Five security implications follow:

1. **Runtime GUIDs defeat manifest enumeration.** A provider GUID synthesized at runtime appears in `EtwpGuidHashTable` and live `EnumerateTraceGuidsEx` output only after the producer registers it - and disappears after deregistration. EDRs that rely on a static manifest list miss these entirely; the right discovery surface is `EnumerateTraceGuidsEx(TraceGuidQueryList)` (§13.7) walked on a heartbeat.
2. **Self-describing payloads leak EDR internals.** Many EDRs use TraceLogging Dynamic (or static TraceLogging) for their own driver-internal telemetry. The metadata for those events is then visible in the event stream, so a sufficiently determined analyst can recover the EDR's event vocabulary by collecting events emitted by drivers running on a clean system.
3. **Schema mutation between events.** Dynamic providers can emit two events with the same event ID but different schemas, since each event carries its own metadata. Parser code that caches the schema by `(ProviderId, EventId)` and reuses it will silently misparse later events; correct parsers re-read the metadata for every event from the descriptor.
4. **Provider name is unverified.** The provider-metadata block carries the provider name as a UTF-8 string, freely chosen by the producer. An attacker registering a TraceLogging provider can name it `"Microsoft-Windows-Kernel-Process"`; only the GUID is authoritative for routing, and the name is purely cosmetic. SOC tooling that trusts the name field is trivially defeated.
5. **Self-tampering.** A producer can re-emit `EtwSetInformation(EventProviderSetTraits)` at any time, changing its provider metadata mid-session. The next event carries the new metadata.

For defenders the practical guidance is: trust GUID, not name; subscribe to `Microsoft-Windows-Kernel-EventTracing` for provider-registration events; cross-reference registered GUIDs against a known-good baseline; and parse events by reading their carried metadata rather than caching schemas across registrations.

### 14.4 Hidden TraceLogging Provider Archaeology (25H2 / 2026)

The largest practical gap in many ETW writeups is TraceLogging provider coverage. Manifest providers are visible through `wevtutil ep`, the publisher registry, and `WEVT_TEMPLATE` extraction. TraceLogging providers are often just metadata blobs in `.rdata`, plus a `_tlgProvider_t` runtime structure in `.data`, and may never appear in the manifest registry at all.

Asuka Nakajima's Black Hat Asia 2026 research is the current best public snapshot of the scale of this gap. On Windows 11 `10.0.26200.7705` (25H2), scanning 64-bit binaries under `C:\Windows\*` and `C:\Program Files\*` found **2,672 TraceLogging providers** and **64,000+ unique events**, compared with roughly **920+ manifest-based providers**. Windows Server 2025 showed a different mix: fewer providers but more unique events in the surveyed set. The engineering conclusion is simple: any "ETW provider catalog" based only on `wevtutil ep` is missing most of the modern developer/security telemetry surface.

The current static-analysis workflow looks like this:

```text
1. Scan non-executable PE sections for the TraceLogging `ETW0` metadata header
   and the TraceLogging magic value.
2. Parse provider blobs and event blobs:
      provider name, provider GUID / group, event name, level, opcode,
      keyword, channel, field names, in-types, out-types, tags.
3. Locate `_tlgProvider_t` runtime provider structures by matching metadata
   pointers in writable sections.
4. Map each event blob back to the provider and function that emits it by
   walking data references, call references, and a bounded call graph.
5. Validate dynamically by enabling the provider GUID in an ETW session and
   parsing `EVENT_SCHEMA_TL` / `PROV_TRAITS` extended metadata from events.
```

This is exactly the problem solved by `TLGMapper`: it combines TraceLogging metadata parsing with IDA data-flow / call-graph resolution so that a reverse engineer can answer "which function emits which hidden TraceLogging event" without first triggering the event at runtime.

Security-relevant examples from the 25H2 research set:

| TraceLogging provider | Binary | Useful events / fields | Security use |
|----------------------|--------|------------------------|--------------|
| `AttackSurfaceMonitor` (`{c4e507b1-7224-4737-bde0-ced9284e7073}`) | `ntoskrnl.exe` | `Ast.DeviceCreated`, `Ast.DeviceSDDLChanged`, `Ast.IoctlCalled`; device name/object, SDDL, IOCTL code | BYOVD and suspicious driver-device abuse |
| `Microsoft.Windows.Kernel.SysEnv` (`{a9fdf37b-d72d-4051-a3cd-d422103ce079}`) | `ntoskrnl.exe` | UEFI `GetVariable` / `SetVariable`; variable name, vendor GUID, attributes, status | Secure Boot / bootkit reconnaissance and tampering |
| `Microsoft.Windows.ShellExecute` (`{382b5e24-181e-417f-a8d6-2155f749e724}`) | `windows.storage.dll` | `ShellExecuteExW` parameters: verb, file, parameters, directory, flags | ClickFix-style and indirect process launch detection |
| `Microsoft.Antimalware.Scan.Interface` | AMSI binaries | richer TraceLogging AMSI scan/provider events alongside manifest AMSI event 1101 | AMSI provider behavior, failures, UAC scan detail |
| `Microsoft.Windows.Kernel.UCPD` / `Microsoft.Windows.Security.IsolationApi` | kernel / isolation components | default-browser/user-choice and isolation attack-surface events | New Windows feature-abuse detection |

The stability model is different from manifest ETW. TraceLogging event names and fields are often developer-facing and can change between cumulative updates. Treat GUID + provider name + event name + field shape as a build-scoped contract, not a stable event ID. For production detection content, baseline per build family (`26100`, `26200`, `28000`), keep the raw provider metadata in your content repository, and make the consumer tolerant of extra fields, missing fields, and provider-name spoofing.

### 14.5 Crimson Channels

Crimson is the Vista-era event-log infrastructure layered on top of ETW. A channel has a *type* (Admin / Operational / Analytic / Debug) and a *value* (a one-byte ID in `EVENT_DESCRIPTOR.Channel`, range 0..255). Common confusion: the type and the value are not the same and there is no fixed type-to-value mapping. The `mc.exe` message compiler assigns values starting at 16 in *definition order* in the manifest XML, so "Operational" can be 16 if it appears first in one provider's manifest and 17 in another's. The system reserves a few small values: 0 (default), 8/9/10 (Windows EventLog), 11 (TraceLogging), 12-15 (system).

The operationally important property is that Admin and Operational channel events are *automatically routed* to the EventLog service's persistent `.evtx` files (under `%SystemRoot%\System32\winevt\Logs`), while Analytic and Debug events are not. This is the substrate of `Get-WinEvent` and `eventvwr.msc`, and it is why security-relevant events that need to survive a reboot are typically routed through Operational or Admin channels.

### 14.6 V2 Properties and System-Wide Private Logger

`EVENT_TRACE_PROPERTIES_V2` (`Wnode.Flags |= WNODE_FLAG_VERSIONED_PROPERTIES`) extends the classical session-properties structure with `FilterDescCount` / `FilterDesc` and a `V2Options` flag word. The most consequential capability it unlocks for security collection is the system-wide private logger: an `EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC` session combined with a session-level PID or executable-name scope filter that targets *other* processes. The kernel handles the filtered private delivery, the session is not one of the normal global logger slots, and the controller can spin one up surgically for any PID it suspects.

The natural EDR pattern is to keep a baseline of broad real-time sessions and, on suspicion, dynamically start a forensic-mode private logger filtered to the suspect PID with stack-walk enabled and file/buffered output. Sixty seconds later the session ends and the resulting ETL is uploaded for offline analysis. The cost on the live host is bounded because the filter cuts noise from all other processes, but this is a post-suspicion artifact path, not a replacement for the always-on real-time collector.

The documented system-wide private-logger scope filters are PID and executable-name filters. Do not assume arbitrary provider filters will be honored at the same layer. The flag word usefully exposes `QpcDeltaTracking` (store timestamps as deltas to improve compactness), `LargeMdlPages` (larger MDLs for high-throughput sessions), and `ExcludeKernelStack` (capture user stack only, at the cost of losing kernel context).

### 14.7 NT Kernel Logger: EnableFlags vs PERFINFO_GROUPMASK

NT Kernel Logger (slot 0) accepts two distinct activation interfaces. The first is the 32-bit `EnableFlags` field of `EVENT_TRACE_PROPERTIES`. It is Vista-era, public, and capped at 32 categories. The second is the 256-bit `PERFINFO_GROUPMASK`. It is Windows 7+, semi-documented in `NTWMI.H` and exposed via `TraceSetInformation(TraceSystemTraceEnableFlagsInfo)`, and the only way to enable many of the more interesting kernel events (heap tracing, pool tracing, ALPC details, hypervisor profiling).

The public controller contract is deliberately different from ordinary providers. For the classical NT Kernel Logger, you do **not** call `EnableTraceEx2` for `SystemTraceControlGuid`; `StartTrace(KERNEL_LOGGER_NAME, ...)` reads `EVENT_TRACE_PROPERTIES.EnableFlags` and uses those flags to configure the kernel provider set. Microsoft documents that there is only one NT Kernel Logger session; if it is already running, `StartTrace` returns `ERROR_ALREADY_EXISTS`. This is the source of the familiar xperf/WPR/EDR conflict: two controllers cannot both own the historical `KERNEL_LOGGER_NAME` session at the same time.

The constants involved are all in `shared\evntrace.h`:

```c
#define KERNEL_LOGGER_NAMEW                L"NT Kernel Logger"
// SystemTraceControlGuid = {9E814AAD-3204-11D2-9A82-006008A86939}

#define EVENT_TRACE_FLAG_PROCESS           0x00000001
#define EVENT_TRACE_FLAG_THREAD            0x00000002
#define EVENT_TRACE_FLAG_IMAGE_LOAD        0x00000004
#define EVENT_TRACE_FLAG_CSWITCH           0x00000010
#define EVENT_TRACE_FLAG_SYSTEMCALL        0x00000080
#define EVENT_TRACE_FLAG_DISK_IO           0x00000100
#define EVENT_TRACE_FLAG_VIRTUAL_ALLOC     0x00004000
#define EVENT_TRACE_FLAG_NETWORK_TCPIP     0x00010000
#define EVENT_TRACE_FLAG_REGISTRY          0x00020000
#define EVENT_TRACE_FLAG_ALPC              0x00100000
#define EVENT_TRACE_FLAG_FILE_IO           0x02000000
#define EVENT_TRACE_FLAG_FILE_IO_INIT      0x04000000
```

Windows 8+ added a second model: a **SystemTraceProvider** session can be multiplexed for up to eight logger sessions, with the first two reserved for NT Kernel Logger and CKCL. To start one of these non-NT-kernel system-trace sessions, the controller gives the session its own logger name and GUID, sets `EVENT_TRACE_SYSTEM_LOGGER_MODE`, and enables the desired system categories. Microsoft's documented constraints are important:

1. `LoggerName` must be your private session name, not `KERNEL_LOGGER_NAME`.
2. `Wnode.Guid` must be a new session GUID, not `SystemTraceControlGuid`.
3. `LogFileMode` must include `EVENT_TRACE_SYSTEM_LOGGER_MODE`.
4. If a non-admin / non-TCB principal starts profiling traces on behalf of third parties, the controller must grant profile privilege and event access to both the session GUID and the system trace provider GUID.

Operational recipe: reserve the historical NT Kernel Logger for WPR/xperf-style broad captures or for a single product that intentionally owns it. For always-on security collection on modern Windows, prefer category-specific System Providers (§14.8) or a dedicated system logger session when the OS supports it, then fall back to NT Kernel Logger / `PERFINFO_GROUPMASK` only for categories that are missing or for older hosts. Before starting anything, query `logman query -ets`, `TraceMaxLoggersQuery`, and, if you have a kernel debugger, `!wmitrace.strdump`. A failed `StartTrace` on `KERNEL_LOGGER_NAME` is usually not a mysterious ETW bug; it usually means somebody else already owns the one classical kernel logger.

The mask is an array of eight 32-bit groups indexed by the high 3 bits of each `PERF_xxx` constant:

```c
#define PERF_MASK_INDEX  (0xe0000000)        // upper 3 bits = Masks[] index
#define PERF_MASK_GROUP  (~PERF_MASK_INDEX)  // lower 29 bits = group bits
#define PERF_NUM_MASKS   8

typedef struct _PERFINFO_GROUPMASK {
    ULONG Masks[PERF_NUM_MASKS];   // 8 x 32 = 256 bits total
} PERFINFO_GROUPMASK;

#define PERFINFO_OR_GROUP_WITH_GROUPMASK(Group, pGM) \
    ((pGM)->Masks[(Group) >> 29] |= ((Group) & PERF_MASK_GROUP))
```

The condensed bit map most relevant to security and performance work, drawn from `NTWMI.H` and `krabsetw/perfinfo_groupmask.hpp`:

```c
// Masks[0] (0x0xxxxxxx) - public EnableFlags-compatible bits
#define PERF_PROCESS              0x00000001  // PROCESS
#define PERF_THREAD               0x00000002  // THREAD
#define PERF_LOADER               0x00000004  // IMAGE_LOAD
#define PERF_PERF_COUNTER         0x00000008  // PROCESS_COUNTERS
#define PERF_CONTEXT_SWITCH       0x00000010  // CSWITCH
#define PERF_DPC                  0x00000020  // DPC
#define PERF_INTERRUPT            0x00000040  // INTERRUPT
#define PERF_SYSTEMCALL           0x00000080  // SYSTEMCALL
#define PERF_DISK_IO              0x00000100  // DISK_IO
#define PERF_DISK_IO_INIT         0x00000400  // DISK_IO_INIT
#define PERF_DISPATCHER           0x00000800  // DISPATCHER
#define PERF_MEMORY               0x00001000  // MEMORY_PAGE_FAULTS
#define PERF_VIRTUAL_ALLOC        0x00004000  // VIRTUAL_ALLOC
#define PERF_NETWORK              0x00010000  // NETWORK_TCPIP
#define PERF_REGISTRY             0x00020000  // REGISTRY
#define PERF_DBGPRINT             0x00040000  // DBGPRINT
#define PERF_ALPC                 0x00100000  // ALPC
#define PERF_SPLIT_IO             0x00200000  // SPLIT_IO
#define PERF_DRIVER               0x00800000  // DRIVER (PnP)
#define PERF_PROFILE              0x01000000  // CPU PROFILE
#define PERF_FILE_IO              0x02000000  // FILE_IO
#define PERF_FILE_IO_INIT         0x04000000  // FILE_IO_INIT

// Masks[1] (0x2xxxxxxx) - extended events, not reachable via EnableFlags
#define PERF_POOL                 0x20000040
#define PERF_HEAP_TRACING         0x20000080  // heap allocator events
#define PERF_CRITICAL_SECTION     0x20000100
#define PERF_POOLTRACE            0x20000200  // detailed pool trace
#define PERF_REFSET               0x20000400
#define PERF_HARD_FAULTS          0x20002000  // hard page faults (disk)
#define PERF_PRIORITY             0x20004000
#define PERF_WORKER_THREAD        0x20008000
#define PERF_CONFIG_SYSTEM        0x20020000  // boot/hardware config
#define PERF_CONFIG_GRAPHICS      0x20040000
#define PERF_CONFIG_OPTICAL       0x20080000

// Masks[2] (0x4xxxxxxx) - Windows 8+
#define PERF_BIGFOOT              0x40000001  // large-trace events
#define PERF_SESSION              0x40000004
#define PERF_CC                   0x40000008  // cache controller
#define PERF_DEBUGGER             0x40000080
#define PERF_PROC_FREEZE          0x40000100

// Masks[4] (0x8xxxxxxx) - hypervisor / power / WDF
#define PERF_HV_PROFILE           0x80080000  // Hyper-V profiling
#define PERF_WDF_DPC              0x80100000
#define PERF_WDF_INTERRUPT        0x80200000
#define PERF_CACHE_FLUSH          0x80400000
```

Setting a bit through `EnableFlags` reaches at most the Masks[0] subset; reaching `PERF_HEAP_TRACING` or `PERF_HV_PROFILE` requires:

```c
PERFINFO_GROUPMASK gm = {0};
PERFINFO_OR_GROUP_WITH_GROUPMASK(PERF_PROCESS,      &gm);
PERFINFO_OR_GROUP_WITH_GROUPMASK(PERF_LOADER,       &gm);
PERFINFO_OR_GROUP_WITH_GROUPMASK(PERF_HEAP_TRACING, &gm);
TraceSetInformation(handle, TraceSystemTraceEnableFlagsInfo, &gm, sizeof(gm));
```

Exact bit positions drift across builds; the canonical source is `NTWMI.H` from the matching WDK or `krabsetw/perfinfo_groupmask.hpp`.

### 14.8 System Providers (Windows 10 SDK 20348+)

Starting with the Windows 10 SDK build 20348 (Server 2022 / 21H2 era), the NT-Kernel-Logger functionality is exposed as a set of **System Providers**: provider GUIDs that wrap categories of the legacy system trace mask and are enableable through `EnableTraceEx2` from sessions started with `EVENT_TRACE_SYSTEM_LOGGER_MODE`. They are easier to compose than the old monolithic `EnableFlags` path, but they are still system-trace plumbing rather than ordinary user providers; Microsoft explicitly notes that generated events are identified as system events, not as events from the individual System Provider GUID.

Do not confuse these System Provider GUIDs with the manifest providers named `Microsoft-Windows-Kernel-*`. They overlap in subject matter, but they sit at different controller surfaces:

| Surface | Controller shape | Event identity | Typical use |
|---------|------------------|----------------|-------------|
| NT Kernel Logger | `StartTrace(KERNEL_LOGGER_NAME, EnableFlags)` | system trace events | broad legacy kernel capture |
| SystemTraceProvider session | `EVENT_TRACE_SYSTEM_LOGGER_MODE` + system categories | system trace events | multiplexed kernel capture without owning slot 0 |
| System Provider GUIDs | `EnableTraceEx2(System*ProviderGuid, ...)` on a system logger session | still reported as system events | category-specific modern control |
| `Microsoft-Windows-Kernel-*` manifest providers | ordinary provider enablement | provider-specific manifest events | SOC-friendly provider rules and EventLog-style metadata |

| System Provider | Replaces / scopes (roughly) |
|----------------|-----------------------------|
| `SystemConfigProviderGuid` | `PERF_CONFIG_SYSTEM`, hardware / boot config |
| `SystemCpuProviderGuid` / `SystemProfileProviderGuid` | CPU accounting and sampled profile |
| `SystemSchedulerProviderGuid` | `PERF_CONTEXT_SWITCH`, `PERF_DISPATCHER`, `PERF_PRIORITY` |
| `SystemProcessProviderGuid` | `PERF_PROCESS`, `PERF_THREAD`, `PERF_LOADER` |
| `SystemIoProviderGuid` / `SystemIoFilterProviderGuid` | disk / file / network / I/O filter activity |
| `SystemMemoryProviderGuid` | `PERF_MEMORY`, `PERF_VIRTUAL_ALLOC`, `PERF_HARD_FAULTS` |
| `SystemRegistryProviderGuid` | registry operations |
| `SystemAlpcProviderGuid` | ALPC activity |
| `SystemPowerProviderGuid` | power transitions, idle states |
| `SystemInterruptProviderGuid` | `PERF_INTERRUPT`, `PERF_DPC` |
| `SystemTimerProviderGuid` | timer activity |
| `SystemHypervisorProviderGuid` | `PERF_HV_PROFILE` |
| `SystemObjectProviderGuid` | handle and object operations |
| `SystemLockProviderGuid` | lock contention |
| `SystemSyscallProviderGuid` | `PERF_SYSTEMCALL` |

Each System Provider has its own GUID; the canonical mapping list, including GUID values and per-provider event keyword constants, is on the Microsoft Learn page "System Providers" (`learn.microsoft.com/en-us/windows/win32/etw/system-providers`). The header that declares them is `shared\evntrace.h` in the matching Windows SDK; 26100 declares the provider GUIDs above plus `LastBranchRecordProviderGuid`. Production code should resolve the GUIDs from the SDK header version it builds against, and should still verify live host support before assuming every category is available.

The practical implication for an EDR shipping kernel telemetry on modern Windows: prefer these system providers where the OS supports them, and fall back to the legacy NT Kernel Logger / `PERFINFO_GROUPMASK` path only for categories that are not exposed or for older hosts. Coexistence is better than the historical single NT Kernel Logger story, but you still need to query the live host because session count, provider support, and system-logger behavior vary by build.

---

## 15. WinDbg Forensics for ETW

### 15.1 `!wmitrace` Extensions

The kernel debugger is the highest-bandwidth interface to live ETW state. The standard extensions are `!wmitrace.*`; richer programmatic access is via the DX object model.

```text
!wmitrace.strdump                              all loggers
!wmitrace.logdump "NT Kernel Logger"           one logger in detail
!wmitrace.loglive  NT Kernel Logger            live buffer state
!wmitrace.guiddump                             registered provider/control GUIDs
!wmitrace.tmffile  C:\symbols\driver.tmf       WPP decode context
!wmitrace.searchpath C:\symbols                WPP TMF search path
!wmitrace.start "TestSession" /guid #...         start/stop (live kernel debugger only)
!wmitrace.stop  "TestSession"
```

Use the extension commands for quick orientation, not as your only source of truth. `!wmitrace.strdump` is excellent for "what sessions exist right now", but it does not prove that every provider enable slot is consistent with the controller's intended state. `!wmitrace.logdump` is excellent for one logger, but build-specific fields still require symbol-aware inspection of `nt!_WMI_LOGGER_CONTEXT`. `!wmitrace.tmffile` and `!wmitrace.searchpath` are mandatory when the session contains WPP messages and you want readable strings rather than `TRACE_MESSAGE` blobs.

The safest live-debug workflow is: dump session names, identify the `LoggerId`, read the corresponding `WMI_LOGGER_CONTEXT`, then walk providers independently from `EtwpGuidHashTable`. If the session says it enabled a provider but the provider's `EnableInfo[]` does not name that logger, you have either a race, stale controller state, or tampering.

### 15.2 DX Object Model

DX scripts give read access to the whole ETW topology; the patterns below are useful in incident analysis:

```javascript
// All live (non-sentinel) loggers
dx ((nt!_WMI_LOGGER_CONTEXT*(*)[0x50])
     (((nt!_ESERVERSILO_GLOBALS*)&nt!PspHostSiloGlobals)
        ->EtwSiloState->EtwpLoggerContext))
   ->Where(l => l != 1 && l != 0)

// EventsLost for slot 0 (NT Kernel Logger)
dx (((nt!_ESERVERSILO_GLOBALS*)&nt!PspHostSiloGlobals)
        ->EtwSiloState->EtwpLoggerContext)[0]->EventsLost

// Real-time consumers attached to logger N
dx (((nt!_ESERVERSILO_GLOBALS*)&nt!PspHostSiloGlobals)
        ->EtwSiloState->EtwpLoggerContext)[N]->Consumers
```

DX is where ETW inspection becomes repeatable. A good dump script should emit a normalized record per session:

```text
LoggerId, LoggerName, Mode, Flags.SecurityTrace, AcceptNewEvents,
EventsLost, LogBuffersLost, RealTimeBuffersLost,
BufferSize, NumberOfBuffers, FreeBuffers, BuffersWritten,
ConsumerCount, EnabledProviderCount
```

Then emit one normalized record per provider enable slot:

```text
ProviderGuid, ProviderType, ProcessId, RegEntry, LoggerId,
IsEnabled, Level, MatchAnyKeyword, MatchAllKeyword,
FilterDescCount, GroupEnabled
```

This is intentionally boring. The point is to diff live state against an expected ledger and against a previous snapshot. DKOM attacks rarely corrupt every view consistently. A provider can have `ProviderEnableInfo.IsEnabled = 0` while a controller handle still exists; a session can have consumers attached while `AcceptNewEvents = 0`; a group GUID can still enable a provider whose individual `EnableMask` was cleared. DX scripts should print contradictions, not just tables.

### 15.3 Memory-Dump Forensics and the DiagTrack Artifact

A small JavaScript that enumerates every provider GUID across all three hash-bucket lists, dumps each provider's `ProviderEnableInfo` and `EnableInfo[0..7]`, and cross-references against a known-good map of `(provider, session, level, keyword)` is sufficient to detect every variant of the DKOM-based tampering in §11.2. Trail of Bits' published `EtwKernelRoutines.js` is a workable starting point.

For a memory-dump (Volatility) workflow, the Tomonaga `ETW Scan` plugin parses `WMI_LOGGER_CONTEXT` out of pool memory, walks back through `BufferQueue` and `UserBufferListHead` to recover unflushed events, and exposes the same enumerations the DX scripts produce against a live system. The output is identical in form; the value is that the analysis runs against a captured image rather than a tampered live host.

The single highest-value forensic artifact on many Windows systems is `%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl`: the DiagTrack autologger can persist `Microsoft-Windows-Kernel-Process` process-start records (command line, image path, parent, SID, ProcessStartKey) and retain them across reboots until the file rolls over. Even when an attacker has deleted application logs, EventLog, and the Sysmon database, DiagTrack may remain untouched because many malware authors do not know about it. FortiGuard Labs (2025) made this widely known after ransomware-incident response recovered evidence here.

Treat DiagTrack as a high-value opportunistic artifact, not a guaranteed audit log. FortiGuard's testing showed that manually setting telemetry verbosity and starting/updating the autologger can create the ETL file without populating it; population appears to depend on internal DiagTrack triggers that are not publicly documented. The right playbook is therefore:

1. Collect the ETL if it exists.
2. Parse `KernelProcess -> ProcessStarted` records and preserve command line, parent PID, SID, session, package name, and ProcessStartKey.
3. Correlate with Amcache, ShimCache, Prefetch, SRUM, USN, $MFT, EventLog, Sysmon, Defender, and EDR records.
4. Do not alert on absence of the file or absence of a record without checking policy, telemetry level, service state, file rollover, and host edition.

### 15.4 Boot-Time ETW

The ETW subsystem is the earliest kernel subsystem to begin recording events on a Windows boot, which makes it the canonical place to look for evidence of pre-boot tampering. The initialization sequence in 25H2/24H2 is two-phase:

```text
Phase 0 - EtwpInitialize(0), run during early ntoskrnl init:
    ├─ allocate ETW_SILODRIVERSTATE for the host silo
    ├─ register ~15 core kernel providers including ETWTI,
    │   Microsoft-Windows-Kernel-Process, Microsoft-Windows-Security-Auditing
    ├─ if HKLM\SYSTEM\CurrentControlSet\Control\WMI\GlobalLogger\Start = 1,
    │   start GlobalLogger here - this is the only session that captures
    │   events emitted by phase-0 driver initialization
    └─ initialize boot ETW handle storage in ntoskrnl .data

Phase 1 - EtwpInitialize(1), run as drivers come up:
    ├─ complete remaining kernel provider registrations
    ├─ start CKCL (slot 1, always-on)
    ├─ walk HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<name>
    │   for each: if Start = 1, start the named session and enable its
    │   per-GUID subkeys (Defender, EventLog-Security, DiagTrack, ELAM)
    └─ ETW topology now fully live; first user-mode services start
```

The forensic and offensive consequence is that **GlobalLogger is the only ETW session that sees the phase-0 window**. A rootkit installing itself as a boot-start driver can be entirely invisible to AutoLoggers if it finishes its install before phase 1, but GlobalLogger will catch the load event if it is configured. The registry layout is:

```text
HKLM\SYSTEM\CurrentControlSet\Control\WMI\GlobalLogger\
    Start            REG_DWORD  1                   ; enable on next boot
    FileName         REG_SZ     "C:\boot.etl"
    MaxFileSize      REG_DWORD  100                 ; MB
    BufferSize       REG_DWORD  64                  ; KB
    MinBuffers       REG_DWORD  40
    MaxBuffers       REG_DWORD  50
    FlushTimer       REG_DWORD  1
    EnableKernelFlags REG_BINARY xx xx xx xx        ; translates to NT Kernel Logger flags
    \{ProviderGUID}\
        Flags  REG_DWORD  0xFFFFFFFF
        Level  REG_DWORD  5

HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<SessionName>\
    Start             REG_DWORD  1
    GUID              REG_SZ     "{SessionGUID}"
    FileName          REG_SZ     "%SystemRoot%\System32\winevt\Logs\session.etl"
    LogFileMode       REG_DWORD  0x8001000C         ; e.g. EVENT_TRACE_FILE_MODE_NEWFILE
    \{ProviderGUID}\
        Enabled       REG_DWORD  1
        EnableFlags   REG_DWORD  0xFFFFFFFF
        EnableLevel   REG_DWORD  5
```

Security-relevant AutoLogger sessions include `AutoLogger-Diagtrack-Listener` (DiagTrack telemetry; the DiagTrack ETL is the high-value forensic artifact mentioned above), `EventLog-Security` (Windows audit events 4624/4663/4688 etc.), `EventLog-System`, and any ELAM-class driver's own autologger session. Persistence techniques that install boot-start drivers will often leave traces here that survive the same incident's log-wipe steps because the AutoLogger ETL is written to disk before any user-mode tooling can clean it up.

Undocumented KDP-related AutoLogger knobs have appeared in public reversing notes and on some 24H2 systems, but this is not a stable public contract like `Start`, `GUID`, or `EnableLevel`. If an EDR wants KDP-backed tamper resistance, the production-safe path is to protect its own driver-owned state with documented KDP APIs and to treat any AutoLogger `KdpProtected`-style registry value as build-specific: verify it on the target with live kernel state before recommending it as a deployment control.

---

## 16. The Security Provider Catalog

Windows 11 25H2 has two different provider universes. The manifest/provider-registry universe is on the order of 900+ useful providers and is what `wevtutil ep` makes visible. The TraceLogging universe is larger: recent 25H2 research found 2,600+ TraceLogging providers across Windows and Program Files binaries. The list below is the working set actually used by EDRs and security researchers. GUIDs in the tables below should be treated as a starting point, not authoritative: provider names occasionally change across feature updates and some less-common providers have drifted between manifests. **Verify every GUID before depending on it** with `logman query providers <name>`, `wevtutil gp <name> /ge:true /gm:true`, live `EnumerateTraceGuidsEx`, or a static TraceLogging metadata scan against the target build.

### 16.1 Process / Thread / Module / Audit

| Provider | GUID | Why it matters |
|---------|------|----------------|
| `Microsoft-Windows-Kernel-Process` | `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` | Process, thread, image events 1/2/3/4/5/6 - the base layer for almost every EDR |
| `Microsoft-Windows-Kernel-Audit-API-Calls` | `{e02a841c-75a3-4fa7-afc8-ae09cf9b7f23}` | `NtOpenProcess`, `NtOpenThread`, `NtSetContextThread`, `NtTerminateProcess` - security provider family; access behavior must be tested on the target because SecurityTrace/AutoLogger paths differ from ordinary providers |
| `Microsoft-Windows-Threat-Intelligence` (ETWTI) | `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` | §9 - injection, LSASS read, hijack |
| `Microsoft-Windows-Kernel-General` | `{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}` | Time changes, system-wide events |
| `Microsoft-Windows-DotNETRuntime` | `{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}` | Assembly load, JIT, GC - essential for .NET in-memory payloads |
| `Microsoft-Windows-DotNETRuntimeRundown` | `{a669021c-c450-4609-a035-5af59af4df18}` | State snapshot at subscription |
| `Microsoft-Windows-RPC` | `{6ad52b32-d609-4be9-ae07-ce8dae937e39}` | RPC call (interface UUID + opnum) - lateral movement |

### 16.2 Memory, Filesystem, Registry, Network

| Provider | GUID | Use |
|---------|------|-----|
| `Microsoft-Windows-Kernel-Memory` | `{d1d93ef7-e1f2-4f45-9943-03d245fe6c00}` | Memory summaries, working-set swap, ACG, physical/MDL allocation context; not a replacement for ETWTI VM-operation events |
| `Microsoft-Windows-Kernel-File` | `{edd08927-9cc4-4e65-b970-c2560fb5c289}` | File create/read/write/delete/rename/path operations - pair with a minifilter when enforcement or pre-operation context matters |
| `Microsoft-Windows-Kernel-Registry` | `{70eb4f03-c1de-4f73-a051-33d13d5413bd}` | Registry create/open/set/delete/query operations - the ETW view of persistence, not a substitute for `CmRegisterCallbackEx` |
| `Microsoft-Windows-FilterManager` | `{f3c5e28e-63f6-49c7-a204-e48a1bc4b09d}` | Minifilter registration changes - security-product evasion |
| `Microsoft-Windows-NTFS` | `{dd70bc80-ef44-421b-8ac3-cd31da613a4e}` | USN journal, alternate data streams, MFT operations |
| `Microsoft-Windows-Kernel-Network` | `{7dd42a49-5329-4832-8dfd-43d979153a88}` | TCP/UDP IPv4/IPv6 flow events - no DNS, TLS, or WFP classification semantics |
| `Microsoft-Windows-DNS-Client` | `{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}` | C2 detection via event 3008 (resolved name + IPs) |
| `Microsoft-Windows-WFP` | `{c22d1b14-c242-49de-9f17-1d76b8b9c458}` | Firewall verdicts |
| `Microsoft-Windows-NDIS-PacketCapture` | `{2ed6006e-4729-4609-b423-3ee7bcd678ef}` | Raw packets - basis of `pktmon` |
| `Microsoft-Windows-WinHttp` | `{7d44233d-3055-4b9c-ba64-0d47ca40a232}` | WinHTTP traffic - headers, user-agent |

### 16.3 Authentication and Scripting

| Provider | GUID | Use |
|---------|------|-----|
| `Microsoft-Windows-Security-Auditing` | `{54849625-5478-4994-a5ba-3e3b0328c30d}` | Source of Security-channel events 4624/4663/4688 |
| `Microsoft-Windows-LSA` | `{cc85922f-db41-11d2-9244-006008269001}` | Auth-package load, SAM access |
| `Microsoft-Windows-NTLM` | `{ac43300d-5fcc-4800-8e99-1bd3f85f0320}` | NTLM auth - Pass-the-Hash |
| `Microsoft-Windows-Kerberos-KdcSvc` | `{1bba8b19-7f31-43c0-9643-6e911f79a06b}` | TGT/TGS issuance - Golden / Silver Ticket |
| `Microsoft-Windows-PowerShell` | `{a0c1853b-5c40-4b15-8766-3cf1c58f985a}` | Event 4104 ScriptBlock - the highest-value scripting signal |
| `PowerShellCore` | `{f90714a8-5509-434a-bf6d-b1624c8a19a2}` | PS7 equivalent |
| `Microsoft-Antimalware-Scan-Interface` | `{2a576b87-09a7-520e-c21a-4942f0271d67}` | AMSI scan event 1101 |

### 16.4 Persistence, Lateral Movement, Self-Telemetry

| Provider | GUID | Use |
|---------|------|-----|
| `Microsoft-Windows-TaskScheduler` | `{de7b24ea-73c8-4a09-985d-5bdadcfa9017}` | Scheduled-task changes |
| `Microsoft-Windows-Services` | `{0063715b-eeda-4007-9429-ad526f62696e}` | Service install / start |
| `Microsoft-Windows-WinRM` | `{a7975c8f-ac13-49f1-87da-5a984a4ab417}` | PowerShell remoting |
| `Microsoft-Windows-WMI-Activity` | `{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}` | Event 5859/5860/5861 - permanent WMI subscriptions (T1546.003) |
| `Microsoft-Windows-DistributedCOM` | `{1b562e86-b7aa-4131-badc-b6f3a001407e}` | DCOM activation (MMC20, ShellWindows abuse) |
| `Microsoft-Windows-SMBClient` / `SMBServer` | (separate) | Lateral SMB activity |
| `Microsoft-Windows-Sysmon` | `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` | Sysmon's own self-emitted events |
| `Microsoft-Windows-CodeIntegrity` | `{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}` | HVCI / WDAC decisions |

### 16.5 The Underdocumented Ones

These are valuable and rarely written about in mainstream EDR documentation:

| Provider | GUID | Use |
|---------|------|-----|
| `Microsoft-Windows-Kernel-EventTracing` | `{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}` | Meta-provider - emits events when *other* sessions start, stop, or have providers enabled/disabled. The right place to detect somebody trying to silence your own session |
| `Microsoft-Windows-Kernel-Boot` | `{15ca44ff-4d7a-4baa-bba5-0998955e531e}` | Soft restart, memory-map, memory-preservation, and EFI-variable context for bootkit / early-driver timelines |
| `Microsoft-Windows-Kernel-PnP` | `{9c205a39-1250-487d-abd7-e831c6290539}` | Driver load/unload, device start/config, and enumeration; high-value for BYOVD timelines |
| `Microsoft-Windows-Hyper-V-Hypervisor` | `{52fc89f8-995e-434c-a91e-199986449890}` | VM entry/exit, EPT violations - useful for VBS-evasion detection |
| `Microsoft-Windows-Schannel-Events` | `{91cc1150-71aa-47e2-a7c8-4f2855bf4d24}` | TLS handshakes - C2 TLS fingerprinting |
| `Microsoft-Windows-WCM` | `{67d07935-283a-4791-8f8d-fa9117f3e6f2}` | Wireless credential use |
| `Microsoft-Windows-Kernel-Power` | `{331c3b3a-2005-44c2-ac5e-77220c37d6b4}` | Sleep/wake, thermal, timer-resolution, and power-setting context |
| `Microsoft-Windows-Kernel-Processor-Power` | `{0f67e49f-fe51-4e9f-b490-6f2948cc6027}` | CPU frequency, sleep-study, power diagnostics, and energy-estimation context |
| `Microsoft-Windows-Kernel-WHEA` | `{7b563579-53c8-44e7-8236-0f87b9fe6594}` | Hardware error records; useful around DMA, instability, suspicious crash, or firmware-tamper windows |
| `Microsoft-Windows-Security-Mitigations` | `{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}` | Process Mitigation Policy hits - CFG / EAF / IAF / ACG enforcement events. Catches exploitation attempts that hit a mitigation gate without successfully exploiting |
| `Microsoft-Windows-CodeIntegrity` | (already in §16.4) | HVCI page-hash mismatches (event 3033), Secure Boot DBX hits (event 3077), WDAC policy decisions |
| `Microsoft-Windows-AppLocker` | `{cbda4dbf-8d5d-4f69-9578-be14aa540d22}` | AppLocker rule evaluations - exec / DLL / script / installer per-rule decisions |
| `Microsoft-Windows-COM` | `{d4263c98-310c-4d97-ba39-b55354f08584}` | COM object instantiation - DCOM lateral-movement source |

The 25H2 TraceLogging-only set adds several providers that do not fit the traditional manifest table:

| TraceLogging provider | GUID / source | Use |
|----------------------|---------------|-----|
| `AttackSurfaceMonitor` | `{c4e507b1-7224-4737-bde0-ced9284e7073}` / `ntoskrnl.exe` | Driver attack surface: device creation, SDDL changes, IOCTL calls. High-value for BYOVD detection. |
| `Microsoft.Windows.Kernel.SysEnv` | `{a9fdf37b-d72d-4051-a3cd-d422103ce079}` / `ntoskrnl.exe` | UEFI variable reads/writes; Secure Boot reconnaissance and boot-policy tampering. |
| `Microsoft.Windows.ShellExecute` | `{382b5e24-181e-417f-a8d6-2155f749e724}` / `windows.storage.dll` | ShellExecuteExW launch metadata, useful for Run dialog, ClickFix, file-association and indirect-launch chains. |
| `Microsoft.Windows.Kernel.UCPD` | TraceLogging metadata scan required | User Choice Protection Driver activity: browser/default-app/user-choice modification attempts. |
| `Microsoft.Windows.Security.IsolationApi` | TraceLogging metadata scan required | Win32 App Isolation and new Windows isolation-feature abuse signals. |

`Microsoft-Windows-Kernel-EventTracing` is the most underrated. It emits an event whenever any ETW session is started, stopped, or has its provider set changed. If an attacker stops your session, even via a controller, this provider sees it. Subscribing to it from a *different* session that the attacker has not specifically targeted is a meta-detector that very few defensive products implement, but which catches the broadest possible class of session tampering. Olaf Hartong's *provmon* tool is built specifically around this provider.

### 16.6 Event ID / Keyword Reference (top providers)

A condensed matrix sufficient for writing rules without consulting the manifest:

**Built-in kernel provider baseline (live 25H2 / 26200.8524).** The host exposes dozens of `Microsoft-Windows-Kernel-*` providers; not all are equally useful for security. The set below is the practical floor for anti-cheat / EDR design:

| Provider | GUID | Primary value | Operational caveat |
|----------|------|---------------|--------------------|
| `Microsoft-Windows-Kernel-Process` | `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` | process, thread, image, job, process-freeze lifecycle | base process graph; still cross-check with `PsSetCreateProcessNotifyEx` / image callbacks |
| `Microsoft-Windows-Kernel-File` | `{edd08927-9cc4-4e65-b970-c2560fb5c289}` | create/read/write/delete/rename/path operations | high volume; minifilter remains the stronger enforcement/correlation source |
| `Microsoft-Windows-Kernel-Registry` | `{70eb4f03-c1de-4f73-a051-33d13d5413bd}` | create/open/set/delete/query key and value operations | excellent persistence signal; payload shape drifts and is noisier than `CmRegisterCallbackEx` |
| `Microsoft-Windows-Kernel-Network` | `{7dd42a49-5329-4832-8dfd-43d979153a88}` | TCP/UDP send, receive, connect, accept, disconnect for IPv4/IPv6 | no DNS/TLS semantics; pair with WFP and DNS providers |
| `Microsoft-Windows-Kernel-Memory` | `{d1d93ef7-e1f2-4f45-9943-03d245fe6c00}` | memory summaries, working-set swap, ACG, physical/MDL allocation | not a substitute for ETWTI VM alloc/protect/write events |
| `Microsoft-Windows-Kernel-Audit-API-Calls` | `{e02a841c-75a3-4fa7-afc8-ae09cf9b7f23}` | sensitive native API audit events such as process/thread handle paths | security-provider family; SecurityTrace/AutoLogger behavior must be verified per build |
| `Microsoft-Windows-Threat-Intelligence` | `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` | executable memory, VM read/write, APC, set-context, suspend/resume, impersonation | requires AM-PPL-qualified consumer path |
| `Microsoft-Windows-Kernel-EventTracing` | `{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}` | session/provider registration, enablement, lost event, capture-state metadata | monitor-of-monitors; can itself be targeted |
| `Microsoft-Windows-Kernel-PnP` | `{9c205a39-1250-487d-abd7-e831c6290539}` | driver load/unload, device start/config, boot/device enumeration | useful for BYOVD and device-object timelines; pair with ETWTI driver/device events |
| `Microsoft-Windows-Kernel-Boot` | `{15ca44ff-4d7a-4baa-bba5-0998955e531e}` | soft restart, memory preservation, memory map, EFI variable activity | boot forensics; strongest when GlobalLogger/AutoLogger captures early enough |
| `Microsoft-Windows-Kernel-General` | `{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}` | time, access-check, token SID management, token query | low-volume security context; useful for token/anomaly correlation |
| `Microsoft-Windows-Kernel-Power` / `Processor-Power` | `{331c3b3a-2005-44c2-ac5e-77220c37d6b4}` / `{0f67e49f-fe51-4e9f-b490-6f2948cc6027}` | sleep, wake, thermal, timer-resolution, CPU frequency/power state | timing and sleep-transition context; not a primary malware detector |
| `Microsoft-Windows-Kernel-WHEA` | `{7b563579-53c8-44e7-8236-0f87b9fe6594}` | hardware error records | hardware/firmware anomaly context; useful around DMA, instability, or suspicious crash windows |

Several names that look obvious do not exist as separate live providers on this build. Thread and image lifecycle are part of `Microsoft-Windows-Kernel-Process`, not separate `Microsoft-Windows-Kernel-Thread` / `Microsoft-Windows-Kernel-Image` providers. Likewise, the System Provider GUIDs in §14.8 are a controller abstraction over system trace events; they should not be mixed up with the manifest providers above when writing provider-GUID-keyed SOC rules.

**Microsoft-Windows-Kernel-Process**: Current 26200 metadata maps event 1 `ProcessStart`, 2 `ProcessStop`, 3 `ThreadStart`, 4 `ThreadStop`, 5 `ImageLoad`, 6 `ImageUnload`, 7 `CpuBasePriorityChange`, 8 `CpuPriorityChange`, 9 `PagePriorityChange`, 10 `IoPriorityChange`, 11/12 `ProcessFreeze` suspend/resume, 13 `JobStart`, 14 `JobTerminate`, and 15 `ProcessRundown`. Common keywords: `0x10` (PROCESS), `0x20` (THREAD), `0x40` (IMAGE), `0x80` (CPU_PRIORITY), `0x100` (OTHER_PRIORITY), `0x200` (PROCESS_FREEZE), `0x400` (JOB), `0x1000` (JOB_IO), `0x2000` (WORK_ON_BEHALF), `0x4000` (JOB_SILO).

**Microsoft-Windows-Threat-Intelligence**: event set as listed in §9.2. Current 26200 keyword values are granular: `0x1/0x2/0x4/0x8` cover alloc-VM local/local-kernel/remote/remote-kernel, `0x10/0x20/0x40/0x80` cover protect-VM variants, `0x100..0x800` cover map-view variants, `0x1000/0x2000` queue APC, `0x4000/0x8000` set-thread-context, `0x10000/0x20000` read-VM, `0x40000/0x80000` write-VM, `0x100000/0x200000` thread suspend/resume, `0x400000..0x2000000` process suspend/resume/freeze/thaw, `0x40000000/0x80000000` driver/device events, and `0x4000000000..0x40000000000` impersonation/syscall-usage events. Always query the live provider metadata before hard-coding masks.

**Microsoft-Windows-Kernel-Audit-API-Calls**: Current 26200 metadata exposes provider `{e02a841c-75a3-4fa7-afc8-ae09cf9b7f23}` with events 1-8 and no public keyword taxonomy. Treat it as a build-scoped handle/API audit surface and decode payloads from the live manifest; pair it with `ObRegisterCallbacks` when the rule depends on process/thread handle opens or duplicates.

**Microsoft-Windows-DNS-Client**: 3006 query initiated, **3008** query completed (contains resolved IPs; the best single event here for C2 detection), 3009 cache hit, 3018 server-list update, 3020 raw response.

**Microsoft-Windows-PowerShell**: 4100 engine state, 4103 module logging, **4104** ScriptBlock compile, 4105/4106 invocation. Keyword bit positions drift between Windows PowerShell and PowerShell 7 manifests. Runspace and Pipeline are consistently at the low bits (`0x1` / `0x2`), but Cmdlets and Host vary; consult `wevtutil gp Microsoft-Windows-PowerShell /ge /gm` for the exact mask on the target build before writing rules.

**Microsoft-Windows-WMI-Activity**: 5859 `__EventFilter` / `__EventConsumer` registration, 5860 permanent subscription, 5861 permanent consumer execution. These three are the canonical signal for the MITRE T1546.003 (WMI event-subscription persistence) technique.

**Microsoft-Windows-Kernel-File**: Current 26200 metadata maps 10 `NameCreate`, 11 `NameDelete`, 12 `Create`, 13 `Cleanup`, 14 `Close`, 15 `Read`, 16 `Write`, 17 `SetInformation`, 18 `SetDelete`, 19 `Rename`, 20 `DirEnum`, 21 `Flush`, 22 `QueryInformation`, 23 `FSCTL`, 24 `OperationEnd`, 26 `DeletePath`, 27 `RenamePath`, 28 `SetLinkPath`, 29 `SetLink`, 30 `CreateNewFile`, 31/32 security set/query, and 33/34 EA set/query. Keywords: `0x10` FILENAME, `0x20` FILEIO, `0x40` OP_END, `0x80` CREATE, `0x100` READ, `0x200` WRITE, `0x400` DELETE_PATH, `0x800` RENAME_SETLINK_PATH, `0x1000` CREATE_NEW_FILE.

**Microsoft-Windows-Kernel-Registry**: Keyword mask is operation-shaped: `0x1000` CreateKey, `0x2000` OpenKey, `0x4000` DeleteKey, `0x100` SetValueKey, `0x200` DeleteValueKey, `0x400` QueryValueKey, `0x800` EnumerateKey, `0x1` CloseKey, plus security/query/flush variants. Treat it as the ETW view of registry persistence, but keep a `CmRegisterCallbackEx` ledger for authoritative pre/post-operation enforcement and for callout-time veto context.

**Microsoft-Windows-Kernel-Network**: IPv4 keyword `0x10`, IPv6 keyword `0x20`; tasks split TCP/IP and UDP/IP, with opcodes for send, receive, connect, disconnect, retransmit, accept, reconnect, fail, TCP copy, UDP send/receive/fail. It gives flow-level timing and endpoint context, not DNS name resolution, TLS SNI, process intent, or WFP classification. The production stack is Kernel-Network + `Microsoft-Windows-DNS-Client` + WFP callout.

**Microsoft-Windows-Kernel-Memory**: Current keywords include `MEMINFO` (`0x20`), `MEMINFO_EX` (`0x40`), working-set swap (`0x80`), ACG (`0x100`), physical allocation (`0x200`), and node memory info (`0x400`). This provider is good for memory-pressure, ACG, and physical/MDL allocation context. It is not the provider that tells you a remote process changed another process's executable memory; that is ETWTI.

**Microsoft-Windows-Kernel-PnP**: Keywords cover boot init (`0x1000`), driver load/unload (`0x2000` / `0x4000`), device start (`0x8000`), device enum (`0x10000`), driver init (`0x20000`), device eject/config, driver database, configuration manager, enumeration, software devices, and notifications. For BYOVD investigations, combine PnP driver/device events with `Kernel-Process` kernel-image loads, ETWTI driver/device events, SCM service-install events, CodeIntegrity, and minifilter/WFP registration telemetry.

**Microsoft-Windows-Kernel-EventTracing**: Current keywords: session (`0x10`), provider (`0x20`), lost event (`0x40`), soft restart (`0x80`), capture state (`0x100`), registration (`0x200`), enablement (`0x400`), group (`0x800`). This is the provider to keep in a separate meta-session. It answers "who changed ETW" and "did ETW lose events"; it does not protect itself, so pair it with canary delivery and kernel-side state checks.

**Microsoft-Windows-Kernel-Boot / General / WHEA / Power**: These are context providers rather than primary detection providers. `Kernel-Boot` has EFI variable and memory-map keywords that matter during bootkit/early-driver investigations; `Kernel-General` exposes time/access-check/token SID management; `Kernel-WHEA` captures hardware errors; `Kernel-Power` and `Kernel-Processor-Power` capture sleep/wake/thermal/frequency/timer-resolution behavior. They explain suspicious windows and crash/boot gaps, but they should not be the only source behind a high-severity detection.

### 16.7 .NET CLR ETW (`Microsoft-Windows-DotNETRuntime`)

The CLR's own ETW provider is the highest-fidelity in-process observation point for managed code and one of the two or three providers that any EDR doing .NET in-memory detection must subscribe to.

**Provider GUID:** `{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}` (same GUID for .NET Framework and modern .NET 5+/Core; the distinction is which CLR is loaded). The companion **Rundown** provider `{a669021c-c450-4609-a035-5af59af4df18}` emits a snapshot of currently-loaded assemblies and JITted methods when a session subscribes with `StartEnumerationKeyword`, so a late-attaching consumer can reconstruct prior state.

**Keyword bits (excerpt):**

```text
0x0000000000000001  GCKeyword                  GC events
0x0000000000000008  LoaderKeyword              AppDomain/Assembly/Module load/unload
0x0000000000000010  JitKeyword                 JIT method start/end
0x0000000000000020  NGenKeyword                NGEN / R2R method load
0x0000000000000040  StartEnumerationKeyword    on-attach rundown
0x0000000000000080  EndEnumerationKeyword      on-detach rundown
0x0000000000000400  SecurityKeyword            strong-name / Authenticode checks
0x0000000000001000  JitTracingKeyword          JIT inlining decisions
0x0000000000004000  ContentionKeyword          monitor contention
0x0000000000008000  ExceptionKeyword           .NET exception throw/catch
0x0000000000010000  ThreadingKeyword           managed thread events
0x0000000000020000  JittedMethodILToNativeMap  IL-to-native maps
0x0000000000040000  OverrideAndSuppressNGen    suppress/override NGEN events
0x0000000000080000  TypeKeyword                type metadata events
0x0000000040000000  StackKeyword               attach managed stacks to events
```

**Security-critical event IDs (provider-relative):**

| ID | Event | Why it matters |
|----|-------|----------------|
| 141 | `MethodLoad` | JIT-compiled method (verbose includes name) |
| 143 | `MethodLoadVerbose` | with method name and signature |
| 145 | `MethodJittingStarted` | the JIT compiler began compiling - fires on every reflective load |
| 152 | `ModuleLoad` | a CLR module loaded; `ModuleFlags & 0x4` = **Dynamic** = in-memory module |
| 153 | `ModuleUnload` | module lifetime end |
| 154 | `AssemblyLoad` | a CLR assembly loaded; `AssemblyFlags & 0x2` = **Dynamic assembly** = reflection emit / in-memory assembly |
| 155 | `AssemblyUnload` | assembly lifetime end |
| 156 | `AppDomainLoad` | useful for legacy .NET Framework host segmentation |
| 157 | `AppDomainUnload` | |
| 80 | `ExceptionThrown_V1` | exception with type/message - useful for evasion noise detection |
| 250-256 | exception catch/finally/filter events | high-noise but useful for loader/evasion debugging |

The "Dynamic" flag on `AssemblyLoad` and `ModuleLoad` is the single most useful in-memory-payload signal on the platform. A red-team `Assembly.Load(byte[])` of an attacker-supplied DLL typically leaves a loader trail where `ModuleLoad` has a synthetic module path and `ModuleFlags & 0x4` is set, while `AssemblyLoad` can carry `AssemblyFlags & 0x2` for dynamic assemblies created through reflection emit. The kernel cannot suppress this without disabling the entire CLR provider. User-mode `ntdll!EtwEventWrite` patches do not reach, because the event is emitted from inside `clr.dll` / `coreclr.dll` as an enabled ETW provider.

Keyword presets are a common source of bad rules. Current `dotnet-trace collect` uses EventPipe-compatible provider syntax; with no provider override it defaults to the `dotnet-common` + sampled-thread-time profiles and shows `Microsoft-Windows-DotNETRuntime` at `0x000000100003801D` / Informational. Microsoft documents the older exact CPU-sampling-equivalent provider string as `0x14C14FCCBD:4`. The older `0x1CDFCC` preset is still seen in PerfView/EDR notes, but on current Windows CLR metadata it expands to Fusion, Loader, Start/End Enumeration, Security, AppDomain resource, JitTracing, Contention, Exception, OverrideAndSuppressNGenEvents, Type, and GCHeapDump; it does **not** include `GCKeyword` (`0x1`) or `JitKeyword` (`0x10`). For in-memory assembly detection, prefer an explicit keyword ledger: `LoaderKeyword` (`0x8`) + `JitKeyword` (`0x10`) + `NGenKeyword` (`0x20`) + `StartEnumerationKeyword` (`0x40`) + `EndEnumerationKeyword` (`0x80`) + `ExceptionKeyword` (`0x8000`) + `StackKeyword` (`0x40000000`) where stack cost is acceptable.

**Bypass surface:** the CLR-side gating point is `clr!ETW::CallbackProviderInvoke` (and its CoreCLR equivalent `coreclr!ETW::CallbackProviderInvoke`). Replacing the static `s_provider` field with a stub that returns "not enabled" disables the entire CLR ETW path inside the patched process. The S3cur3Th1sSh1t and xpn bypass families implement variants of this. Kernel-side detection: the CLR provider's `EnableMask` and `ProviderEnableInfo.IsEnabled` remain set; the per-process patch only affects whether the in-process producer actually emits. Cross-correlation with `Microsoft-Windows-Kernel-Process` event 5 (image load of `clr.dll` or `coreclr.dll`) by a process subsequently producing zero CLR events is the highest-confidence detection.

### 16.8 Commercial EDR Architectures - Worked Examples

The architectural patterns from §16.9 (Sysmon) and §12.5 (Vanguard-class anti-cheat) generalize. Major commercial EDRs deploy structurally similar designs with different emphasis on ETW vs callbacks. Public reverse-engineering and vendor documentation paint a usable, but incomplete, picture:

**Microsoft Defender for Endpoint (MDE).** Major components include protected user-mode services plus kernel filtering / sensor drivers:

- `MsMpEng.exe` (PPL-AM) - Defender AV engine. Publishes `Microsoft-Antimalware-Engine` and `Microsoft-Antimalware-Service`, consumes AMSI scan results.
- `MsSense.exe` - MDE's cloud client, the *primary ETW consumer*. Subscribes to ETWTI, `Microsoft-Windows-Kernel-*`, `Microsoft-Windows-PowerShell`, `Microsoft-Antimalware-Scan-Interface`, `Microsoft-Windows-DNS-Client`, `Microsoft-Windows-WMI-Activity`, `Microsoft-Windows-RPC`, and the `Microsoft-Windows-DotNETRuntime` family. The exact provider list shifts between MDE platform versions.
- `MsSecFlt.sys` - kernel sensor / filtering driver used by MDE. Do not describe a `.sys` driver as "PPL-AM"; PPL-AM is a user-mode protected-process property. The driver can still act as a privileged broker or kernel-side corroboration point, while the AM-PPL-qualified user-mode service satisfies the protected-consumer identity when that path is used. The split between which component actually owns or brokers the ETWTI handle has shifted across builds and should be verified live with `!wmitrace.strdump` on the target.

MDE registers autologger sessions under `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\`. The exact session names (e.g. `DefenderApiLogger`, `DefenderAuditLogger`, MDE-specific aggregator sessions whose names vary by platform version) are enumerable with `logman query -ets` on a live host. Tampering detection should baseline the AutoLogger key set on first install and alarm on any unexpected modification.

**CrowdStrike Falcon.** Architecturally less ETW-centric than MDE:

- `CSAgent.sys` (the kernel driver implicated in the 2024-07-19 channel-file outage) - primary signal source. Heavy on `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, `CmRegisterCallbackEx`, `ObRegisterCallbacks`, plus a WFP callout. Minifilter altitude is in the AV range; verify with `fltmc filters` on a live host.
- `CSFalconService.exe` - user-mode service. Whether it runs as a Protected Process and consumes ETWTI directly varies by Falcon build and license tier; some configurations rely on the kernel driver to act as the ETWTI subscriber instead. Public reverse-engineering writeups for the current build are sparse, so the exact division of labor should be treated as something to confirm against the target deployment rather than asserted.
- Whether Falcon ships a dedicated ELAM driver alongside `CSAgent.sys` is uncertain in public documentation; the platform supports ELAM and CrowdStrike is ELAM-eligible, but I have no recent public-source confirmation of the exact driver layout.

Falcon does not publish a widely-documented user-mode ETW provider GUID of its own. Telemetry flows internally via private IPC rather than ETW. This makes Falcon harder to silence by user-mode ETW patches (no in-process producer to disable) but also means defenders cannot cross-correlate via the ETW stream.

**Elastic Defend / Elastic Endpoint Security.** The most-documented EDR in this list because Elastic Security Labs publishes detection rules and architecture posts. Highlights:

- Subscribes to ETWTI with user-mode call-stack capture *for every ETWTI event* (the 2023 "Doubling Down on ETW callstacks" series). This defeats indirect-syscall and module-stomping evasions that rely on the EDR not seeing the actual caller.
- Open-sourced rule pack at `github.com/elastic/detection-rules` directly names provider GUIDs and keyword bits, which makes it the cleanest reference for "what to subscribe to" if you are designing a new EDR.
- Detection content for ETWTI tampering (added in 2023+) looks for `NtSetInformationProcess(ProcessInstrumentationCallback)` and `EtwSetInformation`-driven session deregistration.

**SentinelOne.** Pre-2022 builds were primarily kernel-callback driven; from 2023+ public reports describe an ELAM/protected-service path, but the driver itself is not "PPL-AM" and public reverse-engineering of current builds is sparse. Treat the exact ETWTI ownership path, whether AM-PPL user-mode consumer, kernel broker, or both, as deployment-specific until confirmed on the target.

The pattern across all four (MDE, Falcon, Elastic, SentinelOne) is the same architectural floor:

1. AM-PPL-qualified consumer process, or a signed kernel broker architecture where the product mediates security telemetry below user mode.
2. ELAM-class driver / protected-service enrollment path for early-launch and trust establishment.
3. Kernel callbacks (`PsSet*`, `CmRegister*`, `ObRegister*`) as ETW-independent redundancy.
4. Minifilter (file) + WFP callout (network) for the events ETW does not surface.
5. User-mode consumer attached to ETWTI + the major `Microsoft-Windows-Kernel-*` providers + AMSI + CLR.

Any new EDR that ships less than this is operationally limited; any cheat or post-exploit toolkit that wants to defeat one of these has to defeat the *full stack*, not just the ETW slice. The four redundancy layers above are precisely why the patchless and DKOM techniques in §11 typically only buy partial visibility loss rather than total silence.

### 16.9 Sysmon - A Worked Example of ETW Emission and Callback Redundancy

Sysmon (System Monitor, Sysinternals, and now also a built-in Windows feature path) is the most legible publicly-available reference implementation of "kernel callback ledger plus ETW/EventLog emission". Do not model it as a simple user-mode consumer of `Microsoft-Windows-Kernel-*` providers. The better architecture model is:

```text
Sysmon.exe (user mode)
   ├─ owns configuration, rule evaluation, service control, and EventLog integration
   └─ communicates with SysmonDrv.sys

Event flow:
   SysmonDrv.sys / service sensors
      ├─ process/image callbacks
      ├─ minifilter file-system observations
      ├─ registry callbacks
      ├─ WFP/network observations
      └─ optional DNS / image / driver / pipe / WMI telemetry paths

   -> rule evaluation
   -> emit Microsoft-Windows-Sysmon events
   -> EventLog session writes "Microsoft-Windows-Sysmon/Operational"
```

The structural property worth noting is that Sysmon is *not* a pure ETW consumer. It owns a kernel driver, callback set, filters, and its own ETW/EventLog provider. This means user-mode ETW patches (`ntdll` inline hooks) do not disable Sysmon's core observations, because those observations are generated by the driver/service pipeline rather than by the attacked process calling `EtwEventWrite`. Kernel DKOM against `Microsoft-Windows-Kernel-Process` can blind other consumers of that provider, but it does not automatically suppress Sysmon's own process callback path. A separate attack has to target Sysmon's driver, service, provider enable state, EventLog delivery session, or rule configuration.

The implication for any defender designing an ETW-based EDR is exactly this: Sysmon's robustness comes from refusing to depend on one telemetry layer. ETW/EventLog is the publication surface; kernel callbacks and filters are the observation surface. The signal-fusion matrix in §17.7 captures the same principle abstractly.

The mapping from Sysmon configuration to sensor class:

```yaml
<EventFiltering>
    <ProcessCreate onmatch="include">   <!-- process-create callback path -->
        <Image condition="contains">mimikatz</Image>
    </ProcessCreate>
    <FileCreate onmatch="include">      <!-- minifilter/file-system path -->
        <TargetFilename condition="end with">.exe</TargetFilename>
    </FileCreate>
    <NetworkConnect onmatch="include">  <!-- network/WFP path -->
        <DestinationPort condition="is">4444</DestinationPort>
    </NetworkConnect>
</EventFiltering>
```

Sysmon's published source-code-free format and the Olaf Hartong / SwiftOnSecurity configurations together amount to one of the best worked examples of "what security-relevant endpoint telemetry should look like once raw kernel observations are normalized for SOC consumption".

---

## 17. Detection Architecture

An ETW-based anti-cheat or EDR should be designed as a set of mutually checking collectors, not as one large trace session. The goal is to know whether an event happened, whether ETW reported it, whether the ETW configuration was still healthy at the time, and whether a non-ETW source saw the same behavior.

### 17.1 Overall Structure

```text
                         Server Correlator
                               |
                  evidence upload / policy decision
                               |
+------------------------------+------------------------------+
|                         User Service                         |
| ETW consumer | TDH/cache | ETL upload | health UI | policy    |
+------------------------------+------------------------------+
                               |
                          IOCTL boundary
                               |
+------------------------------+------------------------------+
|                        Kernel Driver                         |
| process ledger | image ledger | handle mon. | ETW verifier   |
| canary provider| memory scan  | callback inv.| platform chk  |
+------------------------------+------------------------------+
                               |
                    Windows kernel / ETW fabric
```

The user service owns controller handles, consumer callbacks, schema caches, and upload policy. The kernel driver owns the evidence that user-mode ETW cannot protect by itself: process/image/handle ledgers, provider/session integrity checks, canary emission, and cross-view memory observations. The server correlator exists because a live rootkit can still lie to the host; once evidence leaves the box, the attacker has a harder job.

### 17.2 Collector Priority

| Priority | Collector | Rationale |
|---------:|-----------|-----------|
| 1 | ETWTI real-time session | Highest-value memory/thread/handle security events |
| 2 | Kernel process/thread/image session | Broad lifecycle coverage |
| 3 | Process / image / handle callback ledger | Non-ETW cross-view for the same behaviors |
| 4 | ETW provider/session integrity verifier | Detects DKOM and filter/session tampering |
| 5 | Canary provider + consumer heartbeat | End-to-end delivery proof |
| 6 | `Microsoft-Windows-Kernel-EventTracing` meta-session | Session start/stop/enable audit |
| 7 | File-mode backup session | Survives real-time consumer failure |
| 8 | Adaptive private logger | Suspicion-scoped stack/register/detail capture |
| 9 | TraceLogging metadata scanner | Hidden provider discovery and build diffing |
| 10 | Memory / VAD / stack sampler | Confirms behaviors ETW missed or could not observe |
| 11 | Platform posture collector | HVCI, KDP, Secure Boot, TPM, driver-blocklist state |

### 17.3 Source Trust Table

| Source | Description | Trust |
|--------|-------------|------:|
| `UserEtwProvider` | Provider inside the observed process | Low |
| `NtdllEtwPath` | `EtwEventWrite` / `NtTraceEvent` path in user mode | Low |
| `KernelProcessEtw` | Kernel process/thread/image providers | Medium-High |
| `ETWTI` | Kernel threat-intelligence provider | High |
| `AutoLoggerFile` | Boot or service-start ETL file | Medium-High |
| `KernelCallbackLedger` | `Ps*`, `Ob*`, `Cm*`, WFP, minifilter callbacks | High |
| `EtwIntegrityVerifier` | Kernel walk of provider/session state | High when offsets are verified |
| `CanaryDelivery` | Defender-owned event seen by consumer | Very High for delivery path |
| `LossCounters` | `EventsLost`, `RealTimeBuffersLost`, buffer pressure | Medium |
| `OfflineDump` | Post-incident memory/ETL replay | Very High |
| `RemoteCorrelation` | Evidence already uploaded off-host | Very High |

### 17.4 Session Layout

Use one session per behavioral concern, not one mega-session. A typical layout:

```text
AC_Process    Kernel-Process + ETWTI (Process/Thread/Image keywords)
              Real-time, BufferSize 256-1024 KB, FlushTimer 1 s
AC_Memory     ETWTI (Memory keywords only)
              Real-time, BufferSize 512-1024 KB, FlushTimer 1 s
AC_Thread     Kernel-Process (Thread keyword) + ETWTI (Thread keywords)
              Real-time, BufferSize 512-2048 KB, FlushTimer 2 s
AC_Backup     Everything ELSE
              File-backed, BufferSize 1024-4096 KB, FlushTimer 30 s, compressed if supported
```

Separating sessions buys two properties: independent buffer-loss profiles (the noisy `AC_Thread` session does not steal from `AC_Memory`) and independent tamper surfaces (an attacker that DKOMs one session does not lose visibility from the others). The backup file-mode session, compressed, is the last line of defense. Even if all real-time sessions are silenced, the file persists.

### 17.5 Integrity Verification

The integrity-check routine in §12.2 should run on a 1-5 s timer, but it should not be a single boolean. Split the output into producer integrity, session integrity, and delivery integrity:

| Check family | Example | Meaning |
|--------------|---------|---------|
| Producer | ETWTI `ETW_REG_ENTRY` handle still present; `ProviderEnableInfo.IsEnabled` still set; expected `EnableInfo[]` slot still points at the logger | The provider is still logically enabled. |
| Session | `WMI_LOGGER_CONTEXT` pointer still in the expected slot; `AcceptNewEvents` true; `LoggerStatus` active; loss counters sane | The session can still receive events. |
| Delivery | Canary event emitted and consumed; real-time consumer object present; `RealTimeBuffersLost` stable | The event reached the consumer path. |
| Controller ledger | `Microsoft-Windows-Kernel-EventTracing` still reports session changes; controller's intended provider list matches kernel state | The controller view has not drifted from kernel reality. |

Reports of `ETW_TI_HANDLE_NULLED`, `ETW_TI_DISABLED`, or `ETW_SESSION_DETACHED` are high-confidence tamper signals when the platform baseline and offsets are verified. In production, the response should preserve evidence first: snapshot the relevant kernel structures, loss counters, session names, provider slots, and recent canary sequence. Terminating the affected process may be the right anti-cheat action, but the engineering priority is to prove which layer lied before the attacker forces a reboot or a crash dump.

### 17.6 Adaptive Forensics

When a behavioral score crosses a threshold for a specific PID, spin up a short-lived forensic session filtered to that PID, with targeted stack-walk on the security-relevant event IDs and a hard 60-second timeout. Treat this as a bounded offline artifact path; keep the always-on real-time ETWTI/kernel sessions separate. Compression is useful for ordinary file-mode ETL sessions, but do not assume every private-logger path supports the same mode flags as a normal file logger.

The adaptive session should ask a narrower question than the baseline session:

```text
Baseline:
    Did the behavior happen?
    Did the core ETW fabric remain healthy?

Adaptive:
    Which call chain, module set, register context, branch history, or hidden provider
    explains the suspicious behavior?
```

That distinction controls cost. Baseline sessions avoid global stack walks and high-volume payload fields. Adaptive sessions can temporarily enable `EVENT_FILTER_TYPE_STACKWALK`, context-register capture, LBR, stack caching, or a build-specific TraceLogging provider because they are scoped by PID, duration, and suspicion. The adaptive artifact is not a permanent telemetry source; it is a flight recorder for the minute where the detector has already found smoke.

### 17.7 Signal-Fusion Matrix

For every behavior the defender cares about, list at least two independent sources:

| Behavior | ETW source | Callback / minifilter source |
|----------|-----------|------------------------------|
| Process create | `Microsoft-Windows-Kernel-Process` event 1 | `PsSetCreateProcessNotifyEx` |
| User-mode module load | `Kernel-Process` event 5 | `PsSetLoadImageNotifyRoutine` |
| Driver load | `Kernel-Process` event 5 (kernel image) / ETWTI driver-device events 29-32 | `PsSetLoadImageNotifyRoutine` (Image.SystemModeImage flag) |
| VM alloc / protect / map | ETWTI remote events 1/2/3 and local/kernel-caller variants 6-8, 21-28 | none - ETW-only behavior; verify with memory scan |
| Thread context set | ETWTI 5 (`SETTHREADCONTEXT_REMOTE`) | `PsSetCreateThreadNotifyRoutine` only gives supporting lifecycle context, not an equivalent set-context event |
| Handle open / duplicate | `Microsoft-Windows-Kernel-Audit-API-Calls` plus object-manager callbacks | `ObRegisterCallbacks` |
| File I/O | `Kernel-File` | minifilter |
| Registry I/O | `Kernel-Registry` | `CmRegisterCallbackEx` |
| Network connect | `Kernel-Network` | WFP |

Most behaviors have a non-ETW backup. The ones that don't (VM allocations, memory protection changes) are precisely the ones that ETWTI was designed to surface, and the ones that an attacker who has silenced ETWTI is most likely to use undetected. That is why ETWTI integrity matters so much and why production designs treat it as a single point of failure that needs explicit redundancy via memory scans.

### 17.8 Performance Budget

Indicative numbers, holding everything else constant on a game host:

```text
+ kernel callbacks alone               −2%
+ ETW (separated sessions, no stacks)  −5%
+ ETW integrity check (5 s period)     −5.5%
+ ETW with stack walks                 −10%     ← avoid globally
+ Periodic memory scans                −14%     ← suspicion-only
```

Stack walks and memory scans are the two expensive items; both should be triggered on suspicion rather than left globally on. ETW itself is cheap when filtered carefully and when its sessions are sized correctly.

### 17.9 Buffer Sizing and Loss-Counter Monitoring

The relevant levers in `EVENT_TRACE_PROPERTIES` are `BufferSize` (per-buffer, kilobytes), `MinimumBuffers` / `MaximumBuffers` (total session buffer counts, not per-CPU counts), and `FlushTimer` (flush cadence in seconds). Two rules of thumb:

- For real-time consumers on a busy host: start around `BufferSize = 256-1024 KB`, `MinimumBuffers >= NumberOfProcessors * 2`, `MaximumBuffers >= MinimumBuffers * 2`, `FlushTimer = 1`, then tune from loss counters. Total session buffer memory is approximately `MaximumBuffers * BufferSize`, plus overhead; do not multiply by processor count again because `MaximumBuffers` is already the total buffer count.
- For forensic file-mode sessions that need to survive bursts: use a larger `MaximumBuffers`, a moderate `FlushTimer` such as 10-30 s, and compression where supported. Very large per-buffer sizes reduce flush frequency but increase latency and memory pressure; they are not automatically better.

The most useful monitoring primitive is the loss-counter delta. Public session queries expose `EventsLost`, `LogBuffersLost`, `RealTimeBuffersLost`, `NumberOfBuffers`, `FreeBuffers`, and `BuffersWritten`; the internal mirrors live on `WMI_LOGGER_CONTEXT`. A monitor that samples these values every five seconds and alerts on growth > N per interval catches three failure modes:

1. **Buffer-pool exhaustion** under legitimate load - typically a misconfiguration.
2. **Flusher stuck** behind slow disk or a slow consumer - backpressure escalates loss when the rotation pipeline can't keep up.
3. **Intentional flood** aimed at pushing attacker activity past the flusher's effective window - this is a real, documented offensive primitive against EDRs that don't size their sessions for adversarial input.

```text
WinDbg one-liner to read session loss on a known logger context:
   dx ((nt!_WMI_LOGGER_CONTEXT*)@$ctx)->EventsLost
```

Production EDRs should expose these deltas as self-health signals alongside the integrity check from §12.2. The two together cover "the configuration is intact" and "events are not being thrown away unintentionally".

### 17.10 Recommended Sequence

For a new anti-cheat or EDR engineering effort, the practical ordering is:

1. **Always-on kernel ETW baseline** - ETWTI, Kernel-Process, Kernel-File/Registry/Network where needed, with loss counters exported as health telemetry.
2. **Callback-backed cross-view** - process/image/handle/file/registry/network callbacks for behaviors where ETW can be independently checked.
3. **ETW self-protection** - provider/session integrity sweeps, canary events, `Microsoft-Windows-Kernel-EventTracing` meta-session, and dual-slot ETWTI subscription.
4. **Adaptive forensics** - short-lived private logger with stack, LBR/context-register capture, and file-backed output after suspicion.
5. **Build-specific provider mining** - TraceLogging metadata scan, manifest diff, ETWTI keyword/event validation, and per-build detection-content generation.
6. **Platform hardening** - HVCI, KDP-protected defender state, Secure Boot, TPM measurement, and vulnerable-driver blocklist enforcement.

This order reflects how ETW fails in practice. The first failures are usually configuration, buffer loss, provider filtering, and user-mode patching. The expensive failures are kernel DKOM, BYOVD, Patchless syscall tricks, and consumer-path tampering. Build the cheap, broad self-health loop first, then spend kernel complexity only where the evidence justifies it.

### 17.11 Validation Playbook

A design that cannot be tested against known failure modes is only a diagram. Build a repeatable validation harness with one scenario per ETW layer:

| Scenario | What to simulate | Expected defender signal |
|----------|------------------|--------------------------|
| User-mode patch | Patch `ntdll!EtwEventWrite` inside a sacrificial process | User provider quiet, kernel process/ETWTI still active, code-integrity or COW page signal if monitored |
| ETW hot-path hook | In a lab kernel only, redirect a mock HAL timer `QueryCounter` path while CKCL uses the QPC clock mode | Clock-backend verifier catches pointer outside trusted image range; events still flow, proving this is a hook, not ETW blinding |
| Provider DKOM | In a lab driver only, clear a test provider's enable slot | Provider integrity mismatch, canary for that provider absent, meta-session may still report no stop event |
| Filter inversion | Enable provider with an executable/PID/event filter that excludes the target | Controller ledger differs from expected filter policy; provider still enabled but events missing only for scoped process |
| Consumer starvation | Make `EventRecordCallback` sleep or block on I/O | Real-time loss counters rise, canary delayed, file-mode backup still receives events |
| Buffer flood | Emit high-rate benign events into the same session | `EventsLost` delta and buffer pressure rise; attack window should be visible in health telemetry |
| Stack spoof | Trigger ETWTI event through a spoofed call stack | Event arrives, stack confidence drops, CET audit/exception or unwind anomaly appears where supported |
| Hidden TraceLogging | Register and emit a runtime TraceLogging provider not in the manifest registry | Live provider inventory sees it; manifest-only catalog misses it |
| Boot gap | Start a boot driver before AutoLoggers initialize | GlobalLogger captures phase-0 if configured; ordinary AutoLogger starts too late |

The harness does not need production-grade exploit code. It needs controlled deltas: one layer changed, all other layers stable. Every regression run should answer "which layer lied?" with the same vocabulary the production detector will upload.

---

## 18. Selected Vulnerabilities

The ETW infrastructure itself has carried several classes of bugs, useful both as historical context and as patterns to look for in third-party providers.

- **CVE-2023-21536** - Use-after-free in the ETW filter object. A short race window between filter dereference and filter free; resolved by wrapping with `ExAcquireRundownProtection`/`ExReleaseRundownProtection`. The same pattern recurs in any provider that lets its filter be modified while events are being written.
- **Notification reply info-leak** (Winsider 2023). `EtwSendNotification` reply buffers had partially-uninitialized fields that leaked kernel memory contents to user mode; used as a step in a 35-stage exploitation chain. Patched, but the pattern is generic: any kernel-to-user buffer that mixes "structured fields" with "reserved padding" is a candidate.
- **Provider-callback re-entrancy**. A non-locked Enable callback paired with a non-locked Disable callback double-frees the provider's resources when two controllers enable/disable in quick succession. Not a bug in ETW itself but in nearly every poorly written third-party provider. Mitigation is the `KGUARDED_MUTEX` + `enabled` boolean pattern in §4.2.
- **Bug-check 0x139 (`KERNEL_SECURITY_CHECK_FAILURE`) on `WMI_LOGGER_CONTEXT` corruption.** When DKOM corrupts internal fields such as `LoggerStatus` or a buffer-header pointer, the next ETW routine that touches the structure usually trips a compiler-inserted consistency check (`LIST_ENTRY` validation, refcount underflow, `__fastfail`) and crashes via 0x139. PatchGuard (0x109) is a separate, slower path that samples select ETW state on its own schedule. Either way the crash dump preserves the tampered structure, which is useful as a forensic artifact.
- **`ProcessTrace` / direct-parser infinite loop on malicious ETL.** An attacker-controlled `.etl` with `Event.Size = 0`, an invalid `BufferSize`, or a `SavedOffset` that does not advance can wedge a naive parser. Consumers must implement progress checks in their `BufferCallback` and direct ETL readers must abort a buffer when no event boundary advances.
- **ETWHash (Ceri Coburn / TrustedSec, 2022).** Not a vulnerability per se but a credential-capture primitive that demonstrated subscribing to certain Kerberos / Netlogon ETW providers yields events containing partial handshake material useful for offline cracking. Subsequent variants and refinements have been described publicly but should be re-verified against the current build before assuming the technique still works as originally written. Mitigation: keep the Kerberos provider's keyword bitmask restrictive and watch for unauthorized subscriptions to `Microsoft-Windows-Security-Kerberos` and `Microsoft-Windows-Security-Netlogon`.
- **`Microsoft-Windows-Kernel-EventTracing` blind spot.** The meta-provider that emits events when other sessions are tampered with does not itself emit when *it* is tampered with. A sufficiently sophisticated attacker zeros the meta-provider's `EnableInfo` first, then operates freely. Detection: a defender's session subscribed to the meta-provider should periodically emit a canary event and verify it appears on the consumer side - silent drop-out is the only available signal.
- **Sealighter / re-emitter trust chain.** A signed kernel driver re-emitting ETWTI events on a standard ETW provider (the SealighterTI design) creates a transitive trust boundary - if the re-emitter driver is itself compromised, every consumer of its re-emitted events is misled. Operationally relevant only in test/research environments; production EDRs avoid the architecture.

The common pattern is not "ETW is fragile". It is that ETW is a high-throughput shared kernel subsystem, so every lifetime, size, and trust-boundary mistake is amplified:

| Bug class | ETW-specific shape | Production lesson |
|-----------|--------------------|-------------------|
| Lifetime race | Filter, provider trait, or callback-owned state freed while an event write still references it | Use rundown protection around state read by event-write paths. |
| Reserved-field leak | Notification or control reply copies uninitialized padding back to user mode | Zero every kernel-to-user output buffer before filling fields. |
| Parser progress bug | ETL record with zero size, invalid size, or corrupt buffer offset wedges replay | Enforce progress and bounds per buffer, not just per file. |
| Re-entrancy bug | Enable/disable/capture-state callback allocates/frees without serialization | Treat provider callbacks as concurrent control-plane calls. |
| Trust transitivity | A re-emitter, relay driver, or ETW-to-EVTX bridge becomes the source of truth | Preserve original provider/session identity and mark relay trust separately. |
| Meta-monitor blind spot | The monitor of ETW changes can itself be disabled silently | Monitor the monitor with canary delivery and cross-view session checks. |

This is also the right checklist for auditing third-party providers. Look for callback state without a lock, filter data used after controller updates, event-size calculations that can overflow `USHORT`, direct ETL parsers without a zero-progress guard, and providers that assume `CAPTURE_STATE` cannot race with ordinary writes. Most security bugs around ETW are ordinary systems bugs wearing telemetry clothing.

---

## 19. Industry Context (2024-2026)

Three shifts frame the period this post is written in.

**Kernel ETW became the defensive high ground.** User-mode ETW is approximately as trustworthy as the process whose `ntdll` might be patched. Kernel ETW is approximately as trustworthy as the kernel data structures and session state that route it. On a Secure Boot + HVCI + KDP + ELAM machine, that is a materially different trust tier. EDRs and anti-cheats that lean on user-mode ETW for high-stakes decisions are structurally limited; the ones that lean on kernel ETW, ETWTI, and self-verifying session health are playing on the stronger side of the boundary.

**The Windows Resiliency Initiative changes the incentives.** The July 2024 CrowdStrike outage accelerated Microsoft's public push to move more endpoint-security capability out of third-party kernel drivers and into safer platform-provided telemetry. ETW is one of the few existing Windows mechanisms that can plausibly carry that burden. The direction is clear: more provider coverage, more protected delivery, more user-mode-consumable security telemetry, and more pressure on vendors to prove they can survive without arbitrary kernel hooks.

**TraceLogging turned the provider catalog into a reverse-engineering problem.** The 2026 hidden-TraceLogging work shows that a manifest-only view of ETW is no longer enough. The interesting provider may not be in `wevtutil ep`; it may be a TraceLogging blob in `ntoskrnl.exe`, `windows.storage.dll`, Defender, or a vendor driver. For defenders, this means provider discovery becomes a build pipeline: static TraceLogging metadata scan, live `EnumerateTraceGuidsEx` inventory, manifest diff, provider-binary tracking, and per-build rule generation.

The remaining fight is the one between Patchless bypass and ETWTI. Hardware breakpoints + VEH + `NtContinue`, two-layer VEH for `LayeredSyscall`, argument spoofing via `TamperingSyscalls`, call-stack spoofing via `SilentMoonwalk` and `CallStackSpoofer`, RPC provider cache patching, and filter-inversion all try to avoid the state that integrity checks cover. The defensive answer is not a single event ID. It is a system: KDP-protected defender state, sub-second integrity sweeps, canary-event heartbeats, dual-slot ETWTI subscription, `Microsoft-Windows-Kernel-EventTracing` self-watching, zero-event behavioral correlation, and CET shadow-stack events where hardware supports them.

The structural property is simple: the defender owns the hardware platform and the kernel policy. The attacker has to pay for stealth in complexity, fragility, per-build offsets, thread-local limitations, or operational noise. The defender's job is to keep making that bill compound.

---

## References

### Microsoft official documentation
- Windows 11 release information (26H1 / 25H2 / 24H2 build table and 26H1 servicing note): https://learn.microsoft.com/windows/release-health/windows11-release-information
- May 26, 2026 preview update for 25H2 / 24H2 (`26200.8524` / `26100.8524`): https://support.microsoft.com/topic/may-26-2026-kb5089573-os-builds-26200-8524-and-26100-8524-preview-f378c8ae-0170-47c9-a1e9-dfef978c8e17
- Windows SDK overview (`10.0.28000` current SDK page): https://learn.microsoft.com/windows/apps/windows-sdk/
- About Event Tracing - Microsoft Learn: https://learn.microsoft.com/windows/win32/etw/about-event-tracing
- StartTrace / session limits / system-wide private logger notes: https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-starttracea
- EVENT_TRACE_PROPERTIES (evntrace.h): https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
- EVENT_TRACE_PROPERTIES_V2 and session filters: https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_properties_v2
- Configuring and Starting the NT Kernel Logger Session: https://learn.microsoft.com/windows/win32/etw/configuring-and-starting-the-nt-kernel-logger-session
- Configuring and Starting a SystemTraceProvider Session: https://learn.microsoft.com/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
- Protecting anti-malware services / protected antimalware service requirements: https://learn.microsoft.com/windows/win32/services/protecting-anti-malware-services-
- ENABLE_TRACE_PARAMETERS and provider filters: https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
- EVENT_FILTER_DESCRIPTOR / filter constants (26100 SDK cross-check): https://learn.microsoft.com/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor
- EventRegister / provider registration: https://learn.microsoft.com/windows/win32/api/evntprov/nf-evntprov-eventregister
- EventWriteTransfer / ActivityId and RelatedActivityId: https://learn.microsoft.com/windows/win32/api/evntprov/nf-evntprov-eventwritetransfer
- EventActivityIdControl / thread activity IDs: https://learn.microsoft.com/windows/win32/api/evntprov/nf-evntprov-eventactivityidcontrol
- EventSetInformation / EVENT_INFO_CLASS: https://learn.microsoft.com/windows/win32/api/evntprov/ne-evntprov-event_info_class
- Provider Traits and Provider Groups: https://learn.microsoft.com/windows/win32/etw/provider-traits
- EVENT_HEADER_EXTENDED_DATA_ITEM (evntcons.h): https://learn.microsoft.com/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
- EVENT_TRACE_LOGFILE and consumer callbacks: https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
- ProcessTrace / file-vs-real-time consumer limits: https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-processtrace
- Consuming Events / EventRecordCallback / BufferCallback: https://learn.microsoft.com/windows/win32/etw/consuming-events
- TdhGetEventInformation: https://learn.microsoft.com/windows/win32/api/tdh/nf-tdh-tdhgeteventinformation
- TraceLogging overview: https://learn.microsoft.com/windows/win32/tracelogging/trace-logging-about
- WPP software tracing / tracewpp / TMH: https://learn.microsoft.com/windows-hardware/drivers/devtest/adding-wpp-software-tracing-to-a-windows-driver
- WPP vs manifest/TraceLogging ETW comparison: https://learn.microsoft.com/windows-hardware/drivers/devtest/tools-for-software-tracing
- Logging Mode Constants: https://learn.microsoft.com/windows/win32/etw/logging-mode-constants
- System Providers: https://learn.microsoft.com/windows/win32/etw/system-providers
- Configuring and Starting a Private Logger Session: https://learn.microsoft.com/windows/win32/etw/configuring-and-starting-a-private-logger-session
- TraceQueryInformation / TRACE_QUERY_INFO_CLASS: https://learn.microsoft.com/windows/win32/api/evntrace/ne-evntrace-trace_query_info_class
- TRACE_CONTEXT_REGISTER_INFO / context-register tracing: https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-trace_context_register_info
- dotnet-trace provider syntax and current profile masks: https://learn.microsoft.com/dotnet/core/diagnostics/dotnet-trace
- .NET Framework Loader ETW events (ModuleLoad/AssemblyLoad flags): https://learn.microsoft.com/dotnet/framework/performance/loader-etw-events

### Kernel structures
- Geoff Chappell - WMI_LOGGER_CONTEXT, ETW_GUID_ENTRY, ETW_REG_ENTRY, ETW_NOTIFICATION_TYPE, ETWP_NOTIFICATION_HEADER, EtwActivityIdCreate, EtwSendNotification: https://www.geoffchappell.com/
- Geoff Chappell - WMI_LOGGER_INFORMATION / NtTraceControl logger input-output structure: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/wmi_logger_information/index.htm
- NtDoc / PHNT - NtTraceControl and ZwTraceControl prototypes: https://ntdoc.m417z.com/nttracecontrol
- Vergilius Project - Windows 11 25H2 public type views: https://www.vergiliusproject.com/kernels/x64/windows-11/25h2
- Vergilius Project - _WMI_LOGGER_CONTEXT 25H2: https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_WMI_LOGGER_CONTEXT
- Vergilius Project - _ETW_SILODRIVERSTATE 25H2: https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_ETW_SILODRIVERSTATE
- Vergilius Project - _ETW_GUID_ENTRY / _ETW_REG_ENTRY 25H2: https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_ETW_GUID_ENTRY
- Vergilius Project - _ETW_REG_ENTRY 25H2: https://www.vergiliusproject.com/kernels/x64/windows-11/25h2/_ETW_REG_ENTRY

### Security research
- Yarden Shafir, "ETW internals for security research and forensics" - Trail of Bits, 2023: https://blog.trailofbits.com/2023/11/22/etw-internals-for-security-research-and-forensics/
- Ruben Boonen, "Direct Kernel Object Manipulation (DKOM) Attacks on ETW Providers" - IBM X-Force, 2023: https://www.ibm.com/think/x-force/direct-kernel-object-manipulation-attacks-etw-providers
- Asuka Nakajima, "Hidden Telemetry: Uncovering TraceLogging ETW Providers You're Not Using (Yet)" - Black Hat Asia 2026: https://speakerdeck.com/asuna_jp/blackhatasia2026-hidden-telemetry-uncovering-tracelogging-etw-providers-youre-not-using-yet
- "ETW Threat Intelligence and Hardware Breakpoints" - Praetorian
- "Kernel ETW is the best ETW" - Elastic Security Labs: https://www.elastic.co/security-labs/kernel-etw-best-etw/
- "Doubling Down: Detecting In-Memory Threats with Kernel ETW" - Elastic
- "Full Spectrum ETW Detection in Windows Kernel" - fluxsec.red
- Connor McGarr, "Check Your Privilege - ETW SecurityTrace": https://connormcgarr.github.io/securitytrace-etw-ppl/
- "Tampering with Windows Event Tracing" - Palantir Blog

### Hooking and bypass
- Technique-to-ETW-layer mapping for this subsection is in §11.10.
- InfinityHook - https://github.com/everdox/InfinityHook
- "Hooking All System Calls In Windows 10 20H1" - Anze Lesnik: https://lesnik.cc/hooking-all-system-calls-in-windows-10-20h1/
- "Hooking System Calls in Windows 11 22H2 like Avast Antivirus" - Denis Skvortcov, 2022: https://the-deniss.github.io/posts/2022/12/08/hooking-system-calls-in-windows-11-22h2-like-avast-antivirus.html
- "Hooking Context Swaps with ETW" - archie-osu.github.io, 2025: https://archie-osu.github.io/etw/hooking/2025/04/09/hooking-context-swaps-with-etw.html
- "Bypassing ETW For Fun and Profit" - White Knight Labs: https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/
- "A universal EDR bypass built in Windows 10" - Wavestone / EDRSandBlast family: https://github.com/wavestone-cdt/EDRSandblast
- "Design issues of modern EDRs: bypassing ETW-based solutions" - Binarly: https://www.binarly.io/blog/design-issues-modern-edrs-bypassing-etw
- "ETW Threat Intelligence and Hardware Breakpoints" - Praetorian: https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/
- PatchlessEtwAndAmsiBypass (Kazuar v3 inspiration) - https://github.com/TheEnergyStory/PatchlessEtwAndAmsiBypass
- LayeredSyscall (two-layer VEH) - https://github.com/WKL-Sec/LayeredSyscall
- TamperingSyscalls (argument-spoofing) - https://github.com/rad9800/TamperingSyscalls
- SilentMoonwalk (stack desynchronization) - https://github.com/klezVirus/SilentMoonwalk
- CallStackSpoofer / VulcanRaven - https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs
- RPC ETW evasion - `rpcrt4!`-internal provider-state/cache behavior and RPC runtime bypasses, publicly described in Akamai research: https://www.akamai.com/blog/security-research/msrpc-defense-measures-in-windows-etw
- `EVENT_FILTER_TYPE_EXECUTABLE_NAME` filter-inversion - Olaf Hartong, "Falcon Quirks" series

### System Providers and PERFINFO_GROUPMASK
- "System Providers" - Microsoft Learn
- `perfinfo_groupmask.hpp` - github.com/microsoft/krabsetw
- "PERFINFO_GROUPMASK" - Geoff Chappell
- "NTWMI.H" reference - Windows WDK
- "Tracing System Activity Using TraceEvents" - Microsoft Learn

### Forensics
- Shusei Tomonaga, "ETW Forensics" - JPCERT/CC, 2024
- "Event Tracing for Windows Internals" - CODE BLUE 2024
- JPCERT/CC Eyes, "ETW Forensics - Why use Event Tracing for Windows over EventLog?", 2024: https://blogs.jpcert.or.jp/en/2024/11/etw_forensics.html
- FortiGuard Labs, "Uncovering Hidden Forensic Evidence in Windows: The Mystery of AutoLogger-Diagtrack-Listener.etl", 2025: https://www.fortinet.com/blog/threat-research/uncovering-hidden-forensic-evidence-in-windows-mystery-of-autologger

### Manifest binary format
- libfwevt documentation (libyal) - Windows Event manifest binary format
- Willi Ballenthin, "Extracting WEVT_TEMPLATEs from PE files"
- jdu2600 / Windows10EtwEvents - TSV-flattened manifests per build
- nasbench / EVTX-ETW-Resources - manifest archive
- repnz / etw-providers-docs - XML manifest archive

### Tools
- EtwExplorer (zodiacon)
- PerfView (microsoft/perfview)
- wevt_template (williballenthin)
- krabsetw (microsoft/krabsetw)
- SealighterTI (pathtofile/SealighterTI)
- EtwTi-FluctuationMonitor (jdu2600)
- EtwTiViewer (adanto)
- provmon (olafhartong) - built around `Microsoft-Windows-Kernel-EventTracing`
- WinDbg JS scripts for ETW kernel routines - Trail of Bits (`EtwKernelRoutines.js`)
- wtrace - wtrace.net
- tracelogging (microsoft/tracelogging) - C++ Dynamic API reference implementation
- TLGMapper (AsuNa-jp) - TraceLogging metadata and event-to-provider/function mapping: https://github.com/AsuNa-jp/TLGMapper
- dotnet-trace - github.com/dotnet/diagnostics (CLR ETW + EventPipe)
- Elastic detection-rules - github.com/elastic/detection-rules (provider-GUID-keyed rules)

### Commercial EDR analysis
- Elastic Security Labs - "Doubling Down on ETW callstacks" (2023)
- Elastic Security Labs - "Upping the Ante: Detecting In-Memory Injection Techniques"
- Yarden Shafir - "ETW Internals" course material and `windows-internals.com` posts on ETWTI
- Outflank - direct-syscall and indirect-syscall research (2022-2024)
- MDSec - execute-assembly and CLR-ETW evasion writeups
- Red Canary - Threat Detection Report (annual; ETW provider coverage)

### Credential capture / specialized
- "ETWHash" - Ceri Coburn (TrustedSec), 2022 + 2024 refinement
- "Hiding your .NET ETW" - xpn (Adam Chester), 2020
- "Patchless AMSI Bypass via Hardware Breakpoints" - SpecterOps / HellsHollow / AceLdr
- "g_amsiContext corruption" - S3cur3Th1sSh1t, Rastamouse

### .NET CLR ETW
- ClrEtwAll.man - github.com/dotnet/runtime (`src/coreclr/vm/ClrEtwAll.man`)
- "Microsoft-Windows-DotNETRuntime keyword reference" - PerfView wiki
- dotnet-trace current profile presets and provider syntax (`0x100003801D`, `0x14C14FCCBD`): https://learn.microsoft.com/dotnet/core/diagnostics/dotnet-trace

### Runtime discovery APIs
- `EnumerateTraceGuidsEx` - Microsoft Learn, advapi32.dll
- `TraceQueryInformation` - Microsoft Learn
- `TRACE_PROVIDER_INSTANCE_INFO` structure documentation

### Compression and PERFINFO_GROUPMASK
- "ETW Trace Compression and xperf" - Random ASCII (Bruce Dawson)
- Geoff Chappell - PERFINFO_GROUPMASK
- krabsetw `perfinfo_groupmask.hpp`

### AMSI / PowerShell
- Microsoft Learn - AMSI integration with Microsoft Defender Antivirus
- Red Canary - Better Know a Data Source: AMSI
- "Threat Hunting AMSI Bypasses" - Pentest Laboratories

### Vulnerability case studies
- Danny Odler, "Racing bugs in Windows kernel" (CVE-2023-21536)
- Winsider, "Exploiting a 'Simple' Vulnerability - Part 1/5: The Info Leak"

---

*Reference target: Windows 11 25H2 (ntoskrnl 10.0.26200.x) with 24H2 deltas noted where useful; 26H1 (10.0.28000.x) is mentioned where public Microsoft release or SDK data exists, but private layout claims still require symbols for the exact target. Structure offsets, provider GUIDs, ETWTI event-ID-to-function mappings beyond the publicly symbolic ones, TraceLogging provider catalogs, and the exact runtime layout of vendor-specific EDR session names all drift across builds and platform versions. Production code and SOC content should resolve these against the live target (Vergilius/PDB for structures, `logman query providers`/`wevtutil gp`/static TraceLogging metadata scans for provider metadata, `fltmc` for minifilter altitudes, `!wmitrace.strdump` for live session state) rather than copying the values in this document verbatim. Where this document refers to publicly described offensive techniques, the attribution and exact details should be cross-checked against the cited primary sources before being treated as canonical. Security research in this space moves quickly and writeups occasionally contain errors that propagate downstream. The offensive techniques in this document are presented for defensive understanding only.*
