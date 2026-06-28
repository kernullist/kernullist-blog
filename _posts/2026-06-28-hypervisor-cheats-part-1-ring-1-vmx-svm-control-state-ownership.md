---
title: "About Hypervisor Cheats, Part 1: Ring -1, VMX/SVM, and Control-State Ownership"
date: 2026-06-28 00:00:00 +0900
categories: [Windows Internals, Anti-Cheat]
tags: [hypervisor, vmx, svm, vmcs, vmcb, anti-cheat, virtualization, windows]
---

> Hypervisor cheats are not magic Ring -1 stories. They are ownership changes over CPU state, second-stage translation, event delivery, and evidence. This opening post builds the vocabulary for the rest of the series: who owns control, which state was actually consumed by the processor, and why static memory artifacts are not enough to prove a live hypervisor.

## Scope

This part is the architectural foundation. It separates privilege rings from virtualization ownership, follows VMX/SVM control state into VMCS/VMCB fields, and frames later conclusions around authority, data path, invariant, failure mode, and observable evidence.

---

## Technical Principles of Hypervisor-Based Game Cheats

### Executive Summary

Hypervisor-based game cheats should not be explained as a mysterious "Ring -1" trick. The real mechanism is ownership transfer: CPU virtualization creates control state below the guest operating system, and that state can mediate guest memory translation, selected CPU events, timing behavior, and device or input paths before Windows and the game consume them. The important question is not only "which ring is this code in?" but "which layer controlled the state that the CPU actually used?"

A below-OS observer can see CPU state, second-stage translation state, interrupt/timer state, device transactions, or guest memory bytes. None of those observations automatically proves a live game object, a player-visible fact, or a server-visible advantage. The missing work is always the bridge from hardware state to OS state, from OS state to engine meaning, and from engine meaning to player behavior.

The series follows that bridge in order:

1. **Hypervisor technology first.** VMX/SVM, VMCS/VMCB, VM-exits, EPT/NPT, address translation, VMI, and SMP/performance constraints define what is technically possible.
2. **Cheat operation second.** A cheat turns those primitives into memory acquisition, game-object reconstruction, overlay/input delivery, and stealth consistency.
3. **Anti-cheat response third.** Defensive reasoning should combine platform trust, virtualization consistency, memory-view checks, device/DMA posture, I/O evidence, and server-side behavior as separately owned evidence. A single local probe can support only the authority it observes, so broader cheat or enforcement wording requires explicit joins across those owners.

This post avoids loader instructions, exploit chains, game offsets, bypass code, or implementation-ready cheat code. It focuses on technical mechanisms, state transitions, scope boundaries, failure modes, and defensive engineering.

---

## Part I. Hypervisor Technology Fundamentals

### 1. Mental Model: Rings Are Not Enough

Traditional Windows cheat discussions often focus on rings, but rings answer only who can execute privileged code inside the guest. They do not identify the active virtualization owner, the second-stage translation root, the interrupt and timer route, the device-remapping domain, or the epoch that consumed a control object. Ring privilege is only one local capability; it does not by itself prove VMX/SVM ownership, a manipulated memory view, process-memory access, player knowledge, or server-visible impact.

```text
Ring 3  user-mode game, overlay, launcher
Ring 0  Windows kernel, drivers, anti-cheat driver
```

Hardware virtualization adds a different ownership axis with a separate control state, event route, and translation authority. The phrase "below the kernel" is too weak unless the analysis also names the active VMCS/VMCB epoch, the EPT/NPT root defining the memory view, the interrupt fabric delivering events, and the device-remapping owner that allows or denies DMA.

```text
VMX root / SVM host       hypervisor control layer
VMX non-root / SVM guest  Windows kernel and user-mode software
```

The hypervisor is not simply "more privileged Ring 0." It controls the execution environment in which the guest OS runs. The guest still believes it owns CR3, page tables, interrupts, MSRs, timers, and memory permissions, but the CPU can route selected events to the hypervisor first.

The core data path that must stay separated during analysis is an authority chain from game observation down to second-stage translation and hardware state. This chain is also separate from the delivery path that turns a cue into a player decision. Without that separation, "observed in memory" can be over-promoted into "the player used information outside legitimate visibility."

```text
Game and anti-cheat
  -> Windows kernel
  -> guest virtual memory and guest page tables
  -> EPT/NPT second-stage translation controlled by hypervisor
  -> physical memory and hardware-facing state
```

For anti-cheat, this means a malicious or untrusted hypervisor can move the cheat's artifacts outside the normal Windows model. The game process may have no injected DLL, no suspicious handle, and no modified guest page table, while a lower layer still reads or manipulates game state. The limit is just as important: a missing Windows artifact is not proof of absence, and a lower-layer read is not gameplay impact until process ownership, semantic interpretation, delivery, and replay/server consequence are connected.

#### 1.1 What the Hypervisor Actually Owns

The useful mental model is not "ring -1 is stronger than ring 0." The useful model is ownership of architectural contracts. A hypervisor owns the boundary conditions under which ring 0 executes.

Ownership here has a precise meaning. The hypervisor does not automatically own every truth about the system, the Windows memory manager, the game engine, or the player. It owns the CPU and platform contracts that decide how the guest is allowed to run, which state is loaded or saved, which events are intercepted, which physical view backs a guest physical address, and which clocks or virtual devices are presented. Anything stronger has to connect that owned contract to the next layer.

```text
hypervisor_ownership_model =
  architectural_contract
  -> control_object_or_translation_root
  -> guest_visible_illusion
  -> observable_cross_check
  -> unowned_authority_boundary
  -> join_to_next_layer
```

In practice, the word "owns" should answer four questions before the analysis moves to a higher layer:

| Ownership question | Strong answer | Weak or overbroad answer |
|---|---|---|
| Which contract is owned? | execution, state, translation, event delivery, time, platform, or device boundary is named | "ring -1 owns everything" |
| Which control object carries it? | VMCS, VMCB, EPTP, `N_CR3`, intercept bitmap, MSR policy, APIC virtualization state, IOMMU domain, or TLFS contract | generic "hypervisor state" |
| Which guest-visible story should agree? | CPUID/MSR/CR/APIC/timer/page-table/Windows policy observer is named | one clean value is treated as full consistency |
| Which authority remains unowned? | Windows page-state, engine semantics, delivery path, server truth, or player knowledge remains separate | lower-layer visibility is promoted directly to gameplay truth |

| Owned contract | What the guest believes | What the hypervisor can actually control | Technical consequence |
|---|---|---|---|
| execution contract | privileged instructions, exceptions, interrupts, and returns behave like bare metal | selected instructions and events can be routed to VMX root or SVM host first | the guest can be correct locally while still running inside a constrained execution envelope |
| state contract | CRs, DRs, MSRs, segment state, descriptor tables, and APIC state are the machine state | VMCS/VMCB state can virtualize, shadow, save, restore, or reject those values | detection cannot rely on one register story; related state must be cross-checked |
| translation contract | CR3-selected page tables define process memory | guest virtual translation is only the first stage; EPT/NPT decides the final physical view | guest page tables can look clean while the second stage blocks, redirects, or observes access |
| event contract | faults and interrupts are delivered according to architectural priority | exit controls, qualification fields, and reinjection paths can interpose on delivery | wrong event ordering is a stronger signal than a single suspicious value |
| time contract | TSC, APIC timers, QPC, HPET, scheduler time, and network time are mutually plausible | TSC offset/scaling and timer exits can alter some clocks but not all observers equally | timer hiding is a coherence problem, not a single-field spoof |
| platform contract | Windows observes a coherent boot, Hyper-V, VBS, device, and policy story | a VMM may coexist with or conflict with the platform's legitimate hypervisor/trust state | modern analysis must include Hyper-V/TLFS/VSM state, not just CPUID |

This is why hypervisor analysis should start from contracts rather than artifacts. A DLL, handle, driver object, or guest PTE is only one possible manifestation. The deeper question is whether execution, state, translation, event delivery, time, and platform policy still describe one machine. A useful cross-check is to hold the guest workload constant and vary the observer: guest user-mode, guest kernel, CPU native payload, second-stage table replay, Hyper-V/TLFS observer where present, device or DMA posture, and gameplay/replay consequence. If those observers disagree, the analysis should name the first contract that broke instead of jumping straight to a cheat label.

#### 1.2 From Hardware Facts to Game Facts

Each observation belongs to a specific layer. A CPU manual can define what an EPT violation means; it cannot prove which Windows process owned the byte. A Windows memory API can define region, residency, and read-access semantics; it cannot prove that the second-stage translation root was honest. An engine replay can prove server-visible consequence; it cannot prove how the local endpoint learned the hidden state.

The table below keeps each observation at the layer it actually supports. Absence at one layer can disprove a narrow bridge, but it cannot disprove a broader mechanism unless the missing owner, epoch, and observer scope are named.

| Layer | Source of truth | What it can prove | What it cannot prove alone | Needed bridge |
|---|---|---|---|---|
| CPU execution authority | VMCS/VMCB controls, VM-entry or `VMRUN` result, exit reason, event-injection state, interruptibility, vendor capability source | a guest event was configured, intercepted, injected, blocked, or resumed under a CPU contract | process ownership, object meaning, player knowledge, server consequence, or endpoint policy truth | guest mode, vCPU epoch, raw vendor payload, platform owner, and re-entry result |
| First-stage translation authority | guest CR3, paging mode, PCID or ASID context, guest PTE chain, KVA split state, Windows address-space lifetime | a GVA translated to a GPA under a named guest address-space epoch | final physical bytes, second-stage permission, COW ownership, working-set residency, or game object lifetime | second-stage root, Windows region contract, process lifetime, and invalidation context |
| Second-stage translation authority | EPTP or `N_CR3`, EPT/NPT leaf chain, memory type, R/W/X bits, A/D state, EPT violation or NPF payload, invalidation action | a GPA was mapped, denied, redirected, or faulted by the hypervisor-owned translation layer | Windows read legality, private/process ownership, engine semantics, or user-visible advantage | first-stage walk, page-state join, per-core stale-translation proof, and semantic target |
| Host physical byte authority | host physical mapping, dump offset, VMI physical read, debugger memory read, DMA acquisition path | bytes existed at an acquisition address and time | that the bytes were accessible to Windows, belonged to a live process, or represented a current game object | translation proof, OS-read parity, backing-store state, range coherence, and acquisition clock |
| Windows process semantic authority | `VirtualQueryEx`, `MEMORY_BASIC_INFORMATION`, `QueryWorkingSetEx`, `PSAPI_WORKING_SET_EX_BLOCK`, `ReadProcessMemory`, VAD or PTE debugger evidence | region class, selected page attributes, working-set state, COW clues, and handle-bound read parity | hidden second-stage ownership, lower-layer mutation, or gameplay meaning | CPU translation chain, acquisition path, module/section owner, semantic decoder, and epoch |
| Execution-policy authority | page protection, CFG target policy, CET user shadow-stack policy, HVCI/KCFG/KCET source-of-truth fields, second-stage execute permission | whether a code address was permitted, invalid, trapped, or protected by a named execution policy | data visibility, memory acquisition, or gameplay consequence | event payload, module identity, policy epoch, call target or shadow-stack state, and behavior join |
| Engine semantic authority | object root, allocator generation, class metadata, component graph, replication state, prediction/correction state, replay or spectator surface | a byte sequence can be interpreted as a candidate object, surface, or epoch inside an engine model | server truth, player knowledge, anti-cheat label, or offset stability across private builds | source-backed surface class, server/replay authority, object lifetime proof, and decoder version |
| Delivery authority | display/capture path, compositor state, overlay plane, HID or Raw Input path, input timing, foreground/session context | information or automation plausibly reached a human, capture stack, or input stream | local acquisition source, hidden-information access, or server-visible effect | local technical chain, replay tick, input/output epoch, and behavior consequence |
| Platform posture authority | TLFS/VBS/VTL state, TPM or attestation output, App Control/driver policy, Kernel DMA Protection, firmware or device posture | measured boot, policy state, legitimate hypervisor story, device/DMA posture, or entry eligibility | runtime EPT/NPT ownership, process-memory access, game-object access, or cheat absence | runtime contradiction, transition evidence, endpoint telemetry, and source-specific negative control |
| Tool and harness authority | HyperDbg, LibVMI, KVMi, DRAKVUF, QEMU/KVM, LiveCloudKd, Volatility, MemProcFS, LeechCore, CHIPSEC, lab VMMs | what a named tool/backend observed or mutated under a pinned configuration | production endpoint truth, absence of compromise, or equivalence to another acquisition path | provenance context, mutation budget, endpoint comparator, independent corroboration, and freshness gate |

The practical rule is mechanical: write the conclusion from the weakest surviving bridge. If the chain stops at a second-stage fault, the conclusion is a translation-layer event. If it reaches bytes but not Windows region and read parity, it is a below-OS byte sample. If it reaches Windows parity but not engine lifetime, it is a process-memory candidate. If it reaches engine lifetime but not delivery or server consequence, it is a local semantic hypothesis. Stronger wording needs evidence from every layer it names.

### 2. VMX/SVM Control State

Intel VT-x uses VMX root and non-root operation. AMD-V/SVM uses host and guest operation. The exact names differ, but the engineering invariant is similar: the active owner must consume a legal control object, enter guest execution, preserve native exit payloads, and return with state that remains coherent across CPU, OS, nested, and device observers. A statement that stops at "VMX is enabled" or "SVM is enabled" is therefore only a mode candidate, not proof of runtime control-state ownership.

| Concept | Intel term | AMD term | Why it matters |
|---|---|---|---|
| Virtual CPU control block | VMCS | VMCB | Holds guest state, host state, and control policy |
| Second-stage paging | EPT | NPT/RVI | Lets the hypervisor translate guest physical memory to host physical memory |
| Exit to hypervisor | VM-exit | #VMEXIT | Lets selected guest events be handled below the OS |
| Entry to guest | VM-entry | VMRUN/resume | Returns control to Windows after emulation or policy handling |
| Per-register/event filtering | MSR bitmaps, I/O bitmaps, exception bitmap | intercept vectors and bitmaps | Keeps overhead manageable by avoiding unnecessary exits |

Control state is where the hypervisor becomes concrete. Handler code only runs when the VMCS or VMCB routes an event out of the guest. Treating VMX/SVM as a single privilege bit misses the real model: a CPU-enforced policy engine for state, translation, event routing, and return-to-guest behavior. The data path is control object -> legal transition -> native payload -> handler mutation -> re-entry result; the common mistake is skipping one of those owners while still talking about process memory, game semantics, or stealth consistency.

The section-level invariant is consumed control, not configured control. A VMCS, VMCB, bitmap, intercept vector, or nested-enlightenment structure matters only when the responsible owner consumes it in a legal transition and leaves a replayable payload. The defender observable is the conservation of guest state, host resume state, control policy, exit qualification, and re-entry result across that transition. A useful cross-check is wrong-owner replay: substitute a stale, copied, L1-visible, wrong-core, or never-entered control object and see whether the conclusion falls back to a narrower statement.

#### 2.1 State Groups

A hypervisor cheat must keep several state groups coherent across the same vCPU/core, timebase, translation root, interrupt epoch, and device view. If it only spoofs one surface, the rest of the machine can contradict it because each state group has a different owner and a different failure signature.

| State group | Contents | Failure if wrong |
|---|---|---|
| Guest architectural state | CR0/CR3/CR4, RIP/RSP/RFLAGS, segment state, descriptor tables, debug registers | Windows crashes, produces impossible telemetry, or diverges across cores |
| Host resume state | host CR3, host stack, host RIP, host selectors, MSRs used after an exit | VM-exit handling becomes unstable, especially with NMIs or interrupts |
| Execution controls | CPUID, RDTSC, CR access, MSR access, exceptions, interrupts, I/O, EPT/NPT violations | Broad controls create latency. Narrow controls lose visibility. |
| Memory translation state | EPT/NPT root, memory type, permissions, accessed/dirty behavior | stale translations, cache anomalies, inconsistent page views |
| Event qualification state | exit reason, exit qualification, guest linear address, guest physical address | bad emulation changes guest-visible behavior |
| Interrupt and timer state | APIC/x2APIC mode, TPR/PPR, virtual interrupt state, posted-interrupt state, TSC offset/scaling, deadline timers | impossible latency, lost interrupts, duplicated events, or timing probes that disagree with guest clocks |
| Extended processor state | XCR0, XSS, XSAVE area, FPU/SSE/AVX/AVX-512/AMX availability, PKU/CET/LAM-adjacent state | CPUID and exception behavior disagree with saved context or enabled features |
| Device and IOMMU state | remapping domain, requester id, PASID, ATS/PRI state, interrupt-remapping entry, device assignment epoch | DMA and interrupt evidence cannot be joined to the CPU translation story |
| Nested or enlightened state | eVMCS, enlightened TLB flush state, synthetic interrupt state, nested EPT/NPT ownership | L1-visible state is mistaken for bare-metal ownership |
| Per-vCPU scratch state | temporary mappings, single-step state, pending events, current target process | races across cores and intermittent corruption |
| Tool and provenance state | decoder version, symbol profile, acquisition epoch, pause/freeze policy, observer route | stale tooling output is promoted into endpoint truth |

These groups are not independent checkboxes. A VM-exit consumes guest state, host resume state, control policy, translation state, and qualification fields as one transition. A credible analysis should therefore name the transition that joins them: which logical processor owned the control object, which VMCS/VMCB epoch was current, which guest instruction or event caused the exit, which translation root was active, which fields were updated by hardware, which fields were only cached by software, and which pending event was injected or suppressed on re-entry.

The invariant is cross-group conservation. Changing only CPUID while leaving `CR4.OSXSAVE`, XState masks, MSR accessibility, and guest exception behavior unexplained is only a feature story, not a coherent virtual CPU model. Naming an EPT violation while omitting the active EPTP/NPT root, invalidation epoch, guest-linear validity, and re-entry action gives a fault candidate, not a memory-view proof. This is why VMX/SVM analysis should start with state groups before it names a hook, an exit handler, or a cheat capability.

The attacker leverage is selective conservation. A thin malicious hypervisor wants to conserve only the state groups that the guest or anti-cheat is likely to cross-check, while allowing unobserved groups to drift. The defender observable is therefore not one suspicious field; it is a conservation failure across owners that should have changed together. A TSC story that disagrees with interrupt delivery, a CPUID story that disagrees with XState exception behavior, an EPT story that disagrees with Windows page-state replay, or a PASID story that disagrees with the CPU address-space root is stronger than any isolated row.

The safe wording rule is simple: a state group names a native owner, not a gameplay conclusion. "The VMCS says X" is still only a VMCS-local statement until the consuming transition, guest-visible effect, and later layer bridges are named.

#### 2.2 Intel VMCS Layout in Practice

The Intel VMCS is not a single flat "context." It is a field-encoded control object whose guest-state, host-state, control, and exit-information owners are consumed at different transition points: VM-entry, guest execution, VM-exit, and handler re-entry.

| VMCS field class | Examples | Why it matters |
|---|---|---|
| Guest-state fields | guest CR0/CR3/CR4, RIP/RSP/RFLAGS, segment selectors, GDTR/IDTR, activity state, interruptibility state | Defines what Windows sees as the current CPU state |
| Host-state fields | host CR0/CR3/CR4, host RIP/RSP, host segment selectors, host MSRs | Defines where the CPU resumes when an exit happens |
| Pin-based execution controls | external interrupt exiting, NMI exiting, virtual NMIs, posted interrupts where supported | Controls interrupt and NMI routing between guest and hypervisor |
| Primary processor-based controls | HLT, INVLPG, MWAIT, RDTSC, CR3 load/store, CR access, I/O bitmaps, MSR bitmaps, TSC offsetting, MTF | Selects common instruction and control-state exits |
| Secondary processor-based controls | EPT, VPID, unrestricted guest, RDTSCP, INVPCID, VMFUNC, EPT-violation #VE, PML and related features where supported | Enables modern virtualization features and finer event control |
| VM-exit controls | host address size, MSR load/store behavior, acknowledgement of interrupts on exit | Controls how much state is saved or restored when leaving the guest |
| VM-entry controls | guest IA-32e mode, entry event injection, MSR load behavior | Controls how the CPU resumes the guest |
| VM-exit information fields | exit reason, exit qualification, guest linear address, guest physical address, instruction length, interruption info | Gives the handler enough detail to emulate or classify the event |

For cheat analysis, several VMCS fields are especially important because each one creates a different intercept, timing, translation, or re-entry owner. A useful analysis row preserves the field family, the controlling capability MSR or allowed-bits source, the vCPU epoch, and the post-transition artifact instead of flattening the tuple into "VMX was enabled."

- **Exception bitmap:** Determines which guest exceptions exit. It affects hidden breakpoints, single-step behavior, debug register use, and anti-probe logic.
- **MSR bitmap:** Allows selective exiting on RDMSR/WRMSR. Broad MSR interception is noisy. Selective interception requires knowing which MSRs Windows and security products legitimately touch.
- **I/O bitmap:** Similar filtering for port I/O. Modern games rely on it less often, but it still matters for device and timing probes.
- **CR3 target controls and CR access exiting:** CR3 changes can help identify process-context switches, but context switches are frequent. A design that exits on all CR3 movement can become very noisy.
- **TSC offset/scaling-related controls where available:** These can shape guest-visible time, but independent clock sources make long-term consistency hard.
- **EPT pointer and EPT controls:** Select the second-stage address-translation root and related EPT behavior.
- **VPID:** Tags guest TLB entries so guest context changes do not require as much flushing. It improves performance but adds invalidation complexity.
- **Monitor Trap Flag:** Can force a VM-exit after one guest instruction. It is useful for temporary mapping restoration but expensive and timing-visible if overused.

The VMCS also creates a strict division between **configured policy** and **exit-time evidence**. Execution controls say what should exit. Exit information says what actually happened. Defensive analysis needs both. A suspicious hypervisor may keep a small configured intercept set, while runtime behavior still leaks through exit timing, mapping changes, and emulation quality.

##### Intel VMX instruction groups

Intel's SDM separates the VMX instruction set into management, transition, invalidation, and guest-call style operations. That split is worth preserving because each instruction touches a different trust surface.

| Instruction group | Instructions | Manual-level role | Defensive reading |
|---|---|---|---|
| Enter/leave VMX operation | `VMXON`, `VMXOFF` | Enter or leave VMX operation. `VMXON` uses a VMXON region and is gated by CR4.VMXE plus VMX capability/control MSRs. | A late-launch hypervisor must create per-logical-processor VMXON state and satisfy fixed CR0/CR4 and feature-control constraints. |
| VMCS pointer and lifecycle | `VMPTRLD`, `VMPTRST`, `VMCLEAR` | Select the current VMCS, read the current-VMCS pointer, clear launch state, and make a VMCS inactive. | VMCS lifecycle mistakes create launch/resume failures, stale active VMCS state, or cross-core corruption. |
| VMCS field access | `VMREAD`, `VMWRITE` | Read or write encoded VMCS components. | Field-level spoofing must preserve capability-MSR reserved-bit rules and guest/host consistency checks. |
| Guest entry | `VMLAUNCH`, `VMRESUME` | Perform VM entry using the current VMCS. `VMLAUNCH` is for a clear launch state. `VMRESUME` resumes an already launched VMCS. | Launch/resume failures expose invalid control fields, bad host-state fields, or inconsistent guest state. |
| Hypervisor call path | `VMCALL` | Lets VMX non-root software call into the VMM and normally causes a VM exit. | Legitimate hypervisors may expose paravirtual calls. Stealth designs usually avoid obvious guest-visible call paths. |
| VM function path | `VMFUNC` | Lets non-root software invoke VM functions configured by root software without a VM exit, such as EPTP switching where supported. | EPTP-switching designs can reduce exits but create a feature-consistency and EPTP-list telemetry surface. |
| EPT/VPID invalidation | `INVEPT`, `INVVPID` | Invalidate translations derived from EPT or tagged by VPID. | Correct split-view or remap logic needs matching invalidation. Stale views and over-flushing are both detectable failure modes. |

VMX instructions report success or failure through flags and, for valid current-VMCS cases, the VM-instruction error field. Operationally, a correct implementation needs more than a raw VMX instruction path. It must handle `VMfailInvalid`, `VMfailValid`, and VM-entry failure classes cleanly.

The invariant is instruction-state pairing. Every VMX instruction conclusion needs the instruction, the logical processor, the current VMCS state, the capability basis, the success/failure carrier, and the next lifecycle state. The simple check is to keep the same instruction trace but move it to a different logical processor, clear the current VMCS, change launch state, or replace the capability MSR tuple. If the conclusion still says the same thing, it is treating a VMX mnemonic as proof rather than a consumed architectural transition.

##### Intel VMCS field detail

The Intel VMCS is field-encoded, not a C structure with a stable public layout. For analysis, classify fields by processor use, capability dependency, width, access class, and transition epoch.

| VMCS field family | Representative fields | What the processor uses it for | Anti-cheat relevance |
|---|---|---|---|
| Guest control state | guest CR0/CR3/CR4, DR7, IA32_EFER, PDPTEs where relevant | Defines the guest execution and paging environment loaded on VM entry and updated on VM exit. | Bad values crash Windows or create impossible combinations such as unsupported long-mode or paging states. |
| Guest descriptor state | guest CS/SS/DS/ES/FS/GS/TR/LDTR selectors, bases, limits, access rights, GDTR/IDTR | Reconstructs segmentation, task, and descriptor-table state. | Segment/access-right mistakes are a common source of subtle VM-entry failures and emulation artifacts. |
| Guest event state | guest RIP/RSP/RFLAGS, activity state, interruptibility state, pending debug exceptions, VMCS link pointer | Controls where the guest resumes and whether events can be delivered. | Hidden single-step, NMI-window, interrupt-window, and debug behavior can leak if this state is inconsistent. |
| Host state | host CR0/CR3/CR4, host RIP/RSP, host selectors, host MSRs such as SYSENTER/EFER/perf/CET where enabled | Defines the machine state the CPU loads during a VM exit. | A malformed host state usually fails loudly. Partial mistakes show up as NMI/interrupt instability. |
| Pin-based execution controls | external-interrupt exiting, NMI exiting, virtual NMIs, posted interrupts where supported | Handles asynchronous event routing. | Overly broad interrupt/NMI exiting adds latency. Too little routing breaks defensive probes and interrupt semantics. |
| Primary processor controls | HLT, INVLPG, MWAIT, RDTSC, CR3 load/store, MOV-DR, I/O bitmaps, MSR bitmaps, MTF, PAUSE exiting | Handles common synchronous instruction and control-register exits. | These are the usual stealth/performance tradeoff knobs. CR3, RDTSC, MSR, and debug exits are especially timing-visible. |
| Secondary/tertiary controls | EPT, VPID, unrestricted guest, RDTSCP, INVPCID, VMFUNC, #VE, PML, sub-page permissions, HLAT/PASID/speculation controls where supported | Enables modern virtualization and finer translation/control features. | A credible telemetry schema should track capability-dependent fields instead of assuming all Intel systems support the same controls. |
| VM-exit controls | host-address size, acknowledge interrupt on exit, save/load IA32_PAT, IA32_EFER, IA32_PERF_GLOBAL_CTRL, CET/FRED/PKRS-related state where supported | Determines what state is saved or loaded while leaving the guest. | Missing load/save controls cause cross-domain state drift, not obvious byte changes. |
| VM-entry controls | IA-32e guest mode, entry event injection, load debug controls, load IA32_EFER/PAT/perf/CET/PKRS state where supported | Determines how the guest is entered and what event, if any, is injected. | Event-injection mistakes change exception and interrupt ordering, which is observable under probes. |
| Exit information | exit reason, exit qualification, guest linear address, guest physical address, instruction length, interruption info/error code | Describes why the exit occurred and what address/instruction was involved. | Defensive classification should use reason plus qualification, not the raw fact that an exit happened. |

The Intel reserved-bit rule is not cosmetic. Many VMX control fields have allowed-0 and allowed-1 masks reported through capability MSRs, so a control-field conclusion needs the source CPU, capability tuple, computed legal mask, dependency controls, and VM-entry result before it becomes portable.

VMCS field analysis should keep the field encoding, width class, access type, dependency control, owning VMCS pointer, logical processor, raw value, decoded value, and source epoch together. This prevents two subtle errors: using a copied software structure after `VMPTRLD` selected a different current VMCS, and interpreting a decoded field without the capability bit that makes the field meaningful. The cross-check is wrong-width replay: decode the same raw slot as a control, guest-state, host-state, or read-only field and verify that only the legal encoding supports the conclusion.

##### Intel VM-entry, VM-instruction, and VMX-abort details

VMX transition failure is evidence, not only a bring-up bug. Intel separates instruction failure from VM-entry failure, ordinary VM-exit payload, and catastrophic VMX-abort state. A broad sentence such as "VM entry failed" is too weak unless it names the failure class, the field owner, and the information source. A broad sentence such as "VM-exit failed" is usually worse: there is no routine VM-exit failure class that mirrors VM-entry failure. If a VM-exit cannot complete as a coherent transition, the analysis should describe the actual evidence, such as malformed host-state load risk, missing exit-information payload, VMX-abort indicator, reset/shutdown behavior, or crash context.

| Failure surface | Manual-level source | Common broken implementation | Data to retain | Maximum conclusion |
|---|---|---|---|---|
| VMX instruction failure | `VMfailInvalid`, `VMfailValid`, `CF`, `ZF`, current-VMCS validity, VM-instruction error field | stale current VMCS pointer, wrong `VMCLEAR`/`VMPTRLD` lifecycle, `VMLAUNCH` after launch state, `VMRESUME` before launch state, unsupported VMX operation state | instruction, flags, VMCS pointer state, VM-instruction error, logical processor id, `CR4.VMXE`, `IA32_FEATURE_CONTROL`, VMXON region identity | VMX lifecycle failure |
| VM-entry control validation | pin-based, primary processor-based, secondary or tertiary processor-based, VM-exit, and VM-entry controls; capability-MSR allowed-0/allowed-1 masks | hardcoded control constants, reserved bits set, feature bit assumed from another CPU family, inconsistent dependency such as EPT-dependent control without EPT support | raw control values, capability MSRs, computed legal masks, dependency graph, VM-entry failure metadata | illegal control-state failure |
| VM-entry host-state validation | host CR0/CR3/CR4, host selectors, host RIP/RSP, host MSR-load state, fixed-bit and canonical-address requirements | noncanonical host pointer, bad selector, CR fixed-bit violation, host MSR list that does not match enabled controls | host-state fields, CR fixed-bit compliance data, host MSR list address/count, enabled exit controls, failure qualification where available | host-state invalidity |
| VM-entry guest-state validation | guest CR0/CR3/CR4, segment/access-right fields, activity state, interruptibility state, pending debug exceptions, guest IA32_EFER/PAT/debug/CET/FRED/PKRS state where supported | impossible long-mode or paging combination, invalid descriptor state, stale interruptibility, event injection incompatible with guest state | guest-state fields, event-injection fields, interruptibility and activity state, pending-debug state, PDPTE or paging-mode evidence, failure qualification where available | guest-state invalidity |
| VM-entry MSR-load failure | VM-entry MSR-load address/count and 16-byte MSR entries; WRMSR-equivalent validity checks; entry failure qualification | stale MSR-load list, unsupported MSR index, reserved bits in MSR value, EFER/PAT/perf/CET/PKRS state inconsistent with active controls | list address/count, failing entry index, MSR/value pair, control bit that requested the load, entry-failure metadata | entry-load failure |
| EPT/VPID invalidation failure | `INVEPT`, `INVVPID`, EPTP, VPID, invalidation type, EPT/VPID capability bits | remap or split view without matching invalidation, unsupported invalidation type, over-flush hiding stale-state evidence | invalidation instruction, type, operand descriptor, EPTP/VPID, old/new leaf, affected core set, resume epoch | stale or over-flushed translation risk |
| exit-information classification | exit reason, exit qualification, guest-linear address, guest-physical address, instruction information/length, interruption information, IDT-vectoring information | reducing an event to RIP plus reason, losing GLA-valid and page-walk context, mixing event-delivery exits with final memory access exits | full exit payload, GLA-valid and GPA fields, page-walk versus final-page label, event-delivery state, handler decision | classified VM-exit event |
| VMX-abort or exit-transition catastrophe | VMCS abort indicator, VMXON/current-VMCS state, host-state load context, reset or crash evidence | treating an unrecoverable transition as an ordinary exit reason, or treating a reset as stealth | VMCS abort indicator, current VMCS identity, logical processor, host-state fields if retained, machine-check or crash artifact, first coherent post-reset epoch | catastrophic lifecycle evidence |

The strongest Intel conclusion is only as strong as the last legal transition. If the analysis cannot replay the derivation from capability MSRs to legal control fields, from legal control fields to VM-entry, and from VM-entry to exit payload, the conclusion should stop at lab-local failure or mechanism suspicion.

#### 2.3 AMD VMCB Layout in Practice

AMD SVM uses the VMCB as the consumed contract for `VMRUN`, not merely as a memory-resident struct. The consumed-contract invariant splits the control area from the save-state area and then asks which fields were consumed on entry, which fields were written back on exit, which fields were cached or skipped through clean-bit behavior, and which permission-map or nested-root pages lived outside the VMCB body. Without that epoch binding, a VMCB dump is a configuration candidate, not proof that hardware consumed the state.

| VMCB area | Examples | Why it matters |
|---|---|---|
| Control area | intercept vectors, IOPM/MSRPM bases, TSC offset, ASID, TLB control, virtual interrupt controls, nested paging enable and nCR3 | Defines which events exit and how guest memory is translated |
| Save-state area | guest general execution state, segment state, control registers, descriptor tables, EFER, RIP/RSP/RFLAGS | Defines the guest CPU state saved/restored by VMRUN and exits |

Important SVM-specific concepts:

- **Intercept vectors:** SVM exposes intercept controls for control-register access, debug-register access, exceptions, and selected instructions. The strategic question is the same as VMX: which events are worth paying for?
- **MSRPM and IOPM:** MSR and I/O permission maps let the hypervisor avoid broad exits.
- **ASID:** Address-space identifiers tag TLB translations. They reduce flush cost but require careful reuse and invalidation.
- **TLB_CONTROL:** Gives the hypervisor a way to request targeted or broader TLB effects on VMRUN. Poor use can create either stale translations or excessive flush overhead.
- **Nested paging enable and nCR3:** When nested paging is active, nCR3 points to the nested page tables that translate guest physical to system physical addresses.
- **Virtual interrupt controls:** Interrupt shadowing, virtual interrupt delivery, and APIC-related behavior are latency-sensitive and easy to perturb.
- **Clean bits:** On supported processors, clean-bit style mechanisms let the CPU skip reloading unchanged VMCB state. This is a performance feature, but it also means frequent control-state churn has a measurable cost.

The practical invariant is that the VMCB is not one object with one clock. It is a set of contracts with different owners: intercept policy, permission-map physical pages, ASID and TLB-control state, nested root, virtual interrupt state, save-state bytes, clean-bit currentness, and exit-status writeback. The attacker leverage is that a thin SVM layer can touch only a few groups and still observe useful events. The defender observable is cross-group contradiction: an exit stream that does not match the intercept epoch, an NPF tuple that does not match `N_CR3`, an interrupt outcome that does not match virtual interrupt state, or a guest behavior that follows a cached save-state group rather than the VMCB bytes in memory. The sanity check is group isolation: perturb one VMCB group, one clean bit, and one ASID/TLB epoch independently, then reject any sentence that still treats the VMCB as a single timeless state object.

##### AMD SVM instruction groups

AMD exposes a smaller but very explicit SVM instruction set. The VMCB remains the central control object, but several instructions exist only to manage world switch, interrupt gating, and address-translation invalidation. The invariant is role conservation: `VMRUN`, `VMLOAD`/`VMSAVE`, `STGI`/`CLGI`, and `INVLPGA` do not prove the same authority and should not be merged into one generic "SVM activity" label.

| Instruction | Manual-level role | Defensive reading |
|---|---|---|
| `VMRUN` | Enters guest mode using the VMCB physical address in `RAX`. Host state is saved in the host save area and guest state comes from the VMCB. | Treat this as the SVM world-switch boundary. Invalid VMCB state causes `#VMEXIT(VMEXIT_INVALID)` instead of a normal guest run. |
| `VMLOAD` | Loads selected processor state from the VMCB, commonly used around world-switch setup. | State that lives outside normal GPR/page-table views can still change at the virtualization boundary. |
| `VMSAVE` | Saves selected processor state into the VMCB. | Misordered save/load logic creates state drift across exits and cores. |
| `VMMCALL` | Guest-to-hypervisor call mechanism when intercepted. | Similar to `VMCALL`. It is usually policy-visible and not a stealthy path. |
| `STGI` / `CLGI` | Set or clear the global interrupt flag used by SVM interrupt control. | Interrupt gating mistakes affect latency and NMI/interrupt observability. |
| `INVLPGA` | Invalidates TLB entries by virtual address and ASID. | Important for ASID-tagged stale-translation control. |
| `SKINIT` | Secure initialization path tied to measured launch concepts. | More relevant to platform trust and boot-chain integrity than to ordinary in-game VMI. |

AMD also defines many instruction intercepts in the VMCB, including `RDTSC`, `RDPMC`, `PAUSE`, `HLT`, `INVLPG`, `INVLPGA`, `VMRUN`, `VMLOAD`, `VMSAVE`, `VMMCALL`, `STGI`, `CLGI`, `SKINIT`, `RDTSCP`, `WBINVD`, `MONITOR/MWAIT`, `XSETBV`, `INVPCID`, `INVLPGB`, and related TLB synchronization operations where supported. This breadth matters because an SVM design can be noisy even without second-stage page faults if it intercepts hot instruction families.

The source vocabulary needs one more split: dedicated SVM instructions are not the same thing as interceptable instruction families. The former move ownership across the host/guest boundary; the latter are policy decisions encoded in VMCB intercept fields. A analysis that calls every intercepted instruction an "SVM instruction" loses the authority boundary.

The invariant is role conservation. `VMRUN` is a world-switch authority, `VMLOAD` and `VMSAVE` are state-transfer authorities, `STGI` and `CLGI` are interrupt-gating authorities, `INVLPGA` is an address-translation invalidation authority, and an intercept bit is a policy authority. The attacker leverage is selective: a thin hypervisor wants the smallest policy surface that still gives CR3, timer, page-fault, or translation visibility. The defender observable is not the instruction name alone; it is the mismatch between instruction role, VMCB field churn, exit code, timing distribution, and the state that changed afterward.

The data path for this section is control metadata, not game bytes: VMCB physical address, host save area, guest save-state area, intercept bits, ASID, invalidation operand, and exit code. The layer boundary stops at SVM control-plane behavior until another section joins it to process memory, game semantics, or delivery evidence.

Dominant failure modes are broad hot-instruction interception, stale ASID-tagged translations after incomplete `INVLPGA` or `TLB_CONTROL` use, interrupt-window drift after `CLGI`/`STGI` mistakes, hidden state drift from misordered `VMLOAD`/`VMSAVE`, and measured-launch trust inferred from a bare `SKINIT` mention without a boot-chain and TPM evidence bridge. The sanity check removes one role at a time: allow the hot instruction, keep `VMRUN` but freeze the VMCB intercept field, replace `INVLPGA` with a broader flush, replay with a different ASID, or compare NMI/window timing with and without interrupt gating. If the same anti-cheat conclusion survives all variants, the evidence is not role-specific enough.

##### AMD VMCB control-area detail

The AMD APM defines the VMCB as a 4 KB page with a 1024-byte control area followed by a save-state area. The control area starts at offset zero, and unused bytes are reserved and should be zeroed. Several fields are especially important for game-security analysis, but the field table is not the evidence by itself: a control-area conclusion needs field value, clean-bit currentness, `VMRUN` consumption, exit payload or guest-visible effect, and the first missing bridge.

| VMCB control-area field | Manual-level role | Anti-cheat relevance |
|---|---|---|
| Intercept vectors 0-2 | CR read/write intercepts, DR read/write intercepts, exception-vector intercepts. | CR3 tracking, debug-register deception, and exception instrumentation all live here. |
| Intercept vector 3+ | Physical/virtual interrupt intercepts, descriptor-table reads/writes, `RDTSC`, `RDPMC`, `CPUID`, `INVLPG`, `HLT`, `VMMCALL`, `VMRUN`, `VMLOAD`, `VMSAVE`, `STGI`, `CLGI`, `SKINIT`, and other instruction intercepts. | Lets an SVM hypervisor build a very selective policy, but hot intercepts produce timing artifacts. |
| `IOPM_BASE_PA` | Physical base of the I/O permission map. | Port-level filtering avoids unconditional I/O exits but requires correct map alignment and sizing. |
| `MSRPM_BASE_PA` | Physical base of the MSR permission map. | MSR-level filtering is central to timer, APIC, EFER, debug, and security-product coherence. |
| `TSC_OFFSET` / TSC ratio where supported | Adjusts guest-visible TSC behavior. | Timer shaping must remain consistent with QPC, HPET, APIC, scheduler, and network timing. |
| `ASID` | Tags guest address-space translations. | Reduces flush cost but makes ASID reuse and stale mapping bugs visible. |
| `TLB_CONTROL` | Requests flush behavior around `VMRUN`. | Under-flushing leaks stale views. Over-flushing creates measurable performance loss. |
| Virtual interrupt fields | `V_INTR_VECTOR`, priority, masking, TPR-related controls, virtual NMI fields where supported. | Interrupt virtualization is latency-sensitive and can disturb input, DPCs, and frame pacing. |
| `EVENTINJ` and related fields | Injects exceptions or interrupts into the guest. | Incorrect event injection changes exception ordering and is probeable. |
| `NP_ENABLE` and `N_CR3` | Enables nested paging and selects the nested translation root. | AMD-side counterpart to Intel EPTP and a key field for split-view and second-stage translation analysis. |
| Pause filter fields | Pause filter threshold/count where supported. | Helps avoid excessive PAUSE-loop exits. Wrong values create either spin-loop overhead or missed signals. |
| VMCB clean field | Indicates which state groups have not changed and can be cached. | If the hypervisor modifies VMCB state without clearing the matching clean bit, behavior can become undefined or core-dependent. |

The control area should be treated as a transition contract, not as a static field table. A field is meaningful only if the `VMRUN` epoch consumed it, the clean-bit state allowed the CPU or implementation to see the change, and the resulting exit or guest behavior preserved the same owner story.

The evidence bridge is `VMRUN` consumption plus the resulting native exit or guest behavior. The attacker leverage is selective control-state mutation with stale clean-bit or ASID assumptions. The defender observable is a mismatch between the VMCB field story, the clean-bit story, the exit payload, and the guest-visible result.

##### AMD VMCB save-state detail

The VMCB save-state area contains the guest architectural state that `VMRUN` loads and `#VMEXIT` updates. The shallow statement is "the VMCB saves registers"; the precise boundary is which guest state was loaded, which state was written back, which state was cached or protected by SEV-family modes, and which observer was allowed to see it. AMD's manual calls out several details that matter in practice:

| Save-state area category | Examples | Practical meaning |
|---|---|---|
| Segment state | selector, base, limit, attributes for CS/SS/DS/ES/FS/GS, LDTR, TR | AMD stores expanded segment state. Attribute canonicalization and NULL-segment handling must match guest mode. |
| Control state | CR0/CR2/CR3/CR4, EFER, RFLAGS, RIP/RSP, CPL | Illegal combinations cause invalid exits. Long-mode and paging combinations are especially sensitive. |
| Descriptor-table state | GDTR/IDTR base and limit | Incorrect table state breaks exception, interrupt, and system-call behavior. |
| Debug state | DR6/DR7 and related state | Debug state is a high-value anti-probe surface. |
| System-call and MSR-adjacent state | STAR/LSTAR/CSTAR/SFMASK, kernel GS base, SYSENTER fields where supported | Wrong state causes subtle syscall-path or WoW64/compatibility failures. |
| Extended/security state | CET, XCR0, SEV/SEV-ES/SNP-related state where supported | Modern AMD systems may expose more state than older SVM summaries assume. |

The source-contract checkpoint is stricter than "the VMCB saves registers." `VMRUN` uses the system-physical VMCB address supplied through `RAX`, saves only the host subset required for return through the host save area, loads guest state and control from the VMCB, and relies on `VMLOAD`, `VMSAVE`, and software-managed state paths for additional state when needed. AMD's SEV-ES material makes the boundary sharper: legacy AMD-V exposes more register state to hypervisor-managed save paths, while SEV-ES encrypts and integrity-protects the guest save-state area and moves selected emulation disclosure into the guest-controlled #VC/GHCB path. Therefore a save-state conclusion must name the SVM generation and protection mode before it says what the hypervisor can observe or modify.

The invariant is save-state ownership conservation. A VMCB memory snapshot is not automatically the state the CPU loaded, and a post-exit VMCB field is not automatically the state that existed at the faulting instruction. The authority bridge has to connect VMCB physical identity, `VMRUN` epoch, clean-bit state, load/save path, and a guest-visible comparator. The control owner is split between the VMM-maintained VMCB fields, processor state caching, SEV-ES/SNP protection state where enabled, and any guest-mediated disclosure path. The timing model has at least three windows: pre-`VMRUN` bytes, state actually consumed during entry, and state written back or disclosed after exit.

The attacker leverage is stealth consistency rather than a single magic register: a thin hypervisor must keep segment, CR, EFER, syscall, debug, interruptibility, and extended/security state plausible while minimizing exits and clean-bit churn. The defender observable is cross-owner drift: guest-visible syscall or exception behavior that disagrees with VMCB snapshots, per-core differences after VMCB reuse, clean-bit mismatches after field mutation, #VC/GHCB disclosure that does not match expected hypervisor visibility, or invalid-exit evidence after a supposedly valid state transition.

The AMD-specific risk is more than "wrong intercept." Stale cached state is just as important. The APM explicitly describes VMCB state caching and clean-bit rules. A hypervisor that moves a VMCB between cores, changes a VMCB physical page, or modifies guest state without clearing the correct clean bits can produce stale or processor-dependent behavior. Dominant failure modes are pre/post-exit state collapse, VMLOAD/VMSAVE omission, XRSTOR or XState drift, clean-bit stale groups, host-save-area overinterpretation, SEV-ES save-area visibility overstatement, GHCB disclosure understatement, and treating one core's VMCB observation as system-wide state. The sanity check changes one owner at a time: keep the VMCB bytes fixed but change clean bits, keep clean bits fixed but change the physical VMCB page, replay on another core, compare guest `CPUID`/syscall/exception behavior, remove a `VMLOAD` or `XRSTOR` step in a lab trace, or switch the model between legacy SVM and SEV-ES-style disclosure. If the same sentence still names exact guest state, it is reading too much from the VMCB snapshot.

##### AMD SVM run/exit lifecycle

On AMD, the VMCB is not just a saved-register block. It is the contract loaded by `VMRUN` and updated on `#VMEXIT`; the control area, save-state area, ASID, `N_CR3`, intercept vectors, clean bits, and `TLB_CONTROL` each carry a different currentness question.

```text
host prepares VMCB control area and save-state area
  -> RAX points to the VMCB system-physical address
  -> VMRUN saves selected host state and loads guest state
  -> guest runs with intercept, ASID, TSC, interrupt, and NPT policy from the VMCB
  -> an intercept, exception, nested page fault, or invalid state causes #VMEXIT
  -> VMCB exit fields describe the reason and selected event-specific details
  -> host updates control state, TLB policy, and guest state before the next VMRUN
```

Several details are AMD-specific enough that Intel terms can mislead analysis because VMCB, ASID, NPT, and clean-bit evidence follow different state carriers:

| SVM mechanism | AMD implementation detail | Analysis consequence |
|---|---|---|
| VMCB physical address in `RAX` | `VMRUN` uses the system-physical VMCB pointer from `RAX`. | VMCB physical-page identity, alignment, and reuse matter. Moving a VMCB across cores is not only a software bookkeeping issue. |
| host save area | Host state is saved separately from the guest VMCB state. | Broken save/load sequencing can look like random guest-state corruption or per-core drift. |
| intercept vectors | Intercept policy lives in bitfields for exceptions, CR/DR access, selected instructions, interrupts, and I/O/MSR maps. | A sample can be noisy without NPT faults if it intercepts hot instruction families such as `RDTSC`, `CPUID`, or `INVLPG`. |
| `EXITCODE` | Identifies the exit class, such as instruction intercept, exception intercept, invalid VMCB, or `VMEXIT_NPF`. | Analyst tooling should preserve AMD exit code names instead of translating every event into Intel-style labels. |
| `EXITINFO1` and `EXITINFO2` | Hold event-specific details; for `VMEXIT_NPF`, `EXITINFO1` is the fault error code and `EXITINFO2` is the guest physical address. | These fields are the AMD counterpart to Intel EPT violation qualification plus GPA reporting, but the bit layout is not identical. |
| `EXITINTINFO` | Describes event-injection state when exits happen during event delivery. | Important for distinguishing a clean intercept from nested exception-delivery edge cases. |
| clean bits | Tell hardware which VMCB state groups can be treated as unchanged. | If control fields change without dirtying the right group, behavior can become stale or processor-dependent. |
| virtual interrupt controls | SVM has its own virtual interrupt and interrupt-shadow machinery. | Interrupt mistakes create latency and ordering artifacts that are not explained by NPT alone. |

The key defensive point is that AMD analysis has to preserve VMCB-level context. A normalized "hypervisor exit" view should still retain SVM-native `EXITCODE`, `EXITINFO1`, `EXITINFO2`, ASID, TLB-control action, clean-bit state, and `N_CR3`.

The attacker leverage is lifecycle compression: making a configured VMCB look like the consumed state and making the repaired re-entry state look like the fault-time state. The defender observable is the mismatch between AMD-native payload, clean-bit epoch, ASID/TLB epoch, and guest behavior.

##### AMD VMCB failure and invalidation details

AMD failures should remain in SVM vocabulary until the normalization layer is ready. `VMRUN` consumes the system-physical VMCB address in `RAX`; VMCB state caching uses the physical VMCB address as part of the cache identity; ASID, `TLB_CONTROL`, clean bits, and nested-paging fields are evidence, not implementation trivia. Collapsing `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `EXITINTINFO`, `EVENTINJ`, `ASID`, and `N_CR3` into a generic "VM exit" view destroys the context needed to distinguish an intercept, invalid state, stale cache, and nested page fault.

| Failure surface | Manual-level source | Common broken implementation | Data to retain | Maximum conclusion |
|---|---|---|---|---|
| invalid VMCB on `VMRUN` | `VMRUN`, `RAX` system-physical VMCB address, VMCB control/save-state legality, host-save relation | stale, misaligned, reused, or partially initialized VMCB; save-state incompatible with guest mode; host-save sequencing drift | `RAX` VMCB physical address, core id, VMCB physical-page identity, control/save-state snapshot, host-save relation, invalid-exit `EXITCODE` | VMCB validity failure |
| intercept-map misclassification | intercept vectors, exception intercepts, instruction intercepts, IOPM/MSRPM physical bases | translating every SVM exit to an Intel-style reason, losing whether the source was an exception, instruction, I/O, MSR, or interrupt intercept | raw intercept bit, decoded intercept family, IOPM/MSRPM PA, guest RIP/NRIP, decode-assist fields where valid | SVM intercept event |
| NPF payload ambiguity | `VMEXIT_NPF`, `EXITINFO1`, `EXITINFO2`, `N_CR3`, ASID, nested page-table leaf | confusing guest `#PF` with NPF, final-page access with nested page-walk access, or permission fault with malformed translation | `EXITINFO1` bits, faulting GPA from `EXITINFO2`, nested leaf chain, guest PTE role, ASID, `N_CR3`, TLB state | NPF classification |
| clean-bit stale state | VMCB Clean field, cached VMCB state groups, physical VMCB identity | modifying control/save-state fields without clearing the matching clean bit, migrating a VMCB while assuming ASID alone identifies cached state | old/new field value, clean mask before `VMRUN`, VMCB physical page, core migration, `VMRUN` epoch | stale VMCB-state risk |
| TLB and ASID invalidation | `TLB_CONTROL`, `INVLPGA`, `INVLPGB`, `TLBSYNC`, ASID lifecycle, `N_CR3` | ASID reuse without flush, under-flushing after NPT mutation, unsupported broadcast invalidation assumption, broad flush that hides stale-view root cause | invalidation action, target ASID/address/range, `N_CR3`, old/new nested leaf, affected core set, feature-gating CPUID state | stale or over-flushed translation risk |
| event-injection continuity | `EVENTINJ`, `EXITINTINFO`, virtual interrupt controls, interrupt shadow, next RIP/NRIP | double-injecting an exception, losing an interrupted event, treating an event-delivery edge as a clean NPF or instruction intercept | injected vector/type/error code, intercept source, `EXITINTINFO`, virtual interrupt state, interrupt-shadow state, next RIP/NRIP | event-delivery inconsistency |
| AVIC or virtual-interrupt edge | virtual interrupt fields, APIC/AVIC ownership, virtual TPR/priority state where supported | explaining interrupt timing solely as NPT behavior, ignoring APIC ownership and virtual interrupt delivery | virtual interrupt state, APIC/AVIC owner, host/guest event timing, posted or virtual interrupt metadata | interrupt-fabric inconsistency |

An AMD analysis that cannot name ASID, `N_CR3`, clean-bit state, TLB action, and `EXITCODE`/`EXITINFO` payload should not move beyond SVM mechanism suspicion. The normalization layer may map AMD and Intel into a common event model, but only after the vendor-native context remains replayable.

SVM has the same broad defensive story as VMX, but the native carriers, cache rules, exit payloads, and invalidation verbs differ. The defender should not hardcode Intel-only thinking or translate AMD evidence into VMCS/EPT vocabulary before the SVM context is replayable. A credible telemetry schema keeps Intel VMX and AMD SVM paths separate until the normalized layer can prove which owner, transition, payload, and narrowed conclusion survived.

#### 2.4 VM-Exit Lifecycle

A VM-exit is not free. The CPU leaves guest execution, loads host state, runs the hypervisor handler, possibly emulates an instruction or event, then resumes the guest. The cost is not only cycles; it is also the architectural obligation to preserve event priority, interruption state, debug state, instruction side effects, translation visibility, and clock continuity.

Conceptual lifecycle:

```text
guest executes instruction or memory access
  -> CPU checks VMCS/VMCB controls
  -> event matches an intercept policy
  -> CPU saves exit information
  -> hypervisor handler runs
  -> handler emulates, denies, logs, redirects, or modifies state
  -> guest resumes
```

A high-quality exit model needs four connected views, not one log line. The views preserve why the processor left the guest, what native payload was produced, what the handler changed, and why re-entry was legal; losing any one view turns an exit into a label instead of a transition:

| View | Owner | What must be preserved | Failure mode |
|---|---|---|---|
| cause view | CPU architecture and VMCS/VMCB controls | native exit reason, qualification, instruction context, event-vectoring state | a generic "exit happened" row is promoted into a typed event |
| payload view | hardware-updated exit fields | GLA/GPA validity, access type, error-code or exitinfo bits, instruction length or decode assist | analyst inference is mistaken for native evidence |
| mutation view | handler policy | register/MSR/page-view/event-injection delta and invalidation scope | the handler changes state without a replayable explanation |
| resumption view | VM-entry or `VMRUN` contract | legal guest state, pending event handling, next RIP/NRIP, timer/interrupt continuity | the guest resumes with impossible or stale state |

The invariant is transition conservation: the event that left the guest, the handler decision, and the state that re-entered the guest must describe the same vCPU epoch. The attacker leverage is selective observability, because a thin layer can choose a small set of exits that expose timing, CR3, page-fault, MSR, CPUID, or second-stage events. The defender observable is conservation failure: exit counts without native payload, payload without target binding, handler mutation without invalidation evidence, or resumption without legal event state. The sanity check is to keep the guest workload constant while varying one owner, such as intercept bitmap, timer load, vCPU placement, or nested-root epoch, and require the exit explanation to move only with the owner it names.

A cheat-oriented design wants exits to be selective because broad interception creates timing, performance, and event-distribution evidence:

1. Identify the game process or relevant address space.
2. Intercept only events that help memory acquisition, stealth, or input control.
3. Avoid hot render, input, network, and scheduler paths.
4. Emulate side effects exactly enough that Windows remains coherent.
5. Keep per-vCPU and global state synchronized.

##### 2.4.1 Exit Context as a State Transition

A VM-exit should be treated as a state transition, not as a callback log. The useful context is what the CPU was doing, why the architecture transferred control, what state became architecturally visible to the host, and what the handler changed before re-entry.

The important boundary is causality. An EPT violation, NPF, MSR intercept, CPUID intercept, I/O intercept, or event-delivery exit can all look like "the hypervisor observed the guest." Stronger wording needs the context to show that the observed event belongs to the target address space, the handler preserved architectural side effects, the re-entry state is legal, and the event joins to a later semantic or behavioral consequence.

| Layer | Native evidence | Analyst question | If missing |
|---|---|---|---|
| source context | vCPU, guest RIP/NRIP, CR3/ASID, CPL, interruptibility, pending vectoring | which execution epoch produced the exit? | `exit_context_unbound` |
| cause payload | Intel exit reason/qualification or AMD exitcode/exitinfo fields | what exact architectural condition transferred control? | `exit_payload_under_specified` |
| target binding | GLA/GPA validity, process root, nested root, access type, instruction bytes | did the event belong to the target game or OS object? | `target_context_unjoined` |
| handler side effect | emulation result, injected event, register/MSR/page-view delta, invalidation scope | what did the handler change before resume? | `handler_effect_unproven` |
| re-entry legality | VM-entry success/failure, VMRUN resume state, pending events, next RIP/NRIP | did the guest resume in an architecturally legal state? | `reentry_legality_unproven` |
| external promotion | memory semantic, render/input path, replay/server consequence | did the low-level event become an advantage or artifact? | `semantic_bridge_missing` |

This framing is especially important for late-launch hypervisors. A live system already has pending interrupts, debug state, timer state, lazy FPU/XState ownership, scheduler state, and partially ordered memory events. If the exit context does not preserve those joins, the strongest safe statement is only "a transition occurred under virtualization," not "the hypervisor correctly observed or controlled the target behavior."

##### 2.4.2 Cost Model and Exit Budget

The exit-budget invariant is not average latency; it is the distribution of work shifted across guest time, host handler time, cache/TLB state, interrupt delivery, and scheduler visibility. The analysis should therefore keep tail latency, cache/TLB disruption, vCPU descheduling, interrupt delay, timer skew, handler lock contention, cross-core rendezvous, and guest-visible jitter together. A low-frequency intercept can still be observable if its epoch aligns with render frames, input sampling, network receive, anti-cheat probes, or scheduler transitions.

| Cost surface | What changes | Why it matters |
|---|---|---|
| direct exit latency | guest stops while host handler runs | tail spikes can correlate with gameplay phases |
| translation disruption | EPT/NPT or guest-paging caches may need invalidation | stale or over-flushed views change timing and correctness |
| interrupt/event continuity | pending event, vectoring state, interrupt shadow, NMI blocking | double injection or lost event creates rare but strong artifacts |
| SMP coordination | one vCPU's view change must be visible to other cores when treated as global | unsynchronized split views produce cross-core disagreement |
| probe interaction | anti-cheat, OS, or game timing probes run through the same CPU fabric | spoofed timers cannot explain all latency sources equally |

The invariant is:

A good analysis rejects averages that hide tail behavior. A cheat-oriented hypervisor can survive a low average exit cost and still leak through p99 frame stalls, input-sampling jitter, network receive delay, or timer-distribution distortion. Conversely, an isolated synthetic benchmark that shows high exit cost does not support a gameplay-impact conclusion unless it is joined to the same workload phase and vCPU/core placement. The conclusion has to stay scoped to the exit class, workload phase, observer, and clock domain that were actually measured.

#### 2.5 Intercept Cost Model

Interception cost is not only "number of exits." Each exit class mutates a different contract: control-flow ordering, timer monotonicity, interrupt latency, page-walk currentness, MSR identity, or exception delivery. A low exit count can still be loud if it touches a high-sensitivity clock or hot page, while a frequent exit can be benign if it is expected for a legitimate nested or VBS-owned path.

The first expert-grade split is **entry cost versus side-effect debt**. Entry cost is the direct transition work: guest pipeline disruption, microarchitectural serialization, host handler execution, and re-entry. Side-effect debt is the evidence that must remain coherent afterward: the emulated instruction result, flags, exception state, interruptibility, TLB/currentness, timebase, and the first independent guest observation after resume. A trace that captures only "exit count" measures the loudest part poorly and misses the part that most often exposes stealth failure.

Use this vector for each intercept family:

```text
intercept_cost_vector =
  direct_transition_cost
  + handler_emulation_debt
  + translation_invalidation_debt
  + timer_and_clock_debt
  + interrupt_delivery_debt
  + scheduler_tail_latency
  + observer_cardinality
  + reentry_validation_debt
```

The terms are not interchangeable. `direct_transition_cost` can be small while `timer_and_clock_debt` is large. `translation_invalidation_debt` can dominate an otherwise rare EPT/NPT fault. `observer_cardinality` grows when the same event is visible to guest code, VMCS/VMCB payload, Hyper-V/TLFS state, ETW or ISR/DPC timing, device DMA paths, GPU timelines, and server replay. A low-cost statement must therefore say which terms were measured, which terms were intentionally out of scope, and which independent observer would disprove the conclusion.

| Intercept class | Common trigger shape | Primary cost axis | State that must be retained | Common overstatement |
|---|---|---|---|---|
| CPUID | feature discovery, anti-VM probe, library initialization | identity coherence | leaf/subleaf, vendor path, hypervisor-present story, TLFS leaves if exposed, per-core consistency | treating one clean leaf as a coherent CPU story |
| RDTSC/RDTSCP | probes, busy loops, frame timing, QPC-related calibration | clock and scheduler coherence | TSC offset/ratio if used, reference-time relation, core migration, power state, wall-clock or server tick comparator | treating a local delta threshold as proof of hostile virtualization |
| CR3/CR access | context switches, address-space root changes, paging-mode probes | event volume and process-root currentness | old/new CR value, PCID or ASID context, thread/vCPU epoch, CR3-target policy, later address-space join | treating a CR3 sample as a game-process memory proof |
| MSR access | syscall path, APIC, TSC, EFER, PAT, debug/perf, synthetic MSRs | emulation correctness | MSR number, read/write, value, dependency controls, family behavior, failure path | treating a spoofed value as proof that dependent behavior is coherent |
| Debug and exception events | #DB, #BP, #PF, #NM, #VE, single-step, breakpoint-style probes | event ordering | vector, error code, pending debug state, IDT-vectoring or event-injection state, next guest event | treating a delivered value as proof that exception history was legal |
| EPT/NPT violation | watched page, execute trap, write suppression, view switch | translation currentness | access type, GLA/GPA validity, EPTP or `N_CR3`, VPID/ASID, invalidation action, re-arm path | treating a second-stage fault as process/object authority |
| Interrupt/APIC/SynIC events | timer, IPI, EOI, posted interrupt, synthetic timer | latency and delivery ordering | APIC/AVIC/APICv/SynIC owner, pending/service state, vector, EOI path, timer source, ISR/DPC witness | treating interrupt delay as a cheat verdict without platform-owner closure |
| I/O port and MMIO exits | device probe, legacy port, mapped register, doorbell-like path | device ordering | port or GPA, device owner, posted write behavior, memory type, interrupt/fence relation | treating device-side ordering as CPU process-memory evidence |

The second split is **semantic value versus intercept temperature**. A hot intercept is not automatically useful, and a useful intercept is not automatically hot. For example, all-CR3 exiting can produce a large volume of exits but still fail to identify the correct process if the analysis loses thread, PCID, and map-transition context. Conversely, a rare MSR or CPUID intercept can be highly visible if the emulation creates a contradictory Hyper-V, VBS, CET, XState, or timer story. The useful question is not "how many exits occurred?" It is "which layer did this exit help, and which layer did it disturb?"

| Workload phase | Intercept-pressure risk | Why it matters | Safer scope boundary before joins |
|---|---|---|---|
| boot or hypervisor bring-up | VMX/SVM lifecycle, capability, MSR, interrupt setup | many legitimate platform transitions also happen here | platform transition candidate |
| launcher and anti-cheat initialization | CPUID/MSR/timer probes, driver and VBS checks | benign security software can create the same families | platform-coherence candidate |
| map load or level transition | CR3, paging, allocation, file and memory pressure | object roots and address spaces churn quickly | address-space churn candidate |
| active match frame loop | hot pages, timers, input, GPU and interrupt pressure | small added latency can become phase-coupled | workload-correlated pressure candidate |
| spectate, replay, or capture | presentation and behavior observers dominate | local intercept evidence may be absent or stale | delivery or behavior candidate |
| explicit probe window | timing, debug, exception, and CPUID probes | the probe itself changes the workload | probe-conditioned artifact |

This table is also the false-positive guard. A Windows endpoint can legitimately expose Hyper-V, VBS, HVCI, WSL2, debugger, nested virtualization, GPU virtualization, and synthetic interrupt/timer behavior. A high-quality intercept-cost paragraph must preserve the platform owner before it names a hostile owner. The correct narrowing for an unexplained signal is often `platform_owner_unresolved`, not "cheat hypervisor."

The defensible cost model is phase-coupled and replayable:

The sanity check has three controls. First, keep the same workload and remove one intercept family at a time in a benign lab VMM or trace harness; only conclusions owned by that family should move. Second, keep the intercept family but change the workload phase; a process-memory or game-object conclusion should not survive if the only stable evidence is phase-correlated pressure. Third, keep the local trace but add an independent observer, such as Hyper-V/TLFS state where present, ETW timing, a replay/server tick, a device path, or a second core. If the conclusion changes when a stronger observer is added, the original sentence was an intercept-pressure candidate, not a mechanism proof.

For hypervisor-based cheat analysis, the operationally successful design is usually narrow and lazy because each extra intercept expands the observable state and cross-check surface. That is not implementation advice; it is a technical boundary. A low-observable helper still has to account for every intercepted instruction, fault, timer, interrupt, invalidation, and re-entry obligation it selected. Until those debts are paid, the strongest safe wording is that the trace shows bounded intercept pressure under a named workload phase.

#### 2.6 VM-Entry and VM-Exit as a Correctness Contract

VM-entry and VM-exit are often described as transitions, but for analysis they are better treated as a contract. The processor does not just jump to a handler. It validates control fields, loads or saves selected architectural state, saves exit information, applies event-blocking rules, and then expects the VMM to return with a coherent next guest state.

| Contract stage | Intel VMX framing | AMD SVM framing | Analysis consequence |
|---|---|---|---|
| capability discovery | CPUID, VMX capability MSRs, allowed-0/allowed-1 control masks, EPT/VPID capability MSR | CPUID SVM/NPT feature bits, VMCB capability details, ASID and nested paging support | hardcoded control fields are brittle; capability state is part of the evidence |
| launch preconditions | CR0/CR4 fixed bits, IA32_FEATURE_CONTROL, VMXON region, current VMCS, VM-entry checks | EFER.SVME, VMCB physical address in `RAX`, valid control/save-state fields | failures here are not stealth. They indicate broken ownership or incompatible platform state |
| guest state load | VM-entry loads guest CRs, RIP/RSP/RFLAGS, segments, MSR-selected state, event injection state | `VMRUN` loads VMCB save-state and control policy, then executes guest mode | a believable VMM must preserve illegal-state checks and mode-specific corner cases |
| exit dispatch | exit reason, qualification, interruption info, instruction length, GPA/GLA where applicable | `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `EXITINTINFO`, updated save-state area | a normalized trace must preserve vendor-native fields before abstracting them |
| emulation decision | handler may emulate, reflect, deny, adjust controls, or modify memory mappings | handler updates VMCB state, TLB control, ASID/NPT state, event injection | the difficult part is side effects: flags, pending events, TLB state, time, and interrupts |
| re-entry | `VMLAUNCH` or `VMRESUME` re-enters with VM-entry checks and optional injected event | next `VMRUN` re-enters with VMCB state and clean-bit behavior | a bad handler often fails one exit later, not at the point where the mistake was made |

At this level, this means a VM-exit log should not be reduced to "exit reason + RIP." The transition context needs the active vCPU, guest mode, CR3/PCID or ASID, interruptibility, pending event state, exit qualification, GLA/GPA validity, active EPTP or `N_CR3`, and the re-entry action to stay together. Otherwise the log can prove only that an exit row existed, not that the handler preserved a legal transition.

The invariant is transition-state conservation. Every exit must leave enough evidence to replay what hardware saved, what the handler changed, what event was pending, and why the next entry was legal. The attacker leverage is selective incompleteness: retaining the convenient exit reason while dropping the state that would expose an illegal reinjection, stale control cache, wrong CR3/ASID, or impossible interruptibility transition. The defender observable is a transition trace that either replays or names the missing owner. The sanity check is one-exit-later replay: start from the saved state, apply only the captured handler mutations, run the documented entry checks, and verify that the next exit or guest instruction is possible under the described state.

When a VM-exit is used to explain a stable VMM, hidden hook, memory view, or game effect, both halves of the transition have to stay connected: the exit had to be legal to take, and the next entry had to be legal to resume.

Transition contract failure classes:

| Failure class | Missing bridge | Narrowing |
|---|---|---|
| exit without route owner | exit reason exists, but the control bit or nested owner that routed it is unknown | `exit_payload_only` |
| handler without side-effect replay | emulation result is logged, but flags, pending events, time, TLB, or MSR/CR effects are absent | `handler_effect_unclosed` |
| entry legality unpaid | resume was attempted, but entry checks, host state, guest state, or MSR-load legality are not replayed | `resume_attempt_only` |
| clean-state ambiguity | VMCS/VMCB cached or clean fields may not match memory image | `control_currentness_unproven` |
| nested owner ambiguity | L1-visible event, L0 shadow event, and TLFS/enlightened event are collapsed | `nested_transition_owner_uncertain` |
| witness gap | no first post-entry instruction, next exit, or independent observer exists | `transition_not_closed` |

The sanity check is contract half-removal. Keep the same exit payload but remove handler side effects; keep handler effects but remove entry legality; keep entry legality but remove the first witness; keep the witness but change nested owner. A correct sentence narrows from mechanism wording to the last closed contract half. If it still describes a working view-shaping mechanism after entry legality or first witness is missing, it is reading too much from an exit row.

#### 2.7 Event Priority, Injection, and Interruptibility

A hypervisor that intercepts events is responsible for preserving the ordering rules that bare metal would have enforced. This is where many technically impressive but shallow VMMs become distinguishable: the cross-check is an impossible next event, duplicated exception, lost interrupt shadow, stale pending-debug state, or injected event that cannot be derived from the captured exit payload.

Event delivery has three states that must not be collapsed. First, there is the event that caused the exit or was being delivered when the exit occurred. Second, there is the handler's decision: emulate, suppress, retry, reflect, inject another event, or resume without injection. Third, there is the entry-time event state consumed by the next guest run. Intel VMX exposes this separation through VM-exit interruption information, IDT-vectoring or original-event fields, VM-entry interruption-information fields, instruction-length fields, interruptibility state, and pending-debug state. AMD SVM exposes the same analysis class through `EXITINTINFO`, `EVENTINJ`, `nRIP`, decode-assist state, GIF or virtual-interrupt state, interrupt shadow, and VMCB save-state fields. The field names are not interchangeable, but the invariant is shared: the next guest instruction or event must be possible under the event history that the trace describes.

```text
event_delivery_closure =
  pre_exit_guest_state
  -> architectural_priority_decision
  -> native_exit_or_interrupted_event_state
  -> handler_decision_and_side_effects
  -> pending_event_or_injection_state
  -> guest_interruptibility_gate
  -> re_entry_result
  -> first_independent_guest_observation
```

The subtle part is that interruptibility is not commentary. It is a delivery gate. Blocking by `STI`, `MOV SS`, NMI state, SMI or similar modes, debug pending state, and virtual interrupt delivery determines whether an event can legally arrive now, whether it must be delayed, whether the current instruction should be retried, and whether the interrupted event must be completed before a new one is injected. A handler that returns clean memory bytes but corrupts event continuity can still be visible through rare nested faults, debugger behavior, NMI-window behavior, timer jitter, DPC timing, or a first observation after resume that could not follow from bare metal.

| Event surface | Underlying rule | What can go wrong |
|---|---|---|
| instruction emulation | faults, traps, and instruction side effects have architectural priority | the handler advances RIP when the real CPU would have faulted first, or injects the wrong exception type |
| IDT-vectoring state | exits can occur while an event is being delivered | a nested event is lost, duplicated, or reinjected with the wrong error-code validity |
| interrupt shadow | `STI`, `MOV SS`, and related states can delay interrupt delivery | interrupt-window behavior differs from bare metal under timing probes |
| NMI blocking | NMI delivery has special blocking and unblock rules | NMI-window exits or reinjection mistakes create rare but strong evidence |
| debug state | `DR6`, `DR7`, RFLAGS.TF, and pending debug exceptions must agree | single-step or breakpoint hiding changes debugger-observable state |
| APIC and posted interrupts | delivery mode, EOI, TPR, and pending vectors are ordered relative to guest execution | latency-sensitive paths such as input, DPCs, and frame pacing drift |
| event injection controls | entry-time event injection must match vector type, error-code validity, and guest state | returning to the guest with a plausible value but impossible event history still leaks |

The boundary rule is strict. An exception-bitmap hit without vectoring and reinjection state is only an `exception_intercept_candidate`. An NMI-window event without blocking and unblock evidence is only an `nmi_window_candidate`. A single-step or MTF trace without debug-state continuity is only a `single_step_artifact`. A timer or DPC anomaly without event-history closure is only a `latency_correlation`. The sanity check is to replay the same event under a benign VMM or bare-metal control, vary interruptibility state, trigger a nested fault or debug edge, and compare the first independent observation after resume. This is a foundational point, not a variant detail. Hypervisor stealth is less about hiding one object and more about preserving the machine's event history.

#### 2.8 Capability Negotiation and Control-Field Validity

An expert VMM does not "turn on virtualization" with a fixed constant block. It derives a legal control state from CPU-reported capability, platform policy, current ownership of VMX/SVM, and the guest mode it intends to run. The capability surface is therefore evidence. A trace that keeps only the final VMCS or VMCB values loses the reason those values were legal on that CPU.

| Capability surface | Concrete fields or instructions | What must be derived | Common failure mode |
|---|---|---|---|
| Intel fixed control-register masks | `IA32_VMX_CR0_FIXED0`, `IA32_VMX_CR0_FIXED1`, `IA32_VMX_CR4_FIXED0`, `IA32_VMX_CR4_FIXED1` | host and guest `CR0`/`CR4` values that satisfy VMX requirements without inventing impossible OS state | VM-entry fails or a guest resumes with control-register bits that cannot exist on that processor |
| Intel VMX control masks | `IA32_VMX_PINBASED_CTLS`, `IA32_VMX_PROCBASED_CTLS`, `IA32_VMX_TRUE_*_CTLS`, `IA32_VMX_EXIT_CTLS`, `IA32_VMX_ENTRY_CTLS` | allowed-0/allowed-1 normalization for pin, processor, exit, and entry controls | hardcoded control words work on one CPU family and fail on another, or expose a feature combination the CPU cannot support |
| Intel extended virtualization capability | `IA32_VMX_EPT_VPID_CAP`, secondary/tertiary execution controls, EPTP-switching capability, #VE, PML, mode-based execute, sub-page permission, guest-paging verification | the actual EPT/VPID and exit-suppression feature set available to this logical processor | treating "Intel EPT" as one uniform feature and misclassifying newer violation bits or unsupported permission modes |
| Intel VMCS lifecycle | VMXON region revision ID, VMCS revision ID, current-VMCS pointer, `VMPTRLD`, `VMCLEAR`, `VMLAUNCH`, `VMRESUME` | per-logical-processor ownership, launch state, and whether the VMCS is current, active, launched, or clear | cross-core VMCS reuse, stale launch state, or a handler that calls `VMRESUME` on a VMCS that never launched |
| AMD SVM feature discovery | `CPUID Fn8000_000A`, `EFER.SVME`, VMCB intercept fields, nested-paging support, `NRIPS`, decode assists, `VmcbClean`, `FlushByAsid`, `TscRateMsr` | which SVM accelerations are architectural on this CPU and which fields can be trusted on exit | translating an AMD trace into Intel labels and silently dropping SVM-only constraints |
| AMD VMCB caching contract | VMCB clean bits, `TLB_CONTROL`, `ASID`, `N_CR3`, MSRPM/IOPM physical bases | which VMCB groups hardware may cache and which changes require clean-bit clearing or TLB action | modifying a VMCB field while leaving its clean bit set, producing core-dependent or run-dependent behavior |
| AMD invalidation model | `INVLPGA`, `INVLPGB`, `TLBSYNC`, ASID recycling, `FlushByAsid` behavior | whether stale guest or nested translations survive a view change | either stale memory views after a split-view change or over-flushing that creates timing evidence |
| Hyper-V/VSM platform contract | TLFS synthetic MSRs, VTL state, VSM partition/VP status, MBEC, VTL memory protections | whether a system already has a legitimate hypervisor and higher-VTL memory policy | a hidden VMM creates a second, incoherent virtualization story instead of fitting the platform owner |

Preserve the raw feature leaves, capability MSRs, computed control values, VM-entry error fields, VM-exit reason, exit qualification, per-core VMCS or VMCB identity, and the invalidation action that made the next run legal. The invariant is simple: if a control bit is set, the trace should explain which capability made it legal and which guest-visible behavior required it.

Failure classes are stable across vendors even though the field names differ. A hardcoded VMCS control word without the capability MSR is `control_word_unlegalized`. An AMD VMCB update without a clean-bit and ASID/TLB story is `cached_control_candidate`. A nested-enlightenment field without L0/L1/L2 owner identity is `nested_owner_unbound`. A feature bit that appears in CPUID but is not consumed by a successful transition is only `capability_advertised`. The sanity check is control transposition: replay the same guest mode on a nearby CPU or nested owner with one capability absent, and require the conclusion to narrow from "control active" to "control requested" or "capability advertised" rather than silently preserving the stronger wording.

#### 2.9 VMX/SVM Transition-State Closure

Field names become useful only when they are tied to a transition. A VMCS dump, a VMCB dump, or a nested-enlightenment structure can show configured policy, but it does not prove that the processor consumed that policy on the next guest run. The closure question is narrower: did the control object become current, were its fields legal for that CPU and nested owner, did entry consume the expected state, did exit produce a native payload, and did the handler make the next run coherent?

This is the bridge from control-state language into process-memory, timing, interrupt, endpoint-equivalence, or behavior language:

| Transition closure field | Intel VMX evidence | AMD SVM evidence | Nested Hyper-V evidence | Broken implementation it catches | Maximum wording before closure |
|---|---|---|---|---|---|
| control-object identity | VMXON region revision, VMCS revision, current-VMCS pointer, `VMPTRLD`, `VMCLEAR`, launch state, logical processor | `VMRUN` `RAX` system-physical VMCB address, VMCB physical-page identity, host-save area relation | enlightened VMCS GPA, VP assist page active eVMCS field, enlightened VMCB reserved area, `VmId`, `VpId` | treating a copied control page as the active control object, cross-core reuse, stale launch state | control-object candidate |
| capability legalizer | `IA32_FEATURE_CONTROL`, fixed `CR0`/`CR4` masks, `IA32_VMX_*_CTLS`, `IA32_VMX_EPT_VPID_CAP`, secondary/tertiary controls | `CPUID Fn8000_000A`, `EFER.SVME`, SVM feature bits, `VmcbClean`, `FlushByAsid`, `NRIPS`, decode-assist support | TLFS CPUID leaves `0x40000006`, `0x40000009`, `0x4000000A`, eVMCS version, direct virtual flush and enlightened TLB bits | hardcoded control words, Intel-only feature assumptions, unsupported nested feature exposure | legal-control candidate |
| entry input state | guest/host CRs, RIP/RSP/RFLAGS, segment/access-right fields, VM-entry controls, VM-entry MSR-load list, entry interruption-info field | VMCB control area, save-state area, `EVENTINJ`, guest `EFER`, `RIP/RSP/RFLAGS`, segment state | eVMCS/eVMCB fields plus clean-field mask that decides whether L0 reloads memory | entry consumes stale or impossible guest/host state; injected event is incompatible with guest state | entry-state candidate |
| native transition result | `CF`/`ZF`, `VMfailInvalid`, `VMfailValid`, VM-instruction error field, VM-entry failure class, VM-exit reason, exit qualification, IDT-vectoring and interruption fields | `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `EXITINTINFO`, `nRIP`, decode-assist fields where valid, updated save-state | synthetic exit reason, nested VM-exit delivery, direct-flush synthetic exit when partition assist state requires it | collapsing instruction failure, entry failure, synthetic exit, and ordinary VM-exit into one "exit" label | native-transition candidate |
| coherence and currentness action | `INVEPT`, `INVVPID`, EPTP, VPID, MTF restore edge, interruptibility update, old/new VMCS fields | `TLB_CONTROL`, ASID, `N_CR3`, `INVLPGA`, `INVLPGB`, `TLBSYNC`, VMCB clean-bit clear, old/new VMCB fields | eVMCS `CleanFields`, enlightened VMCB clean bit 31, direct virtual flush hypercall fields, partition assist page | table or field mutation never reaches executing hardware; stale virtual TLB survives nested context | coherent-transition candidate |
| external bridge | CR3/PCID or ASID epoch, Windows region/page/read contract, ETW or ISR/DPC witness, engine tick/frame, endpoint comparator | same, plus AMD-native ASID/`N_CR3` and NPF payload retention | nested L0/L1/L2 owner, guest-visible TLFS feature state, hosted endpoint comparator | later bytes, interrupts, or behavior are used to repair a missing transition proof | external-bridge candidate |

The analysis rule is strict. "VMX controls show EPT monitoring" is only `configured_policy_candidate` unless the trace also shows a current VMCS, legal control derivation, VM-entry success or failure class, native exit payload, and invalidation/currentness action. "AMD VMCB has NPT enabled" is only `configured_policy_candidate` unless `VMRUN`, `EXITCODE` or `EXITINFO*`, ASID, `N_CR3`, clean-bit state, and TLB action are joined. "Nested Hyper-V exposed enlightened VMCS" is only `nested_contract_candidate` unless the TLFS feature leaf, VP assist/eVMCS identity, clean-field state, synthetic or native exit, and virtual-TLB ownership are all named.

The invariant is consumed-control proof. A control object does not gain evidentiary force because it exists in memory; it gains force when the processor or nested owner consumed it across a legal transition and produced a replayable native result. The attacker leverage is control-page theater: leaving behind plausible VMCS/VMCB-like pages, copied enlightened structures, or stale clean-field state that looks authoritative without being the active authority. The defender observable is the transition edge that binds identity, legality, native payload, currentness action, and post-entry behavior. The sanity check is control-object substitution: keep the same dump and proposed sentence, then replace the active object with a copied, stale, or wrong-core object. If the sentence does not narrow, it was reading memory decoration rather than transition state.

## Next

Next, the series moves from control-state ownership into the real memory primitive: EPT/NPT. The focus becomes second-stage translation as an evidence-producing state machine, not just a convenient way to hide or reveal pages.
