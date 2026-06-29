---
title: "About Hypervisor Cheats, Part 1: Ring -1, VMX/SVM, and Control-State Ownership"
date: 2026-06-28 00:00:00 +0900
categories: [Windows Internals, Anti-Cheat]
tags: [hypervisor, vmx, svm, vmcs, vmcb, anti-cheat, virtualization, windows]
---

> Hypervisor cheats are not magic Ring -1 stories. They are about who controls the CPU while Windows is running as a guest. This opening post keeps that idea concrete: which state did the processor actually use, and why a structure sitting in memory does not prove a live hypervisor by itself.

## Scope

This part is the architectural foundation. It separates privilege rings from virtualization ownership, explains VMCS/VMCB control state, and introduces one rule that will repeat through the series: a low-level observation is not a game fact until it is connected to Windows state, game state, and player-visible behavior.

---

## Technical Principles of Hypervisor-Based Game Cheats

### Executive Summary

Hypervisor-based game cheats should not be explained as a mysterious "Ring -1" trick. The real mechanism is simpler and more useful: CPU virtualization lets another layer control parts of the environment in which Windows runs. That layer can decide which events leave the guest, which physical page backs a guest physical address, and which timing or device behavior Windows is allowed to see.

That does not mean every low-level observation is automatically meaningful to the game. A hypervisor can observe CPU state, translation state, timer state, device traffic, or raw bytes. To turn that into a cheat explanation, the analysis still has to connect three steps:

```text
hardware fact
  -> Windows process fact
  -> game object or player behavior fact
```

Skipping one of those steps is where many hypervisor-cheat explanations become confusing or overconfident.

The series follows that bridge in order:

1. **Hypervisor technology first.** VMX/SVM, VMCS/VMCB, VM-exits, EPT/NPT, address translation, VMI, and SMP/performance constraints define what is technically possible.
2. **Cheat operation second.** A cheat turns those primitives into memory acquisition, game-object reconstruction, overlay/input delivery, and stealth consistency.
3. **Anti-cheat response third.** Defensive reasoning combines platform trust, virtualization consistency, memory-view checks, device/DMA posture, I/O evidence, and server-side behavior. A single local probe should not be stretched beyond the layer it actually observed.

This post avoids loader instructions, exploit chains, game offsets, bypass code, or implementation-ready cheat code. It focuses on technical mechanisms, state transitions, where each conclusion applies, failure modes, and defensive engineering.

---

## Part I. Hypervisor Technology Fundamentals

### 1. Mental Model: Rings Are Not Enough

Traditional Windows cheat discussions often start with rings. That is useful, but incomplete. Rings tell us whether code is running in user mode or kernel mode inside Windows. They do not tell us whether Windows itself is running directly on the CPU or inside a virtualized environment.

```text
Ring 3  user-mode game, overlay, launcher
Ring 0  Windows kernel, drivers, anti-cheat driver
```

Hardware virtualization adds a second question:

```text
Who controls the environment that Windows is running inside?
```

That is the important part of "Ring -1." It is not just a lower privilege number. It is a separate control layer that can decide how the guest runs.

```text
VMX root / SVM host       hypervisor control layer
VMX non-root / SVM guest  Windows kernel and user-mode software
```

The guest still believes it owns CR3, page tables, interrupts, MSRs, timers, and memory permissions. A hypervisor can let most of that run normally, but ask the CPU to report selected events first.

Keep two paths separate:

1. **Observation path:** how bytes, events, or timing were observed.
2. **Delivery path:** how that information could reach a player, overlay, input helper, replay, or server-visible behavior.

This separation matters because "read below Windows" is not the same sentence as "the player used hidden information."

```text
Game and anti-cheat
  -> Windows kernel
  -> guest virtual memory and guest page tables
  -> EPT/NPT second-stage translation controlled by hypervisor
  -> physical memory and hardware-facing state
```

For anti-cheat, this means a malicious or untrusted hypervisor can move important artifacts outside the normal Windows model. The game process may have no injected DLL, no suspicious handle, and no modified guest page table, while a lower layer still observes memory or timing.

The limit is just as important. A missing Windows artifact is not proof of absence. A lower-layer read is not gameplay impact until it is tied to a process, a game object, a delivery path, and a behavior or replay consequence.

#### 1.1 What the Hypervisor Actually Owns

The useful mental model is not "Ring -1 is stronger than Ring 0." The useful model is narrower:

```text
the hypervisor owns the conditions under which Ring 0 runs
```

It can own execution rules, state transitions, second-stage memory translation, event delivery, selected timing behavior, and some platform/device presentation. It does not automatically own every truth about Windows, the game engine, the player, or the server.

Before moving from a low-level fact to a game fact, ask four simple questions:

| Question | Good answer | Weak answer |
|---|---|---|
| What is being controlled? | execution, memory translation, event delivery, time, or device view | "Ring -1 controls everything" |
| What carries that control? | VMCS, VMCB, EPTP, `N_CR3`, intercept bitmap, MSR policy, or IOMMU domain | "some hypervisor state" |
| Who can check the story? | guest code, kernel code, CPU payload, device path, or replay/server evidence | one clean value |
| What is still unproven? | Windows ownership, game meaning, player visibility, or server impact | lower-layer visibility is treated as gameplay truth |

| Owned area | What the guest believes | What the hypervisor can actually control | Technical consequence |
|---|---|---|---|
| execution | privileged instructions, exceptions, interrupts, and returns behave like bare metal | selected instructions and events can be routed to VMX root or SVM host first | the guest can be correct locally while still running inside a constrained execution envelope |
| state | CRs, DRs, MSRs, segment state, descriptor tables, and APIC state are the machine state | VMCS/VMCB state can virtualize, shadow, save, restore, or reject those values | detection cannot rely on one register story; related state must be cross-checked |
| translation | CR3-selected page tables define process memory | guest virtual translation is only the first stage; EPT/NPT decides the final physical view | guest page tables can look clean while the second stage blocks, redirects, or observes access |
| events | faults and interrupts are delivered according to architectural priority | exit controls, qualification fields, and reinjection paths can interpose on delivery | wrong event ordering is a stronger signal than a single suspicious value |
| time | TSC, APIC timers, QPC, HPET, scheduler time, and network time are mutually plausible | TSC offset/scaling and timer exits can alter some clocks but not all observers equally | timer hiding is a coherence problem, not a single-field spoof |
| platform | Windows observes a coherent boot, Hyper-V, VBS, device, and policy story | a VMM may coexist with or conflict with the platform's legitimate hypervisor/trust state | modern analysis must include Hyper-V/TLFS/VSM state, not just CPUID |

This is why hypervisor analysis should start from behavior, not artifacts. A DLL, handle, driver object, or guest PTE is only one possible clue. The better question is whether execution, state, translation, events, time, and platform policy still describe one coherent machine.

If different observers disagree, name the first layer where the story breaks. That is stronger and clearer than jumping straight to a cheat label.

#### 1.2 From Hardware Facts to Game Facts

Each observation belongs to a specific layer. A CPU manual can define what an EPT violation means; it cannot prove which Windows process owned the byte. A Windows memory API can describe region and read rules; it cannot prove that the second-stage memory view was honest. A replay can show behavior; it cannot prove how the local endpoint learned the information.

Read the evidence as a ladder:

| If the evidence stops here | Say this | Do not say this yet |
|---|---|---|
| CPU exit or VMCS/VMCB state | a low-level transition or control-state event happened | a game object was read |
| guest CR3 and page-table walk | a virtual address mapped to a guest physical address | the final physical bytes were honest |
| EPT/NPT entry or fault | the second-stage view mapped, blocked, redirected, or faulted a GPA | Windows would expose the same bytes |
| physical or VMI byte read | bytes were acquired through one route | the live process contained a current object |
| Windows region and read parity | a bounded process-memory observation exists | the object was meaningful to gameplay |
| engine object plus delivery path | the information could affect player-visible behavior | enforcement certainty without replay or server context |

The practical rule is simple: write the conclusion from the weakest step in the chain. If the chain stops at a second-stage fault, call it a translation-layer event. If it reaches bytes but not Windows parity, call it a below-OS byte sample. If it reaches Windows parity but not engine lifetime, call it a process-memory observation. Stronger wording needs stronger joins.

### 2. VMX/SVM Control State

Intel VT-x uses VMX root and non-root operation. AMD-V/SVM uses host and guest operation. The names differ, but the practical idea is the same: the CPU needs a valid control object, enters guest execution, records why it left, and returns to the guest without breaking the machine's story. So a statement that stops at "VMX is enabled" or "SVM is enabled" is only saying that a mode exists. It does not prove who actually controlled execution at runtime.

| Concept | Intel term | AMD term | Why it matters |
|---|---|---|---|
| Virtual CPU control block | VMCS | VMCB | Holds guest state, host state, and control policy |
| Second-stage paging | EPT | NPT/RVI | Lets the hypervisor translate guest physical memory to host physical memory |
| Exit to hypervisor | VM-exit | #VMEXIT | Lets selected guest events be handled below the OS |
| Entry to guest | VM-entry | VMRUN/resume | Returns control to Windows after emulation or policy handling |
| Per-register/event filtering | MSR bitmaps, I/O bitmaps, exception bitmap | intercept vectors and bitmaps | Keeps overhead manageable by avoiding unnecessary exits |

Control state is where the hypervisor becomes real. Handler code only runs when the VMCS or VMCB tells the CPU to send an event out of the guest. Thinking of VMX/SVM as one magic privilege bit hides the real model: the CPU is following a set of rules for state, memory translation, event routing, and returning to Windows.

The useful path is:

```text
control object
  -> legal guest entry or exit
  -> native exit payload
  -> handler changes
  -> guest resumes coherently
```

The common mistake is to skip one of those steps and then make a stronger claim about process memory, game state, or stealth.

The key distinction is configured control versus consumed control. A VMCS, VMCB, bitmap, intercept vector, or nested structure matters only when the CPU or nested owner actually used it during a legal transition. A useful cross-check is simple: replace the active control object with a stale copy, a wrong-core copy, or an object that was never entered. If the conclusion still sounds just as strong, it was probably based on a memory object rather than live execution.

#### 2.1 State Groups

A hypervisor has to keep several parts of the machine consistent at the same time. If it only fakes one surface, another surface can contradict it. That is why the important question is not "did one field look suspicious?" but "did all related state move together?"

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

These groups are not independent checkboxes. A VM-exit joins guest state, host resume state, control policy, translation state, and exit information into one transition.

A readable analysis should answer a few concrete questions:

- which logical processor owned the control object?
- which VMCS or VMCB was current?
- which guest instruction or event caused the exit?
- which translation root was active?
- which fields were updated by hardware?
- which state was only cached or inferred by software?
- which pending event was injected, delayed, or suppressed when the guest resumed?

The rule is cross-group consistency. For example, changing only CPUID while leaving `CR4.OSXSAVE`, XState masks, MSR access, and exception behavior unexplained is not a full CPU story. It is only a feature story. Naming an EPT violation without the active EPTP/NPT root, invalidation step, guest-linear validity, and resume behavior is not a complete memory-view conclusion. It is only a fault observation.

A thin malicious hypervisor wants to keep only the surfaces that someone is likely to check. The useful defensive signal is not one odd field. It is a mismatch between fields that should agree:

- a TSC story that disagrees with interrupt delivery
- a CPUID story that disagrees with XState exception behavior
- an EPT story that disagrees with Windows page-state replay
- a PASID story that disagrees with the CPU address-space root

The safe wording rule is simple: "the VMCS says X" is still only a VMCS-local statement. It becomes stronger only after the live transition, the guest-visible result, and the later process or game evidence are connected.

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

For cheat analysis, several VMCS fields are especially important because each one creates a different intercept, timing, translation, or re-entry owner. A useful analysis row preserves the field family, the controlling capability MSR or allowed-bits source, the vCPU epoch, and the evidence after the transition instead of flattening the tuple into "VMX was enabled."

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

The invariant is instruction-state pairing. Every VMX instruction conclusion needs the instruction, the logical processor, the current VMCS state, the capability basis, the success/failure carrier, and the next lifecycle state. The simple check is to keep the same instruction trace but move it to a different logical processor, clear the current VMCS, change launch state, or replace the capability MSR tuple. If the conclusion still says the same thing, it is treating a VMX mnemonic as evidence instead of checking the architectural transition that actually happened.

##### Intel VMCS field detail

The Intel VMCS is field-encoded, not a C structure with a stable public layout. For analysis, classify fields by processor use, capability dependency, width, access class, and transition epoch.

| VMCS field family | Representative fields | What the processor uses it for | Anti-cheat relevance |
|---|---|---|---|
| Guest control state | guest CR0/CR3/CR4, DR7, IA32_EFER, PDPTEs where relevant | Defines the guest execution and paging environment loaded on VM entry and updated on VM exit. | Bad values crash Windows or create impossible combinations such as unsupported long-mode or paging states. |
| Guest descriptor state | guest CS/SS/DS/ES/FS/GS/TR/LDTR selectors, bases, limits, access rights, GDTR/IDTR | Reconstructs segmentation, task, and descriptor-table state. | Segment/access-right mistakes are a common source of subtle VM-entry failures and emulation evidence. |
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

VMX transition failure is evidence, not only a bring-up bug. Intel separates instruction failure from VM-entry failure, ordinary VM-exit payload, and catastrophic VMX-abort state.

A broad sentence such as "VM entry failed" is too weak unless it names the failure class, the field owner, and the information source. A broad sentence such as "VM-exit failed" is usually worse because there is no routine VM-exit failure class that mirrors VM-entry failure.

If a VM-exit cannot complete as a coherent transition, describe the actual evidence: malformed host-state load risk, missing exit-information payload, VMX-abort indicator, reset/shutdown behavior, or crash context.

| Failure surface | Manual-level source | Common broken implementation | Data to retain | Maximum conclusion |
|---|---|---|---|---|
| VMX instruction failure | `VMfailInvalid`, `VMfailValid`, `CF`, `ZF`, current-VMCS validity, VM-instruction error field | stale current VMCS pointer, wrong `VMCLEAR`/`VMPTRLD` lifecycle, `VMLAUNCH` after launch state, `VMRESUME` before launch state, unsupported VMX operation state | instruction, flags, VMCS pointer state, VM-instruction error, logical processor id, `CR4.VMXE`, `IA32_FEATURE_CONTROL`, VMXON region identity | VMX lifecycle failure |
| VM-entry control validation | pin-based, primary processor-based, secondary or tertiary processor-based, VM-exit, and VM-entry controls; capability-MSR allowed-0/allowed-1 masks | hardcoded control constants, reserved bits set, feature bit assumed from another CPU family, inconsistent dependency such as EPT-dependent control without EPT support | raw control values, capability MSRs, computed legal masks, dependency graph, VM-entry failure metadata | illegal control-state failure |
| VM-entry host-state validation | host CR0/CR3/CR4, host selectors, host RIP/RSP, host MSR-load state, fixed-bit and canonical-address requirements | noncanonical host pointer, bad selector, CR fixed-bit violation, host MSR list that does not match enabled controls | host-state fields, CR fixed-bit compliance data, host MSR list address/count, enabled exit controls, failure qualification where available | host-state invalidity |
| VM-entry guest-state validation | guest CR0/CR3/CR4, segment/access-right fields, activity state, interruptibility state, pending debug exceptions, guest IA32_EFER/PAT/debug/CET/FRED/PKRS state where supported | impossible long-mode or paging combination, invalid descriptor state, stale interruptibility, event injection incompatible with guest state | guest-state fields, event-injection fields, interruptibility and activity state, pending-debug state, PDPTE or paging-mode evidence, failure qualification where available | guest-state invalidity |
| VM-entry MSR-load failure | VM-entry MSR-load address/count and 16-byte MSR entries; WRMSR-equivalent validity checks; entry failure qualification | stale MSR-load list, unsupported MSR index, reserved bits in MSR value, EFER/PAT/perf/CET/PKRS state inconsistent with active controls | list address/count, failing entry index, MSR/value pair, control bit that requested the load, entry-failure metadata | entry-load failure |
| EPT/VPID invalidation failure | `INVEPT`, `INVVPID`, EPTP, VPID, invalidation type, EPT/VPID capability bits | remap or split view without matching invalidation, unsupported invalidation type, over-flush hiding stale-state evidence | invalidation instruction, type, operand descriptor, EPTP/VPID, old/new leaf, affected core set, resume epoch | stale or over-flushed translation risk |
| exit-information classification | exit reason, exit qualification, guest-linear address, guest-physical address, instruction information/length, interruption information, IDT-vectoring information | reducing an event to RIP plus reason, losing GLA-valid and page-walk context, mixing event-delivery exits with final memory access exits | full exit payload, GLA-valid and GPA fields, page-walk versus final-page label, event-delivery state, handler decision | classified VM-exit event |
| VMX-abort or exit-transition catastrophe | VMCS abort indicator, VMXON/current-VMCS state, host-state load context, reset or crash evidence | treating an unrecoverable transition as an ordinary exit reason, or treating a reset as stealth | VMCS abort indicator, current VMCS identity, logical processor, host-state fields if retained, machine-check or crash evidence, first coherent post-reset epoch | catastrophic lifecycle evidence |

The strongest Intel conclusion is only as strong as the last legal transition. If the analysis cannot replay the derivation from capability MSRs to legal control fields, from legal control fields to VM-entry, and from VM-entry to exit payload, the conclusion should stop at lab-local failure or mechanism suspicion.

#### 2.3 AMD VMCB Layout in Practice

AMD SVM uses the VMCB as the state block that `VMRUN` actually reads and updates, not merely as a struct that happens to exist in memory. A useful trace separates the control area from the save-state area, then asks which fields were used on entry, which fields were written back on exit, which fields may have been cached through clean-bit behavior, and which permission-map or nested-root pages lived outside the VMCB body. Without that `VMRUN` epoch, a VMCB dump is only configuration evidence.

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

The practical rule is simple: do not treat the VMCB as one object with one clock. Its control fields, permission-map pages, ASID/TLB state, nested root, virtual-interrupt state, save-state bytes, clean bits, and exit-status fields can all have different currentness.

That matters because a thin SVM layer can touch only a few groups and still observe useful events. The useful defensive clue is contradiction between groups:

- an exit stream that does not match the intercept epoch
- an NPF tuple that does not match `N_CR3`
- an interrupt result that does not match virtual-interrupt state
- guest behavior that follows cached state rather than the VMCB bytes currently visible in memory

The sanity check is to change one group at a time: one VMCB field group, one clean bit, and one ASID/TLB epoch. If the conclusion still treats the VMCB as a single timeless object, the wording is too strong.

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

The source vocabulary needs one more split: dedicated SVM instructions are not the same thing as interceptable instruction families. The former move ownership across the host/guest boundary; the latter are policy decisions encoded in VMCB intercept fields. An analysis that calls every intercepted instruction an "SVM instruction" loses the authority boundary.

Keep the roles separate. `VMRUN` is a world-switch operation. `VMLOAD` and `VMSAVE` move selected state. `STGI` and `CLGI` gate interrupts. `INVLPGA` invalidates address translations. An intercept bit is policy.

A thin hypervisor wants the smallest policy surface that still exposes CR3, timer, page-fault, or translation information. A defender should therefore look for mismatch between the role, the VMCB fields that changed, the exit code, the timing distribution, and the state that changed afterward.

This section is about SVM control metadata, not game bytes. The useful data is the VMCB physical address, host save area, guest save-state area, intercept bits, ASID, invalidation operand, and exit code. It should not be described as process memory or game evidence until another section connects it to those layers.

Common failure modes are easier to read as a list:

- broad interception of hot instructions
- stale ASID-tagged translations after incomplete `INVLPGA` or `TLB_CONTROL` use
- interrupt-window drift after `CLGI` or `STGI` mistakes
- hidden state drift from misordered `VMLOAD` or `VMSAVE`
- measured-launch trust inferred from `SKINIT` without boot-chain and TPM evidence

The sanity check removes one role at a time. Allow the hot instruction, freeze one intercept field, replace `INVLPGA` with a broader flush, replay with a different ASID, or compare NMI timing with and without interrupt gating. If the same conclusion survives every variant, the evidence is not role-specific enough.

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

The control area should be read as transition-owned state, not as a static field table. A field is meaningful only if the `VMRUN` epoch used it, the clean-bit state allowed the CPU or implementation to see the change, and the resulting exit or guest behavior preserved the same owner story.

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

The source checkpoint is stricter than "the VMCB saves registers."

`VMRUN` uses the system-physical VMCB address supplied through `RAX`. It saves only the host subset needed for return through the host save area, then loads guest state and control from the VMCB. Additional state may still depend on `VMLOAD`, `VMSAVE`, or software-managed paths.

SEV-ES makes this boundary sharper. Legacy AMD-V exposes more register state to hypervisor-managed save paths. SEV-ES encrypts and integrity-protects the guest save-state area and moves selected emulation disclosure into the guest-controlled #VC/GHCB path. A save-state conclusion should therefore name the SVM generation and protection mode before it says what the hypervisor can observe or modify.

The ownership rule is also simple: a VMCB memory snapshot is not automatically the state the CPU loaded. A post-exit VMCB field is not automatically the state that existed at the faulting instruction.

The bridge has to connect VMCB physical identity, `VMRUN` epoch, clean-bit state, load/save path, and a guest-visible comparator. There are at least three time windows:

1. bytes before `VMRUN`
2. state actually consumed during entry
3. state written back or disclosed after exit

The cheat-side problem is consistency. A thin hypervisor must keep segment state, control registers, `EFER`, syscall state, debug state, interruptibility, and extended/security state plausible while minimizing exits and clean-bit churn.

The defensive clue is cross-owner drift: guest-visible syscall or exception behavior that disagrees with VMCB snapshots, per-core differences after VMCB reuse, clean-bit mismatches after field mutation, #VC/GHCB disclosure that does not match expected visibility, or invalid exits after a supposedly valid transition.

The AMD-specific risk is more than "wrong intercept." Stale cached state is just as important. A hypervisor that moves a VMCB between cores, changes a VMCB physical page, or modifies guest state without clearing the correct clean bits can produce stale or processor-dependent behavior.

The common failure modes are:

- collapsing pre-exit state, consumed-entry state, and post-exit writeback into one snapshot
- omitting `VMLOAD` or `VMSAVE` from the state story
- drifting XState after `XRSTOR` or lazy save paths
- leaving clean-bit groups stale
- over-reading the host save area
- overstating SEV-ES save-area visibility
- understating GHCB-mediated disclosure
- treating one core's VMCB observation as system-wide state

The sanity check changes one owner at a time. Keep the VMCB bytes fixed but change clean bits. Keep clean bits fixed but change the physical VMCB page. Replay on another core. Compare guest `CPUID`, syscall, and exception behavior. If the same sentence still names exact guest state, it is reading too much from the VMCB snapshot.

##### AMD SVM run/exit lifecycle

On AMD, the VMCB is not just a saved-register block. It is the state block loaded by `VMRUN` and updated on `#VMEXIT`; the control area, save-state area, ASID, `N_CR3`, intercept vectors, clean bits, and `TLB_CONTROL` each carry a different currentness question.

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

A VM-exit is not free. The CPU leaves guest execution, loads host state, runs the hypervisor handler, possibly emulates an instruction or event, then resumes the guest. The cost is not only time. The handler also has to preserve event priority, interruption state, debug state, instruction results, memory-translation visibility, and clock continuity.

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
| handler-change view | handler policy | register/MSR/page-view/event-injection change and invalidation range | the handler changes state without a replayable explanation |
| resumption view | VM-entry or `VMRUN` contract | legal guest state, pending event handling, next RIP/NRIP, timer/interrupt continuity | the guest resumes with impossible or stale state |

The rule is transition conservation. The event that left the guest, the handler decision, and the state that re-entered the guest must describe the same vCPU epoch.

A thin layer benefits from selective observability. It can choose a small set of exits that expose timing, CR3, page-fault, MSR, CPUID, or second-stage events.

The defensive clue is conservation failure:

- exit counts without native payload
- payload without target binding
- handler mutation without invalidation evidence
- resumption without legal event state

The sanity check is to keep the guest workload constant while varying one owner, such as intercept bitmap, timer load, vCPU placement, or nested-root epoch. The exit explanation should move only with the owner it names.

A cheat-oriented design wants exits to be selective because broad interception creates timing, performance, and event-distribution evidence:

1. Identify the game process or relevant address space.
2. Intercept only events that help memory acquisition, stealth, or input control.
3. Avoid hot render, input, network, and scheduler paths.
4. Preserve the same CPU-visible results that Windows expects.
5. Keep per-vCPU and global state synchronized.

##### 2.4.1 Exit Context as a State Transition

A VM-exit should be treated as a state transition, not as a callback log. The useful context is what the CPU was doing, why the architecture transferred control, what state became architecturally visible to the host, and what the handler changed before re-entry.

The important question is causality. An EPT violation, NPF, MSR intercept, CPUID intercept, I/O intercept, or event-delivery exit can all look like "the hypervisor observed the guest." Stronger wording needs more context: did the event belong to the target address space, did the handler preserve the CPU-visible result, did the guest resume legally, and did the event later connect to memory, game state, or behavior?

| Step | Native evidence | Analyst question | If missing |
|---|---|---|---|
| source context | vCPU, guest RIP/NRIP, CR3/ASID, CPL, interruptibility, pending vectoring | which execution moment produced the exit? | the exit is missing context |
| cause payload | Intel exit reason/qualification or AMD exitcode/exitinfo fields | what exact condition transferred control? | the exit type is under-specified |
| target binding | GLA/GPA validity, process root, nested root, access type, instruction bytes | did the event belong to the target game or OS object? | the target is not joined |
| handler change | emulation result, injected event, register/MSR/page-view change, invalidation range | what did the handler change before resume? | the handler result is not yet replayed |
| re-entry legality | VM-entry success/failure, VMRUN resume state, pending events, next RIP/NRIP | did the guest resume legally? | resume legality is unproven |
| later consequence | memory meaning, render/input path, replay/server consequence | did the low-level event become an advantage or evidence? | the game bridge is missing |

This framing is especially important for late-launch hypervisors. A live system already has pending interrupts, debug state, timer state, lazy FPU/XState ownership, scheduler state, and partially ordered memory events. If the exit context does not preserve those joins, the strongest safe statement is only "a transition occurred under virtualization," not "the hypervisor correctly observed or controlled the target behavior."

##### 2.4.2 Cost Model and Exit Budget

A VM-exit has two costs. The obvious cost is the time spent leaving the guest, running the handler, and returning to the guest. The less obvious cost is the trace it leaves behind: changed timing, TLB/cache disturbance, interrupt delay, or a slightly different event order. A rare exit can still matter if it happens during a render frame, input sample, network receive, anti-cheat probe, or scheduler transition.

| Cost surface | What changes | Why it matters |
|---|---|---|
| direct exit latency | guest stops while host handler runs | tail spikes can correlate with gameplay phases |
| translation disruption | EPT/NPT or guest-paging caches may need invalidation | stale or over-flushed views change timing and correctness |
| interrupt/event continuity | pending event, vectoring state, interrupt shadow, NMI blocking | double injection or lost event creates rare but strong evidence |
| SMP coordination | one vCPU's view change must be visible to other cores when treated as global | unsynchronized split views produce cross-core disagreement |
| probe interaction | anti-cheat, OS, or game timing probes run through the same CPU fabric | spoofed timers cannot explain all latency sources equally |

A useful analysis should not stop at average latency. A cheat-oriented hypervisor can have a low average cost and still leak through rare frame stalls, input jitter, network delay, or timer distortion. The reverse is also true: a synthetic benchmark can show expensive exits without proving gameplay impact. The exit has to be tied to the same workload phase, core placement, and observer that the conclusion talks about.

#### 2.5 Intercept Cost Model

Interception cost is not only "number of exits." Each exit class touches a different part of the machine: control-flow order, timer behavior, interrupt latency, page-table freshness, MSR identity, or exception delivery. A low exit count can still be loud if it touches a sensitive clock or hot page. A frequent exit can be benign if it belongs to a legitimate Hyper-V, VBS, or nested-virtualization path.

For each intercept family, separate the immediate cost from the follow-up obligations:

```text
intercept_cost =
  time_spent_in_exit_handler
  + emulation_correctness
  + translation_invalidation_work
  + timer_and_clock_consistency
  + interrupt_delivery_consistency
  + scheduler_tail_latency
  + number_of_observers_that_can_notice
  + reentry_correctness
```

These terms are not interchangeable. The handler can be fast while the timer story is still wrong. A rare EPT/NPT fault can still be expensive if it forces broad invalidation. The same event may also be visible to guest code, VMCS/VMCB payload, Hyper-V/TLFS state, ETW timing, device paths, GPU timelines, or server replay. A low-cost statement should therefore say what was measured and which observers were not covered.

| Intercept class | Common trigger shape | Primary cost axis | State that must be retained | Common overstatement |
|---|---|---|---|---|
| CPUID | feature discovery, anti-VM probe, library initialization | identity coherence | leaf/subleaf, vendor path, hypervisor-present story, TLFS leaves if exposed, per-core consistency | treating one clean leaf as a coherent CPU story |
| RDTSC/RDTSCP | probes, busy loops, frame timing, QPC-related calibration | clock and scheduler coherence | TSC offset/ratio if used, reference-time relation, core migration, power state, wall-clock or server tick comparator | treating a local delta threshold as evidence of hostile virtualization |
| CR3/CR access | context switches, address-space root changes, paging-mode probes | event volume and process-root currentness | old/new CR value, PCID or ASID context, thread/vCPU epoch, CR3-target policy, later address-space join | treating a CR3 sample as game-process memory evidence |
| MSR access | syscall path, APIC, TSC, EFER, PAT, debug/perf, synthetic MSRs | emulation correctness | MSR number, read/write, value, dependency controls, family behavior, failure path | treating a spoofed value as evidence that dependent behavior is coherent |
| Debug and exception events | #DB, #BP, #PF, #NM, #VE, single-step, breakpoint-style probes | event ordering | vector, error code, pending debug state, IDT-vectoring or event-injection state, next guest event | treating a delivered value as evidence that exception history was legal |
| EPT/NPT violation | watched page, execute trap, write suppression, view switch | translation currentness | access type, GLA/GPA validity, EPTP or `N_CR3`, VPID/ASID, invalidation action, re-arm path | treating a second-stage fault as process/object authority |
| Interrupt/APIC/SynIC events | timer, IPI, EOI, posted interrupt, synthetic timer | latency and delivery ordering | APIC/AVIC/APICv/SynIC owner, pending/service state, vector, EOI path, timer source, ISR/DPC witness | treating interrupt delay as a cheat verdict without platform-owner closure |
| I/O port and MMIO exits | device probe, legacy port, mapped register, doorbell-like path | device ordering | port or GPA, device owner, posted write behavior, memory type, interrupt/fence relation | treating device-side ordering as CPU process-memory evidence |

The second split is **semantic value versus intercept temperature**. A hot intercept is not automatically useful, and a useful intercept is not automatically hot.

For example, all-CR3 exiting can produce many exits and still fail to identify the correct process if the analysis loses thread, PCID, and map-transition context. Conversely, a rare MSR or CPUID intercept can be highly visible if the emulation creates a contradictory Hyper-V, VBS, CET, XState, or timer story.

The useful question is not "how many exits occurred?" It is "which layer did this exit help, and which layer did it disturb?"

| Workload phase | Intercept-pressure risk | Why it matters | Careful wording before more evidence |
|---|---|---|---|
| boot or hypervisor bring-up | VMX/SVM lifecycle, capability, MSR, interrupt setup | many legitimate platform transitions also happen here | possible platform transition |
| launcher and anti-cheat initialization | CPUID/MSR/timer probes, driver and VBS checks | benign security software can create the same families | possible platform-coherence issue |
| map load or level transition | CR3, paging, allocation, file and memory pressure | object roots and address spaces churn quickly | possible address-space churn |
| active match frame loop | hot pages, timers, input, GPU and interrupt pressure | small added latency can become phase-coupled | workload-correlated pressure |
| spectate, replay, or capture | presentation and behavior observers dominate | local intercept evidence may be absent or stale | possible delivery or behavior evidence |
| explicit probe window | timing, debug, exception, and CPUID probes | the probe itself changes the workload | probe-conditioned signal |

This table is also a false-positive guard. A Windows endpoint can legitimately expose Hyper-V, VBS, HVCI, WSL2, debugger, nested virtualization, GPU virtualization, and synthetic interrupt or timer behavior. A good intercept-cost paragraph should identify the legitimate platform owner before it names a hostile one. For an unexplained signal, the honest wording is often "platform owner unresolved," not "cheat hypervisor."

The defensible cost model is phase-coupled and replayable:

Use three controls for the sanity check:

1. Keep the same workload and remove one intercept family at a time in a benign lab VMM or trace harness. Only conclusions owned by that family should move.
2. Keep the intercept family but change the workload phase. A process-memory or game-object conclusion should not survive if the only stable evidence is phase-correlated pressure.
3. Keep the local trace but add an independent observer, such as Hyper-V/TLFS state where present, ETW timing, a replay/server tick, a device path, or a second core.

If the conclusion changes when a stronger observer is added, the original sentence was only a phase-correlated signal, not a complete mechanism explanation.

For hypervisor-based cheat analysis, the important lesson is that extra intercepts create extra evidence. Each intercepted instruction, fault, timer, interrupt, invalidation, and re-entry path has to be explained. Until those requirements are satisfied, the safest wording is only that the trace shows limited intercept activity during a named workload phase.

#### 2.6 VM-Entry and VM-Exit as a Correctness Check

VM-entry and VM-exit are often described as transitions, but the useful reading is stricter. The processor does not just jump to a handler. It validates control fields, loads or saves selected architectural state, saves exit information, applies event-blocking rules, and then expects the VMM to return with a coherent next guest state.

| Transition stage | Intel VMX framing | AMD SVM framing | Analysis consequence |
|---|---|---|---|
| capability discovery | CPUID, VMX capability MSRs, allowed-0/allowed-1 control masks, EPT/VPID capability MSR | CPUID SVM/NPT feature bits, VMCB capability details, ASID and nested paging support | hardcoded control fields are brittle; capability state is part of the evidence |
| launch preconditions | CR0/CR4 fixed bits, IA32_FEATURE_CONTROL, VMXON region, current VMCS, VM-entry checks | EFER.SVME, VMCB physical address in `RAX`, valid control/save-state fields | failures here are not stealth. They indicate broken ownership or incompatible platform state |
| guest state load | VM-entry loads guest CRs, RIP/RSP/RFLAGS, segments, MSR-selected state, event injection state | `VMRUN` loads VMCB save-state and control policy, then executes guest mode | a believable VMM must preserve illegal-state checks and mode-specific corner cases |
| exit dispatch | exit reason, qualification, interruption info, instruction length, GPA/GLA where applicable | `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `EXITINTINFO`, updated save-state area | a normalized trace must preserve vendor-native fields before abstracting them |
| emulation decision | handler may emulate, reflect, deny, adjust controls, or modify memory mappings | handler updates VMCB state, TLB control, ASID/NPT state, event injection | the difficult part is preserving flags, pending events, TLB state, time, and interrupts |
| re-entry | `VMLAUNCH` or `VMRESUME` re-enters with VM-entry checks and optional injected event | next `VMRUN` re-enters with VMCB state and clean-bit behavior | a bad handler often fails one exit later, not at the point where the mistake was made |

At this level, this means a VM-exit log should not be reduced to "exit reason + RIP." The transition context needs the active vCPU, guest mode, CR3/PCID or ASID, interruptibility, pending event state, exit qualification, GLA/GPA validity, active EPTP or `N_CR3`, and the re-entry action to stay together. Otherwise the log can prove only that an exit row existed, not that the handler preserved a legal transition.

The rule is transition-state conservation. Every exit must leave enough evidence to replay four things:

1. what hardware saved
2. what the handler changed
3. what event was pending
4. why the next entry was legal

The common failure is selective incompleteness: keeping the convenient exit reason while dropping the state that would expose illegal reinjection, stale control cache, wrong CR3/ASID, or impossible interruptibility.

The sanity check is one-exit-later replay. Start from the saved state, apply only the captured handler mutations, run the documented entry checks, and verify that the next exit or guest instruction is possible under the described state.

When a VM-exit is used to explain a stable VMM, hidden hook, memory view, or game effect, both halves of the transition have to stay connected: the exit had to be legal to take, and the next entry had to be legal to resume.

Common ways transition evidence gets overstated:

| Failure class | Missing evidence | Safer wording |
|---|---|---|
| exit without route owner | exit reason exists, but the control bit or nested owner that routed it is unknown | exit payload only |
| handler result not replayed | emulation result is logged, but flags, pending events, time, TLB, or MSR/CR effects are absent | handler result incomplete |
| entry legality missing | resume was attempted, but entry checks, host state, guest state, or MSR-load legality are not replayed | resume attempt only |
| clean-state ambiguity | VMCS/VMCB cached or clean fields may not match memory image | currentness unproven |
| nested owner ambiguity | L1-visible event, L0 shadow event, and TLFS/enlightened event are collapsed | nested owner uncertain |
| witness gap | no first post-entry instruction, next exit, or independent observer exists | transition not closed |

The sanity check is to remove one piece of evidence at a time. Keep the same exit payload but remove the handler result. Keep the handler result but remove entry legality. Keep entry legality but remove the first witness after resume. Keep the witness but change the nested owner. A correct sentence should weaken exactly where the missing evidence appears.

#### 2.7 Event Priority, Injection, and Interruptibility

A hypervisor that intercepts events is responsible for preserving the ordering rules that bare metal would have enforced. This is where many technically impressive but shallow VMMs become distinguishable: the cross-check is an impossible next event, duplicated exception, lost interrupt shadow, stale pending-debug state, or injected event that cannot be derived from the captured exit payload.

Event delivery has three states that must not be collapsed:

1. the event that caused the exit, or the event that was already being delivered
2. the handler decision: emulate, suppress, retry, reflect, inject, or resume
3. the entry-time event state consumed by the next guest run

Intel VMX exposes this through interruption-information fields, IDT-vectoring fields, VM-entry injection fields, instruction length, interruptibility state, and pending-debug state. AMD SVM exposes the same analysis class through `EXITINTINFO`, `EVENTINJ`, `nRIP`, decode-assist state, GIF or virtual-interrupt state, interrupt shadow, and VMCB save-state fields.

The field names differ. The rule is the same: the next guest instruction or event must be possible under the event history that the trace describes.

```text
event_delivery_closure =
  pre_exit_guest_state
  -> architectural_priority_decision
  -> native_exit_or_interrupted_event_state
  -> handler_decision_and_state_changes
  -> pending_event_or_injection_state
  -> guest_interruptibility_gate
  -> re_entry_result
  -> first_independent_guest_observation
```

Interruptibility is not commentary. It is a delivery gate.

States such as `STI` blocking, `MOV SS` blocking, NMI blocking, SMI-like modes, pending debug state, and virtual interrupt delivery decide whether an event can legally arrive now or must be delayed.

A handler can return clean memory bytes and still leak through event history. The visible symptoms may be rare nested faults, debugger behavior, NMI-window behavior, timer jitter, DPC timing, or a first observation after resume that could not follow from bare metal.

| Event surface | Underlying rule | What can go wrong |
|---|---|---|
| instruction emulation | faults, traps, and instruction results have architectural priority | the handler advances RIP when the real CPU would have faulted first, or injects the wrong exception type |
| IDT-vectoring state | exits can occur while an event is being delivered | a nested event is lost, duplicated, or reinjected with the wrong error-code validity |
| interrupt shadow | `STI`, `MOV SS`, and related states can delay interrupt delivery | interrupt-window behavior differs from bare metal under timing probes |
| NMI blocking | NMI delivery has special blocking and unblock rules | NMI-window exits or reinjection mistakes create rare but strong evidence |
| debug state | `DR6`, `DR7`, RFLAGS.TF, and pending debug exceptions must agree | single-step or breakpoint hiding changes debugger-observable state |
| APIC and posted interrupts | delivery mode, EOI, TPR, and pending vectors are ordered relative to guest execution | latency-sensitive paths such as input, DPCs, and frame pacing drift |
| event injection controls | entry-time event injection must match vector type, error-code validity, and guest state | returning to the guest with a plausible value but impossible event history still leaks |

Use narrow wording when the event history is incomplete:

- exception-bitmap hit without vectoring and reinjection state: possible exception intercept
- NMI-window event without blocking and unblock evidence: possible NMI-window evidence
- single-step or MTF trace without debug-state continuity: possible single-step evidence
- timer or DPC anomaly without event-history closure: latency correlation only

The sanity check is to replay the same event under a benign VMM or bare-metal control, vary interruptibility state, trigger a nested fault or debug edge, and compare the first independent observation after resume. Hypervisor stealth is less about hiding one object and more about preserving the machine's event history.

#### 2.8 Capability Negotiation and Control-Field Validity

An expert VMM does not "turn on virtualization" with a fixed constant block. It derives a legal control state from CPU-reported capability, platform policy, current ownership of VMX/SVM, and the guest mode it intends to run. The capability surface is therefore evidence. A trace that keeps only the final VMCS or VMCB values loses the reason those values were legal on that CPU.

| Capability surface | Concrete fields or instructions | What must be derived | Common failure mode |
|---|---|---|---|
| Intel fixed control-register masks | `IA32_VMX_CR0_FIXED0`, `IA32_VMX_CR0_FIXED1`, `IA32_VMX_CR4_FIXED0`, `IA32_VMX_CR4_FIXED1` | host and guest `CR0`/`CR4` values that satisfy VMX requirements without inventing impossible OS state | VM-entry fails or a guest resumes with control-register bits that cannot exist on that processor |
| Intel VMX control masks | `IA32_VMX_PINBASED_CTLS`, `IA32_VMX_PROCBASED_CTLS`, `IA32_VMX_TRUE_*_CTLS`, `IA32_VMX_EXIT_CTLS`, `IA32_VMX_ENTRY_CTLS` | allowed-0/allowed-1 normalization for pin, processor, exit, and entry controls | hardcoded control words work on one CPU family and fail on another, or expose a feature combination the CPU cannot support |
| Intel extended virtualization capability | `IA32_VMX_EPT_VPID_CAP`, secondary/tertiary execution controls, EPTP-switching capability, #VE, PML, mode-based execute, sub-page permission, guest-paging verification | the actual EPT/VPID and exit-suppression feature set available to this logical processor | treating "Intel EPT" as one uniform feature and misclassifying newer violation bits or unsupported permission modes |
| Intel VMCS lifecycle | VMXON region revision ID, VMCS revision ID, current-VMCS pointer, `VMPTRLD`, `VMCLEAR`, `VMLAUNCH`, `VMRESUME` | per-logical-processor ownership, launch state, and whether the VMCS is current, active, launched, or clear | cross-core VMCS reuse, stale launch state, or a handler that calls `VMRESUME` on a VMCS that never launched |
| AMD SVM feature discovery | `CPUID Fn8000_000A`, `EFER.SVME`, VMCB intercept fields, nested-paging support, `NRIPS`, decode assists, `VmcbClean`, `FlushByAsid`, `TscRateMsr` | which SVM accelerations are architectural on this CPU and which fields can be trusted on exit | translating an AMD trace into Intel labels and silently dropping SVM-only constraints |
| AMD VMCB caching behavior | VMCB clean bits, `TLB_CONTROL`, `ASID`, `N_CR3`, MSRPM/IOPM physical bases | which VMCB groups hardware may cache and which changes require clean-bit clearing or TLB action | modifying a VMCB field while leaving its clean bit set, producing core-dependent or run-dependent behavior |
| AMD invalidation model | `INVLPGA`, `INVLPGB`, `TLBSYNC`, ASID recycling, `FlushByAsid` behavior | whether stale guest or nested translations survive a view change | either stale memory views after a split-view change or over-flushing that creates timing evidence |
| Hyper-V/VSM platform story | TLFS synthetic MSRs, VTL state, VSM partition/VP status, MBEC, VTL memory protections | whether a system already has a legitimate hypervisor and higher-VTL memory policy | a hidden VMM creates a second, incoherent virtualization story instead of fitting the platform owner |

Preserve the raw feature leaves, capability MSRs, computed control values, VM-entry error fields, VM-exit reason, exit qualification, per-core VMCS or VMCB identity, and the invalidation action that made the next run legal. The invariant is simple: if a control bit is set, the trace should explain which capability made it legal and which guest-visible behavior required it.

The same failure pattern shows up on both vendors even when the field names differ:

- a VMCS control word is shown without the capability MSR that made it legal
- a VMCB field is updated without explaining clean bits, ASID, and TLB currentness
- a nested or enlightened field is shown without naming the L0/L1/L2 owner
- a CPUID feature bit is advertised but never tied to a successful transition

The sanity check is capability subtraction. Replay the same guest mode on a nearby CPU or nested owner with one capability absent. The conclusion should narrow from "control active" to "control requested" or "capability advertised" instead of silently preserving stronger wording.

#### 2.9 VMX/SVM Transition-State Closure

Field names become useful only when they are tied to a transition. A VMCS dump, a VMCB dump, or a nested structure can show configured policy, but it does not prove that the processor used that policy on the next guest run.

The practical question is narrower: did the control object become current, were its fields legal for that CPU and nested owner, did entry use the expected state, did exit produce native evidence, and did the handler make the next run coherent?

This is the bridge from control-state language into process-memory, timing, interrupt, endpoint-equivalence, or behavior language:

| Transition evidence | Intel VMX evidence | AMD SVM evidence | Nested Hyper-V evidence | Broken implementation it catches | Careful wording before evidence is complete |
|---|---|---|---|---|---|
| control-object identity | VMXON region revision, VMCS revision, current-VMCS pointer, `VMPTRLD`, `VMCLEAR`, launch state, logical processor | `VMRUN` `RAX` system-physical VMCB address, VMCB physical-page identity, host-save area relation | enlightened VMCS GPA, VP assist page active eVMCS field, enlightened VMCB reserved area, `VmId`, `VpId` | treating a copied control page as the active control object, cross-core reuse, stale launch state | possible control object |
| capability legalizer | `IA32_FEATURE_CONTROL`, fixed `CR0`/`CR4` masks, `IA32_VMX_*_CTLS`, `IA32_VMX_EPT_VPID_CAP`, secondary/tertiary controls | `CPUID Fn8000_000A`, `EFER.SVME`, SVM feature bits, `VmcbClean`, `FlushByAsid`, `NRIPS`, decode-assist support | TLFS CPUID leaves `0x40000006`, `0x40000009`, `0x4000000A`, eVMCS version, direct virtual flush and enlightened TLB bits | hardcoded control words, Intel-only feature assumptions, unsupported nested feature exposure | possible legal control |
| entry input state | guest/host CRs, RIP/RSP/RFLAGS, segment/access-right fields, VM-entry controls, VM-entry MSR-load list, entry interruption-info field | VMCB control area, save-state area, `EVENTINJ`, guest `EFER`, `RIP/RSP/RFLAGS`, segment state | eVMCS/eVMCB fields plus clean-field mask that decides whether L0 reloads memory | entry consumes stale or impossible guest/host state; injected event is incompatible with guest state | possible entry state |
| native transition result | `CF`/`ZF`, `VMfailInvalid`, `VMfailValid`, VM-instruction error field, VM-entry failure class, VM-exit reason, exit qualification, IDT-vectoring and interruption fields | `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `EXITINTINFO`, `nRIP`, decode-assist fields where valid, updated save-state | synthetic exit reason, nested VM-exit delivery, direct-flush synthetic exit when partition assist state requires it | collapsing instruction failure, entry failure, synthetic exit, and ordinary VM-exit into one "exit" label | possible native transition |
| coherence and currentness action | `INVEPT`, `INVVPID`, EPTP, VPID, MTF restore edge, interruptibility update, old/new VMCS fields | `TLB_CONTROL`, ASID, `N_CR3`, `INVLPGA`, `INVLPGB`, `TLBSYNC`, VMCB clean-bit clear, old/new VMCB fields | eVMCS `CleanFields`, enlightened VMCB clean bit 31, direct virtual flush hypercall fields, partition assist page | table or field change never reaches executing hardware; stale virtual TLB survives nested context | possible coherent transition |
| external bridge | CR3/PCID or ASID epoch, Windows region/read relation, ETW or ISR/DPC witness, engine tick/frame, endpoint comparator | same, plus AMD-native ASID/`N_CR3` and NPF payload retention | nested L0/L1/L2 owner, guest-visible TLFS feature state, hosted endpoint comparator | later bytes, interrupts, or behavior are used to fill a missing transition step | external bridge still needed |

The wording rule is strict:

- "VMX controls show EPT monitoring" means only that monitoring was configured unless the trace also shows the current VMCS, legal controls, VM-entry result, native exit payload, and invalidation action.
- "AMD VMCB has NPT enabled" means only that NPT was configured unless `VMRUN`, `EXITCODE` or `EXITINFO*`, ASID, `N_CR3`, clean-bit state, and TLB action are connected.
- "Nested Hyper-V exposed enlightened VMCS" means only that nested virtualization metadata exists unless TLFS feature leaves, VP assist/eVMCS identity, clean-field state, synthetic or native exit, and virtual-TLB ownership are named.

The rule is used-control evidence. A control object matters when the processor or nested owner actually used it across a legal transition and produced a replayable native result.

Without that bridge, plausible VMCS/VMCB-like pages, copied enlightened structures, or stale clean-field state are only memory observations. The useful defensive evidence is the transition edge that binds identity, legality, native payload, currentness action, and post-entry behavior.

The sanity check is control-object substitution. Keep the same dump and sentence, then replace the active object with a copied, stale, or wrong-core object. If the sentence does not narrow, it was reading memory decoration rather than transition state.

## Next

Next, the series moves from control-state ownership into the real memory primitive: EPT/NPT. The focus becomes second-stage translation as an evidence-producing state machine, not just a convenient way to hide or reveal pages.

## References

- Intel, Intel 64 and IA-32 Architectures Software Developer's Manual: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- AMD, AMD64 Architecture Programmer's Manual Volume 2, System Programming, Rev. 3.44: https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2
- Microsoft, Hyper-V Top-Level Functional Specification: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
- Microsoft, Virtualization-based Security overview for OEMs: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs
- Microsoft, Enable virtualization-based protection of code integrity: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
