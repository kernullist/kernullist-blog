---
title: "About Hypervisor Cheats, Part 2: EPT/NPT, Split Views, and Second-Stage Fault Evidence"
date: 2026-06-29 00:00:00 +0900
categories: [Windows Internals, Anti-Cheat]
tags: [hypervisor, ept, npt, memory, anti-cheat, virtualization, windows]
---

> Second-stage translation is where hypervisor cheat discussions often become either too mystical or too shallow. EPT and NPT are page tables below the guest page tables, but the important point is ownership: they decide the final memory view that Windows runs on. This post explains that view through permissions, backing pages, faults, invalidations, and stale translations.

## Scope

This part follows EPT/NPT entries, access roles, split views, large-page narrowing, memory types, TLB and invalidation range, EPT violations, EPT misconfigurations, AMD nested page faults, and the limits that prevent a byte sample from being overstated as game knowledge.

---

### 3. EPT/NPT: The Core Memory Primitive

EPT/NPT is the reason hypervisor cheats are more than "kernel drivers with a different name." Windows still owns its ordinary page tables, but the hypervisor owns a second translation layer underneath them. That second layer can decide whether a guest physical page is readable, writable, executable, redirected, or temporarily faulted.

The important idea is simple:

```text
guest virtual address
  -> guest page tables selected by CR3
  -> guest physical address
  -> EPT/NPT table controlled by hypervisor
  -> host physical address
```

The rest of the post keeps that chain separated. A second-stage event can show that a GPA crossed a hypervisor-owned policy boundary. It does not automatically show that a Windows process exposed the same bytes, that the bytes were a live game object, or that the player acted on them.

Use this simpler evidence ladder while reading:

| Evidence reached | What can be said | What is still not established |
|---|---|---|
| CPU capability | the processor supports the feature | the endpoint is using it now |
| active EPTP or `N_CR3` | a second-stage view exists for this guest run | a game object was read |
| EPT/NPT entry or fault | a GPA was mapped, denied, redirected, or faulted | Windows would see the same bytes |
| invalidation and cross-core check | the changed view became current for the covered CPUs | every observer or device saw it |
| Windows page-state join | the bytes can be compared to a process-memory view | the bytes are meaningful to the game |
| engine and delivery join | the information may affect player-visible behavior | full causality or enforcement certainty |

The common mistake is capability inflation. "This CPU supports EPT" is not the same as "a hidden hook ran." "An EPT violation happened" is not the same as "the game object was read." Each step needs its own evidence.

#### 3.2 Translation Structures

EPT and NPT are both second-stage translation systems. The important reading habit is to keep the guest translation and the nested translation separate. A careful sentence should name the first-stage root, the second-stage root, page size, permissions, memory type, invalidation epoch, and the observer that actually read the bytes.

```text
guest virtual address
  -> guest CR3 selects guest paging hierarchy
  -> guest page-table walk produces guest physical address
  -> EPTP or nCR3 selects nested paging hierarchy
  -> nested walk produces host/system physical address
```

On Intel EPT, the nested paging hierarchy uses EPT paging-structure entries. On AMD NPT, the nested hierarchy is selected through nCR3 and resembles the normal x86-64 paging model more closely. In both cases, the hypervisor controls the second-stage view, but the native root, leaf format, invalidation tag, and fault payload remain different evidence owners.

Key translation properties should be read as owner boundaries rather than address-conversion trivia:

- A guest virtual address is meaningful only under the correct guest CR3.
- A guest physical address is not necessarily the real machine physical address that DRAM sees.
- A guest page-table inspection can look normal while EPT/NPT redirects the second-stage mapping.
- A single guest physical page can have multiple guest virtual aliases.
- A single logical game object can cross page boundaries or move while being read.
- With five-level paging or different guest modes, address canonicality and walk depth can vary.

Translation should therefore be written as a chain of responsibility:

```text
first-stage owner
  -> first-stage walk result
  -> second-stage owner
  -> second-stage walk result
  -> observer path
  -> invalidation epoch
  -> semantic consumer
```

No owner should be silently substituted.

- The guest OS owns process roots and PTE semantics.
- The hypervisor owns EPTP or `N_CR3` selection and second-stage permissions.
- The CPU owns combined-translation caching and fault payload rules.
- Devices may own a separate IOTLB or address-translation cache.
- The game engine owns whether the resulting bytes mean a live object.

The attacker benefits from gaps between those owners. A lower observer can collect bytes without producing the same API visibility that Windows would have produced.

The defensive clue is non-equivalence between paths: a CPU read sees one frame, a device path still has a stale translation, or a Windows region query says the range is no longer the same committed object. The minimum cross-check is substitution: change one root, cache, page size, memory type, or game epoch and verify which part of the sentence is still true.

This is why VMI memory acquisition needs both OS context and paging context. Raw physical reads are not enough to recover stable game semantics because CR3 ownership, Windows page state, residency, object generation, and disclosure authority can all change while the same physical bytes remain readable.

##### 3.2.1 Walk Product and Ownership

A translation result is not one value. It is the result of several owners agreeing at the same moment: the Windows address space, the guest page-table walk, the EPT/NPT walk, the cache state, and the observer that captured the bytes.

| Walk item | Owner | Evidence | What goes wrong |
|---|---|---|---|
| process address-space root | guest OS scheduler and memory manager | CR3/DTB, PCID/ASID, process generation, vCPU/thread epoch | stale or substituted process context |
| guest paging product | guest page-table hierarchy | PML5/PML4/PDPTE/PDE/PTE path, present/large/NX/U/S/RW bits, software states | non-resident, transition, copy-on-write, or wrong-mode page |
| nested root | hypervisor control state | EPTP or nCR3, nested-paging enable state, VMCS/VMCB epoch | wrong nested view or owner not established |
| nested paging product | EPT/NPT hierarchy | nested-entry path, permission, memory type, page size, A/D state where supported | stale combined translation or malformed mapping |
| final byte range | memory subsystem or device path | CPU reread, host physical range, DMA/IOMMU route, cacheability evidence | CPU/device view mismatch or torn multi-page read |

The practical rule is to name where the chain stops. A guest page-table walk without EPT/NPT context is only a guest translation. An EPT/NPT walk without a process epoch is only a second-stage physical mapping. A byte range without observer and invalidation context is only a byte sample.

The strongest supportable statement is often narrower than the tempting one. "This address would translate to this backing range under these roots" is defensible. "The game object was current and visible to the player" needs object lifetime, game tick, and delivery evidence.

##### 3.2.2 Alias and Epoch Consistency

Second-stage translation creates alias problems that normal process-memory language hides. The same guest physical page can be reached through more than one virtual address, more than one EPT/NPT view, or more than one observer path. A game object can also span multiple pages that were not sampled at the same time.

That creates a simple failure mode: the analysis accidentally mixes two moments or two routes and calls the result "memory." Examples:

- current CR3 with an old object root
- clean guest page tables with a stale EPTP
- CPU-visible bytes treated as equivalent to a DMA-visible route
- a two-page structure assembled across a map transition

For a blog-level conclusion, keep the check simple. If changing one owner changes the result, the sentence must narrow to that owner. If flushing the CPU-side translation changes the answer, the original sentence was about CPU currentness. If a device route sees a different view, the original sentence was not a global memory truth. If a game object moved between reads, the original sentence was not a current object.

#### 3.3 EPT Entry Semantics

An EPT entry is more than an address. The CPU reads it as a compound second-stage rule: which access types are legal, which host physical page backs the GPA, which memory type applies, whether a large mapping is being narrowed, whether accessed/dirty updates are enabled, and whether special delivery modes such as virtualization exceptions can alter reporting. Exact bit layout depends on CPU capabilities, but the categories below are stable enough to prevent a page-base observation from being overstated as a memory-view or game-authority conclusion.

| EPT entry category | Meaning | Why it matters |
|---|---|---|
| Read/write/execute permissions | Controls which guest accesses are allowed by second-stage translation | Enables execute-only, read traps, write traps, and split views |
| Physical page base | Selects the host physical page backing a guest physical page | Enables shadow pages and redirection |
| Memory type | Defines caching behavior for the mapped memory | Wrong type can cause severe performance or correctness anomalies |
| Large-page bit | Allows larger mappings at higher levels | Splitting large pages changes TLB behavior |
| Accessed/dirty information | Hardware may trace whether a page was accessed or written | Useful for monitoring, but changes page-table state and behavior |
| Suppress or virtualization-exception related controls where supported | Alters how selected EPT events are reported | Relevant to nested or defensive hypervisor designs |

EPT permissions are independent from guest page-table permissions. A guest page may be readable according to the guest PTE but fail because EPT read permission is absent. Conversely, a guest PTE can fault before EPT permissions matter. This ordering is important for interpreting faults and timing because the native payload names different owners: a first-stage fault is guest paging and Windows memory-manager evidence, while an EPT violation is second-stage policy evidence. A report that collapses both into "memory access failed" loses the data path, fault priority, and simple check.

Intel's EPT state also has an important root-level object: the **EPT pointer**, or EPTP. The EPTP selects the EPT paging-structure root and also carries attributes that influence the second-stage walk. The EPTP is therefore an authority root, not a cosmetic field: an entry hash, exit qualification, or page-base sample cannot be compared across views unless the EPTP, walk length, paging-structure memory type, VPID context, and invalidation action are retained.

| Intel EPT field or capability | Manual-level role | Why it matters |
|---|---|---|
| EPTP memory type | Defines the memory type used for EPT paging-structure references. | A strange or inconsistent type can create performance and coherency anomalies. |
| EPT page-walk length | Encodes the walk depth, usually matching a four-level or five-level EPT hierarchy depending on capability. | A telemetry schema should not assume a fixed EPT walk depth on future systems. |
| Accessed/dirty enable | Allows hardware to update A/D state for EPT entries where supported. | Useful for monitoring but changes page-table write behavior and invalidation requirements. |
| EPTP list and VMFUNC EPTP switching | Lets configured VM functions switch among EPTP values without a VM exit where supported. | Can reduce exits in split-view designs, but creates a distinct EPTP-list and VMFUNC capability surface. |
| EPT violation qualification | Traces read/write/execute, whether the access was during a guest page walk, and related permission facts. | Defensive analysis should classify the access mode and walk context, not only count violations. |
| EPT misconfiguration | Reports invalid EPT entry encodings or unsupported memory/type combinations. | Misconfiguration is usually an implementation bug or malformed state, not a normal stealth mechanism. |
| INVEPT type support | Single-context and all-context invalidation capabilities are reported by CPU capability state. | Remap-heavy designs need correct invalidation granularity to avoid stale views or unnecessary global flushes. |

One source-level correction matters here: EPT `R/W/X` bits are not a free-form alphabet where every tuple is an equally valid watchpoint policy. Some shapes are invalid or capability-dependent. A write-enabled EPT entry without read permission should be treated as malformed or unsupported before it is treated as a useful write trap. Execute-only EPT needs the processor's execute-only EPT capability before `X=1, R=0` can be treated as intentional. If a trace treats every permission tuple as a stealth design choice, it can turn an EPT misconfiguration into a false hidden-hook story.

| EPT permission shape | Careful interpretation before more evidence |
|---|---|
| `W=1` while `R=0` | malformed or unsupported EPT entry until capability state and VM-exit class say otherwise |
| `X=1` while `R=0` | execute-only policy only when execute-only EPT support is present; otherwise treat it as capability or misconfiguration triage |
| legal leaf, denied access, EPT violation payload retained | configured second-stage policy |
| reserved bit, unsupported memory type, or illegal tuple | EPT misconfiguration, not a normal permission trap |

For Intel, the practical model is an EPTP-rooted evidence chain rather than a generic "EPT hook" label. The active EPTP is the root of the authority statement; the leaf entry is only one row inside that root's paging-structure epoch, and an exit payload is only meaningful when it is tied back to that root, the pre-access entry state, and the invalidation action that made the processor consume the new entry:

```text
VMCS EPTP field
  -> EPT paging-structure hierarchy
  -> EPT entry permissions, memory type, A/D behavior, and physical page base
  -> EPT violation or misconfiguration evidence
  -> INVEPT/VPID lifecycle when mappings change
```

Common ways this gets overstated:

| Failure class | What it means | Safer wording |
|---|---|---|
| EPTP root is missing | A leaf entry is shown without the active EPTP and walk-depth context. | second-stage-looking row |
| native payload is missing | Read/write/execute result is discussed without exit qualification and guest-walk context. | access anomaly |
| memory type is ignored | The report ignores EPT memory type, IPAT, large-page state, or A/D updates. | page-base observation only |
| misconfiguration is confused with violation | Invalid encodings are treated as ordinary permission traps. | malformed second-stage state |
| invalidation is missing | A changed leaf is assumed current without INVEPT/VPID/core-range evidence. | stale-view possibility |

Minimum cross-check: leaf replay under root swap. Reconstruct the same GPA under the recorded EPTP, then replay the walk with a different EPTP or stale leaf snapshot. If the conclusion does not change, the report is probably not using EPT semantics and should be narrowed to a page-base observation.

#### 3.4 NPT Entry Semantics

AMD NPT provides the same strategic capability as EPT, but it should not be described as an Intel-shaped feature with different names. The second-stage root is carried through VMCB `N_CR3`, permission and memory-type results are consumed during `VMRUN` execution, ASID and TLB-control decisions define the freshness epoch, and nested page faults report AMD-native payloads through `EXITCODE` and `EXITINFO` fields. The defensive category is still second-stage translation authority, but the evidence owner is VMCB/NPT/SVM, not VMCS/EPT/VMX.

| NPT concept | Meaning | Why it matters |
|---|---|---|
| nCR3 | Root of nested page tables | Equivalent strategic role to EPTP |
| Nested page permissions | Restrict access after guest translation | Enables trapping and redirection at the second stage |
| Nested page fault | Exit class for nested translation failure or permission failure | AMD-side counterpart to EPT violation-style analysis |
| ASID | Tags address-space translations | Improves performance but complicates stale-translation handling |
| TLB control | Requests flushing behavior across VMRUN boundaries | Incorrect use causes stale mappings or excessive flushes |

AMD's nested paging behavior is controlled through the VMCB instead of a VMCS EPTP field. When `NP_ENABLE` is set, `VMRUN` loads `N_CR3` as the nested paging root, and guest physical addresses are translated through the nested page tables before becoming system physical addresses. On exit, AMD's manual notes that guest paging state is written back to the VMCB while `nCR3` itself is not saved back as a guest-updated value.

| AMD NPT field or behavior | Manual-level role | Why it matters |
|---|---|---|
| `NP_ENABLE` | Enables nested paging for the guest run. | Without it, there is no NPT second-stage translation for that guest execution. |
| `N_CR3` / `nCR3` | Selects the nested paging root used while the guest is running. | AMD-side root-of-trust for second-stage mapping. |
| Host paging dependency | Nested paging is allowed only when host paging is enabled. | Invalid combinations lead to invalid exits instead of normal guest execution. |
| Guest PAT interaction | Guest PAT state is loaded from the VMCB when nested paging is active. | Memory-type consistency matters for both correctness and detection. |
| Nested page fault information | Reports nested translation or permission failures. | Needs access type and address context to distinguish watchpoint, stale mapping, and malformed state. |
| `INVLPGA`, `INVLPGB`, `TLBSYNC` where supported | AMD-side invalidation and TLB synchronization mechanisms. | ASID-tagged stale-view control is vendor-specific and should not be modeled as Intel `INVEPT` only. |

For cross-vendor anti-cheat telemetry, the correct abstraction is not "EPT detected" or "NPT detected." The correct abstraction is a replayable second-stage authority tuple:

```text
second-stage translation root
  + permission policy
  + invalidation behavior
  + violation/fault reporting
  + per-vCPU consistency
```

##### 3.4.1 AMD NPT Walk Model

NPT is AMD's second-stage translation path. With nested paging enabled, the guest still owns its normal page tables and CR3, but the resulting guest physical address is not the final system physical address.

The processor translates it again through the nested tables selected by `N_CR3` in the VMCB for that `VMRUN` epoch. This makes `N_CR3` the AMD-side view root, but it is not enough by itself.

A high-quality NPT row must also name whether `NP_ENABLE` was active, which ASID tagged the translation, which TLB-control action retired stale translations, which guest PAT or memory-type state participated, and which nested page fault payload was preserved if the walk failed.

```text
guest virtual address
  -> guest CR3 and guest page tables
  -> guest physical address
  -> N_CR3-selected nested page tables
  -> system physical address
```

Minimum cross-check: choose a GVA whose guest page-table walk is stable, then change only one AMD-native variable at a time: `NP_ENABLE`, `N_CR3`, ASID, TLB-control action, nested leaf permission, and memory-type state. Trace the guest walk result, nested walk result, NPF exit payload, CPU reread result, and re-entry action. If the row cannot show the active VMCB and `N_CR3`, say only that an AMD nested view may be involved. If the NPF payload was flattened into Intel EPT terminology, say only that a normalized fault was reported. If the bytes are not joined to process-memory semantics, stop at second-stage memory evidence.

##### 3.4.2 AMD Nested Page Fault Reporting

AMD reports nested-paging failures as `#VMEXIT(NPF)`, with `EXITCODE = VMEXIT_NPF`. In the AMD APM, `EXITINFO1` contains the page-fault-style error code and `EXITINFO2` contains the guest physical address that caused the fault.

The important AMD-specific distinction is the role of `EXITINFO1[33:32]`, which separates final-GPA translation evidence from guest-page-table-walk evidence:

| EXITINFO1 bit | AMD meaning | Why it matters |
|---|---|---|
| bit 32 | NPF occurred while translating the guest's final physical address. | Treat it like the final target-page side of Intel EPT violation analysis. |
| bit 33 | NPF occurred while translating guest page tables. | Treat it as a page-walk or address-space-tracking event, not necessarily game-data access. |
| bit 37 | Shadow-stack related NPT condition where supported. | Modern security features can affect NPF interpretation. |

The AMD NPF payload should stay attached to the VMCB epoch that produced it. Lower fault-code-style bits describe conditions such as present/not-present, write/read, user/supervisor, reserved-bit, instruction-fetch, and shadow-stack cases where supported.

AMD also treats nested table walks for guest page tables differently from final data accesses. A trace that only says "NPF happened" is therefore weak. It lost the access class, the page-walk/final-address distinction, and the VMCB epoch needed for a stronger statement.

Do not translate this too quickly into "AMD EPT violation." The carrier fields, invalidation vocabulary, VMCB caching rules, and ASID semantics are different. A defensible statement says whether the NPF came from:

- final nested translation
- nested translation of a guest paging-structure access
- a protection feature interaction
- a CPU- or implementation-specific caveat

An NPF row has authority over the VMCB epoch, `N_CR3`, ASID, `EXITINFO1`, `EXITINFO2`, and the nested leaf state that produced the exit. It does not automatically have authority over a Windows process, an engine object, or a player decision.

The minimum cross-check is role inversion. Keep the same faulting GPA, then force one path where the fault comes from final data translation and one path where it comes from guest page-table walking. If the report cannot separate those roles, it is not ready to describe process-memory observation.

##### 3.4.3 AMD Attribute Combination Rules

AMD combines guest and nested attributes, but each attribute family has a different owner.

AMD's rule is specific. Guest writability requires both guest and nested write permission. Guest `gCR0.WP` changes only guest page-table interpretation and cannot override a nested read-only mapping. Host `hCR0.WP` is ignored for nested-paging permission.

Execution also requires both guest and nested execution permission, with guest and host `EFER.NXE` controlling whether NX is meaningful at each layer. Global state is guest-owned and scoped by ASID. User accessibility requires a guest user mapping, but the nested entry must also mark the page user to allow guest access.

| Attribute question | AMD analysis point |
|---|---|
| Is the guest PTE writable? | Not sufficient. The nested entry can still make the effective page read-only. |
| Is the guest PTE executable? | Not sufficient. Nested NX and guest NX behavior both matter. |
| Is the page user or supervisor? | Guest and nested U/S meaning combine, and GMET-capable systems can change execution interpretation. |
| Is the page global? | Global is a guest-level concept and scoped by ASID. |
| What memory type applies? | Guest PAT, host PAT, nested and guest PTE PCD/PWT/PATi, CR3 PCD/PWT, MTRR state on system physical addresses, and `gCR0.CD`/`hCR0.CD` all influence the final behavior. |

The memory-type side is easy to overstate. With nested paging enabled, AMD constructs the eventual TLB entry from both guest and nested memory-type inputs.

There is no hardware guest-MTRR state. A VMM that wants guest-MTRR-like behavior has to simulate it by changing nested mappings or effective memory types. MTRRs apply to system physical addresses, not to guest physical names.

So a below-OS trace that sees a guest physical address and a cacheability symptom does not automatically know the cause. It could be guest PAT, host PAT, nested PCD/PWT/PATi, MTRR state, `CD`, stale translation, or device-visible ordering.

For attack analysis, this is the AMD version of the split-view problem. The guest can inspect its page tables and see one story, while nested translation enforces another. The useful attack surface is not only read/write/execute denial; it is divergence between:

- guest page-table state
- nested permission state
- memory-type state
- TLB lifetime

That divergence can support page traps, clean-view scans, write suppression, execute-only views, cacheability deception, or stale-view windows. The exact evidence is AMD-specific: `N_CR3`, `EXITINFO1`, `EXITINFO2`, ASID, TLB-control state, `INVLPGA` or related invalidation evidence, VMCB clean-bit behavior, guest and host PAT epochs, and feature state such as GMET or supervisor shadow-stack handling.

The bridge runs from guest virtual intent, through guest page-table data, through nested page-table data, into a system-physical access and finally into a TLB entry with a timing lifetime. The data path is incomplete if any owner is skipped: guest PTE bytes alone are guest evidence, nested leaf bytes alone are second-stage evidence, and a cacheability symptom alone is timing evidence. Only the joined bridge lets the paragraph talk about an effective AMD guest memory attribute.

The rule is effective-attribute consistency across layers. A writable, executable, user, global, or cacheability statement is valid only when the guest layer, nested layer, processor feature state, and translation lifetime all support the same wording.

Common mistakes are:

- treating `gCR0.WP` as if it could bypass nested read-only state
- assuming host `CR0.WP` participates in nested permission
- treating guest global as host-global
- forgetting ASID scope
- inventing hardware guest-MTRR state
- missing GMET because it must be inferred from effective NX/U/S and fault code
- replaying a result after the TLB entry or nested leaf has changed

The minimum cross-check changes one owner at a time: guest PTE write bit, nested write bit, guest NX, nested NX, guest U/S, nested U/S, guest PAT, host PAT, `N_CR3`, ASID, and invalidation epoch. If the conclusion survives every change without changing its wording, it is probably describing a slogan rather than the AMD attribute combination.

#### 3.5 Split-View State Machine

A common public model, also visible in EPT hook documentation such as HyperDbg, is read/execute separation. The important point is not merely that two byte copies exist. The useful conclusion is per-observer: which access type, vCPU, translation root, backing page, invalidation epoch, and re-entry action produced which view.

```text
normal state:
  code page maps to clean physical page

execute attempt:
  EPT execute violation
  hypervisor maps execute view to modified shadow page
  guest executes selected instruction range under a bounded vCPU and invalidation epoch

read or scan attempt:
  EPT read violation or mapping switch
  hypervisor presents clean page to the classified read observer

restore:
  mapping returns to default or per-vCPU temporary state
```

The important part is not that two byte copies exist. The important part is which observer received which copy, and whether the temporary switch was correctly restored.

| Transition | Invariant | Attacker leverage | Defender observable | Failure mode |
|---|---|---|---|---|
| default to execute | execute permission and shadow backing must match the faulting instruction epoch | expose modified execution while hiding bytes from simple reads | EPT/NPF payload, RIP window, MTF or re-arm timing, stale execute translation | wrong instruction window or wrong vCPU receives the execute view |
| execute to read | clean backing must be served only to the observer and epoch being stated | return clean bytes to scanners or integrity checks | read/execute path mismatch, invalidation scope, page hash, observer identity | clean page leaks to execution or shadow page leaks to read |
| transient to restored | rollback must retire stale translations on the affected CPUs | keep the modified window short | INVEPT/INVVPID/ASID flush evidence, cross-core reread, timer tail | stale TLB or paging-structure cache keeps an old view |
| per-vCPU to global | local view changes must not be reported as global state | reduce synchronization cost | cross-core disagreement, NMI/APIC timing, scheduler migration evidence | another core observes an impossible mixture of views |

This is conceptually simple but operationally hard. The hypervisor must handle stale TLB entries, cross-core execution, memory type consistency, instruction-cache effects, and timing evidence. A split-view finding is therefore not "hidden bytes exist." It is "the same guest physical page produced different views for different observers, under a replayable transition."

##### 3.5.1 View Identity and Transition Ownership

The phrase "split view" hides several distinct questions. A clear explanation should answer them directly:

| State | View owner | Required evidence | Failure mode |
|---|---|---|---|
| default view | nested translation root | EPTP/nCR3, leaf entry, memory type, page size | default view not actually clean or current |
| execute view | per-vCPU or global nested policy | execute permission, shadow backing, RIP range, instruction boundary | shadow executes on wrong core or wrong instruction window |
| read/scan view | scanner-facing nested policy | read permission, clean backing, observer identity, scan epoch | clean view served to the wrong observer or stale scanner epoch |
| transition view | handler and invalidation path | exit reason, qualification/NPF info, TLB invalidation, MTF/single-step if used | stale translation or temporary mapping without a clear range |
| rollback view | restore policy | old/new leaf, affected vCPU set, CPU reread, event reinjection state | restore races with another core or event delivery |

Use this short checklist:

1. Which observer was classified: execute, read, scanner, debugger, host, DMA, or another vCPU?
2. Which backing page did that observer receive?
3. Which EPT/NPT root and leaf produced the view?
4. Which invalidation or re-entry step made the view current?
5. Was the temporary view restored before another observer could see it?

This prevents a common ambiguity: a view can be correct for one observer and wrong for another. An execute view can be legal for the game thread while a concurrent scanner, DMA reader, debugger, crash-dump path, or second vCPU sees a different story.

##### 3.5.2 Failure Modes That Matter More Than the Diagram

The simple diagram implies a clean alternation between execute and read. Real systems are messier. Two vCPUs may touch the same guest physical page at the same time. A scanner may run on one core while execution happens on another. A page can contain mixed code and data. A handler may need to preserve pending events, debug state, branch-tracing state, and timing plausibility. Instruction-cache and data-cache behavior can also disagree with the intended story if memory type or aliasing is mishandled.

The dangerous failure classes are the ones that leave cross-layer contradictions rather than immediate crashes:

- per-vCPU disagreement: one core still executes or scans through a stale translation
- pending-event loss: an interrupt, exception, or debug condition is delivered under the wrong view
- memory-type disagreement: the access succeeds, but timing or cacheability no longer matches the clean story
- mixed code/data pages: permission toggling becomes visible to unrelated reads
- large-page splitting: the local page neighborhood changes and can create timing or A/D-bit evidence
- nested virtualization: the visible EPT/NPT transition may belong to the outer owner, not the layer under analysis

For defense, the useful observation is a contradiction between bounded observers: execute-only code whose read view does not match later control flow, page-neighborhood timing changes around a large-page split, per-core disagreement after a mapping flip, or replay behavior that depends on information unavailable through the clean view. That is a view-consistency problem first. It becomes a game-object or player-advantage statement only after the process, object, and delivery path are connected.

##### 3.5.3 Minimum cross-check

The practical cross-check is observer permutation. Run the same page through read, execute, cross-core execute, scanner-like read, debugger or host read, and DMA where available. A mature explanation should narrow if it cannot say which observer saw which backing page, which permission transition happened, which translation root was active, and which invalidation made the transition current.

Moving beyond a split-view observation requires two joins. First, the native translation evidence must replay: same EPTP or `N_CR3`, same VPID or ASID epoch, same access class, same backing-page identity, and coherent re-entry. Second, the game bridge must replay: the view difference must reach a process address, game object, render/input/capture path, or server/replay behavior. If either join is missing, keep the wording at split-view evidence.

#### 3.6 EPT Violation, Misconfiguration, and Nested Page Faults

Intel distinguishes an EPT violation from an EPT misconfiguration, and a high-quality paragraph must keep that split until the native payload has been decoded. A permission denial, an invalid second-stage entry, and an AMD NPF evidence set are different events with different recovery paths, different failure modes, and different limits.

| Event | Meaning | Example defensive interpretation |
|---|---|---|
| EPT violation | The nested translation exists, but access permissions or related policy do not allow the attempted access | Expected if a page is intentionally marked non-readable, non-writable, or non-executable |
| EPT misconfiguration | The CPU encountered an invalid or unsupported EPT paging-structure entry while translating | Suggests a broken or malformed EPT entry, not a normal watchpoint |
| Nested page fault on AMD | Nested translation or permission failure under NPT | AMD-side event to classify with exit information and access type |

For analysis, exit qualification is the native carrier for the second-stage access statement. The qualification evidence should preserve whether the access was read, write, execute, whether it involved a page walk, which guest linear and guest physical address were reported, and whether guest page-table permissions also allowed the access. Without those fields, the careful wording is only "untyped second-stage event" because a deliberate permission watch, a page-walk effect, a malformed entry, and a stale translation can otherwise look identical.

EPT misconfiguration has a different meaning from EPT violation because it is not a stealth feature. It is usually an error, unsupported bit pattern, or invalid memory-type/page-entry combination. A production hypervisor treats it as a correctness failure, not as a normal control path.

Repeated misconfiguration-like behavior is therefore a stability and implementation-quality observable. It is not evidence of a hidden hook unless the handler, recovery, and view-transition evidence are joined.

The vendor taxonomy is stricter than the casual wording. Intel EPT violation means a configured EPT translation or policy disallowed the access. Intel EPT misconfiguration means the processor encountered an EPT paging-structure entry that is invalid, reserved, or unsupported for translation.

The same guest-visible symptom can therefore have different native owners. AMD NPF is not an Intel EPT violation with renamed fields. The native owner is SVM exit state: `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `N_CR3`, ASID, guest state, and the final-page versus guest-page-table classification carried by AMD's NPF payload.

A high-quality paragraph keeps those native classes separate before it says "memory fault."

Use this simpler order before turning any second-stage event into a higher-level statement:

```text
native event class
  -> vendor-native payload
  -> malformed state or policy failure
  -> access and address validity
  -> first-stage context
  -> second-stage root and leaf epoch
  -> handler action and invalidation
  -> replay or observer comparison
  -> game bridge
  -> strongest safe statement
```

The rule is native-class consistency: an EPT violation, an EPT misconfiguration, and an AMD NPF may all interrupt guest progress, but they do not mean the same thing. A lower layer can use policy failures as a timing or data-acquisition trigger while trying to avoid malformed-state evidence. The useful defensive clue is disagreement between native class, leaf state, address-validity bits, handler action, invalidation epoch, and replay result.

The lifecycle is the ordered path from fault class, native payload, root and leaf epoch, handler mutation, invalidation, replay, and game bridge. If any phase is reconstructed only from a later repaired state, the paragraph must stay below process-memory or gameplay wording.

Dominant failure modes are violation/misconfiguration collapse, Intel-shaped interpretation of AMD NPF, GLA overuse, final-page/page-walk confusion, stale EPTP or `N_CR3`, handler-created sample contamination, and treating a repaired post-exit table as the pre-access table. The minimum cross-check is to keep the suspected GPA constant while changing one owner: convert violation to misconfiguration, remove GLA validity, flip final-page into page-walk context, change EPTP or `N_CR3`, replay with stale VPID/ASID state, or remove the handler mutation trace. If the sentence still names the same process object or game fact, it is overstated.

##### 3.6.1 EPT Fault Anatomy

People often say "EPT fault" informally, but the terminology matters. Intel's precise terms are **EPT violation** and **EPT misconfiguration**. AMD uses nested-page-fault terminology for the NPT side. A sentence that does not preserve this distinction collapses policy violation, invalid entry encoding, and AMD-native NPF payload into one vague label. Until the native event class is named, call it only a possible second-stage fault.

An EPT violation is a permission or policy event in the second-stage walk. The guest may believe a page is present and readable because its own PTE allows it, but the processor still has to translate the resulting guest physical address through EPT. If the EPT entry blocks that access, VMX root receives a VM exit with address and qualification state. The same is true when the processor is walking the guest's own page tables: the page-table entries live in guest-physical memory, so their accesses are also mediated by EPT.

| EPT structure or field | Technical role | Attack/analysis meaning |
|---|---|---|
| EPTP | VMCS field selecting the EPT root plus EPT walk attributes | Identifies the active second-stage view. EPTP changes are a strong clue for whole-view switching. |
| EPT paging-structure entries | PML5E/PML4E/PDPTE/PDE/PTE-style hierarchy, depending on capability and page size | Maps guest physical pages to host/system physical pages and carries access policy. |
| R/W/X permission bits | Second-stage read, write, and execute policy | The core lever for read traps, write traps, execute traps, execute-only views, and split views. |
| Memory type and IPAT-like behavior | Cacheability and memory-type behavior for translated pages | Wrong types create performance and coherency anomalies that can be more visible than bytes. |
| Large-page bit | Lets an upper-level entry map a large page | Splitting a large page to trap 4 KB subpages changes TLB and performance behavior. |
| Accessed/dirty support | Lets hardware update EPT A/D state where supported | Useful for telemetry, but it can add write-like behavior to paging structures and changes invalidation expectations. |
| Suppress-VE / #VE-related controls where supported | Can route selected EPT events to virtualization exceptions instead of normal exits | Changes where evidence appears and complicates nested or defensive hypervisor analysis. |
| Sub-page permission and newer capability bits | Capability-dependent finer-grained controls | Do not assume every Intel endpoint has the same EPT surface. Capability state must be recorded. |
| INVEPT lifecycle | Invalidates cached EPT-derived translations | Mapping changes without matching invalidation create stale views; over-invalidation creates timing noise. |

An EPT event therefore has two meanings at once. It is a memory access event, and it is also a statement about the active second-stage view. Analysts should ask which EPTP, which vCPU, which access type, which guest physical page, and which guest context produced the event. An access type without EPTP, leaf state, invalidation epoch, and guest context is only a partial event. An EPTP or leaf sample without the native payload is only a partial view.

##### 3.6.2 Exit Qualification: What the EPT Violation Tells You

The exit reason alone is too weak. The useful signal is the exit reason plus exit qualification, guest physical address, optional guest linear address, guest RIP, vCPU identity, and timing preserved inside the same transition epoch.

A qualification bit is not object identity. It decodes which translation, fetch, or data path produced the second-stage fault.

The attacker's advantage is ambiguity. A read trap, page-walk effect, and execute-view switch can all be described as an "EPT fault" unless the payload is decoded. The defensive clue is where GLA validity, translated-linear-address indication, first-stage permission, and access type stop matching the stated game object.

| Qualification category | What it tells the handler | Why it matters for attack analysis |
|---|---|---|
| access type | whether the triggering access was read, write, instruction fetch, or a combination reported by the processor | Separates scanner reads, game writes, code execution, and page-walk effects. |
| EPT permission facts | whether the EPT entry was readable, writable, or executable for the attempted access | Shows whether the event was caused by an intentional trap, a missing mapping, or a bad view transition. |
| guest-linear-address validity | whether a guest linear address is meaningful for the event | Some EPT violations happen during guest page walks; not every event maps cleanly back to a user-mode pointer. |
| translated-linear-address indicator | whether the guest linear translation completed before the EPT violation | Distinguishes a violation on the final target page from a violation while accessing guest paging structures. |
| guest page-table permission facts | whether guest paging allowed read/write/execute at the first stage | Helps separate normal guest #PF-like behavior from second-stage interference. |
| guest physical address | the GPA that hit the EPT policy | The stable anchor for second-stage mapping analysis. |
| guest RIP and instruction context | where the guest was executing when the event happened | Needed to classify scanner, game thread, kernel path, page walker, or anti-cheat probe context. |

A common analysis mistake is to treat all EPT violations as equivalent. They are not. A read violation against a final game-data page, a write violation caused by guest page-table A/D-bit behavior, and an execute violation on a shadowed code page are different events even though all share the same broad exit class. The qualification field is therefore a payload decoder, not an object label.

Read the event in this order:

```text
exit reason
  -> access type and EPT permission facts
  -> GLA validity and translation shape
  -> final page or page-walk classification
  -> EPTP, VPID, CR3, and PCID epoch
  -> instruction and event context
  -> invalidation and replay epoch
  -> process or game bridge
  -> strongest safe statement
```

The steps mean:

- the exit reason says only that the CPU left guest execution because of an EPT violation
- the access and permission fields separate read, write, execute, and EPT-side permission facts
- GLA validity decides whether a guest linear address can be used at all
- final-page versus page-walk classification prevents guest page-table maintenance from being mislabeled as game-data access
- EPTP, VPID, CR3, and PCID epoch tie the event to translation roots
- instruction and event context attach RIP, instruction assist, interruptibility, and event history
- invalidation and replay context checks that stale TLB, VPID, EPTP, or cross-core state did not make the row a previous view

Only after the process or game bridge is joined should the report discuss process object, engine object, or gameplay implications.

The stable rule is that an EPT violation payload names a translation boundary, not a semantic target. Its strongest native evidence is the tuple `(exit reason, qualification bits, GPA, optional valid GLA, EPTP, VPID, CR3/PCID, vCPU, event/instruction context, invalidation epoch)`. AMD NPF has a different native tuple: `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `N_CR3`, ASID, guest CR3, and the `EXITINFO1[32:33]` final-versus-guest-page-table classification. Cross-vendor normalization is valid only after each native tuple has kept its own root, address-validity, and replay context.

The dominant failure modes are GLA overuse, page-walk/final-page confusion, stale root identity, unaccounted VPID or ASID reuse, cross-core invalidation gaps, event-context loss, and processor-feature or erratum-sensitive bit interpretation. Each failure mode lowers the row from semantic evidence to narrower translation evidence.

Minimum cross-check: hold the GPA constant and change one owner at a time. Clear the GLA-valid bit, flip final access into page-walk access, move the same GPA under a different EPTP or `N_CR3`, reuse the VPID/ASID without invalidation context, convert the event to an AMD NPF with `EXITINFO1[32]` or `[33]`, or replay the same event after changing guest CR3/PCID. If the sentence still says the same process-memory or game-object fact, it is overstated. The careful wording is the first step that still survives.

##### 3.6.2.1 Intel EPT Violation Qualification Bit Map

The Intel EPT violation qualification field is compact, but it carries enough information to separate final data accesses, instruction fetches, page-walk accesses, guest-paging verification, and newer security-feature interactions. Do not collapse it into "read/write/execute."

| Bit or range | Intel meaning | Expert interpretation |
|---|---|---|
| bit 0 | the access causing the violation was a data read | may be a real guest load, an implicit read, or part of a page-walk or A/D update path |
| bit 1 | the access causing the violation was a data write | may be a guest store, a hardware A/D update, or another write-like paging-structure effect |
| bit 2 | the access causing the violation was an instruction fetch | the event is tied to execution authority, not ordinary data observation |
| bit 3 | the EPT entry for the GPA allowed read access | describes the second-stage permission fact, not the guest PTE permission |
| bit 4 | the EPT entry for the GPA allowed write access | useful for distinguishing an intentional write trap from a missing or malformed view |
| bit 5 | the EPT entry for the GPA allowed execute access | if clear on an execute event, this is a second-stage execute policy decision |
| bit 6 | if mode-based execute control is active, EPT allowed execute for user-mode linear addresses | separates user-mode execute authority from supervisor execute authority on capable systems |
| bit 7 | the guest-linear-address field is valid | only then can the GLA be used as process-address evidence |
| bit 8 | when bit 7 is set, indicates a translated final linear access rather than a guest page-walk access | one of the key bits for telling target-page traps from traps on guest paging structures |
| bit 9 | advanced exit information indicates the guest linear access was user mode | helps separate user-mode game accesses from supervisor paging or kernel probes |
| bit 10 | advanced exit information reports guest paging read/write classification | captures first-stage access semantics that are distinct from EPT permissions |
| bit 11 | advanced exit information reports guest paging executable classification | connects first-stage NX/executable state to the second-stage violation |
| bit 12 | the violation was associated with NMI unblocking due to IRET | event-history information, not a memory-object identifier |
| bit 13 | the access was to a shadow stack | CET and shadow-stack state can create events that resemble hook activity if the schema is too small |
| bit 14 | supervisor shadow-stack related EPT information where supported | modern control-flow protection changes the interpretation of execute/data policy events |
| bit 15 | guest-paging verification information where supported | points at hardware verification of first-stage paging rather than ordinary game-data access |
| bit 16 | asynchronous access not caused by direct instruction execution or event delivery where supported | tracing features can produce EPT events outside the simple "RIP touched page" model |

Bits 0-2 are not mutually exclusive in every interpretation that matters to an analyst. Hardware updates to accessed/dirty state during paging can look read-like and write-like, and Intel documents cases where page-walk effects matter. Bits 3-6 describe EPT-side permissions. Bits 7-11 decide whether the guest linear address and guest paging classification are safe to use for process-memory reconstruction. Bits 13-16 are a warning: modern platform features can create EPT telemetry that is not a simple "RIP touched page" event.

##### 3.6.2.2 Intel Low-Exit EPT Telemetry and Exception-Routing Surfaces

EPT analysis should not assume that every useful event appears as a simple VM exit. Intel exposes capability-conditioned surfaces that can reduce exits, move evidence into the guest, or trace delayed page state. These features are useful to analysts because they show how a VMM can observe memory pressure without trapping every access. They also lower conclusion portability because each depends on VMX controls, capability MSRs, VMCS fields, EPT leaf state, and processor generation.

| Surface | Control or field family | What it can support | What it cannot support alone | Evidence to retain |
|---|---|---|---|---|
| EPT accessed/dirty state | EPTP A/D enable plus EPT leaf accessed and dirty fields where supported | a guest-physical page was accessed or dirtied under one EPTP and sampling epoch | which instruction, thread, game object, or semantic field mattered | EPTP, leaf version, GPA range, A/D enable state, sampling time, invalidation state, cross-core reread |
| PML | PML enable, PML address, PML index, dirty-page logging behavior | a page became dirty and was logged through the hardware-maintained PML path | that the write was malicious, current, game-semantic, or tied to a player action | PML address, index before/after, logged GPA set, EPTP, vCPU/core, dirty-bit relation, overflow/full-buffer handling |
| EPT-violation #VE | EPT-violation #VE control, virtualization-exception information area, EPT leaf suppress-VE state | selected EPT violations may be reported as guest-visible virtualization exceptions instead of ordinary VM exits | stealth, semantic correctness, or absence of root exits for all related accesses | #VE enable state, VE information GPA, suppress-VE bit, guest handler identity, exception vector/timing, fallback VM-exit path |
| MBEC | mode-based execute control for EPT, execute permission for supervisor and user-mode linear addresses | user-mode and supervisor-mode execute authority can be distinguished in the second-stage policy on capable systems | that a byte sequence is a legal control-flow target under CFG/CET or game authority | capability source, EPT execute bits, exit qualification bit 6, CPL or user/supervisor classification, CFG/CET context where relevant |
| SPP | sub-page write permissions for EPT, SPP enable state, SPP page or bitmap state where present | write policy may be finer than a 4 KB EPT page on processors and VMMs that support it | broad portability, mainstream deployment, or future availability | SPP capability, enable state, affected GPA range, sub-page permission state, Intel advisory status, fallback 4 KB policy |

These surfaces are not interchangeable:

- PML is delayed dirty-page telemetry, not an access trace.
- A/D bits are coarse page-state evidence, not a typed event.
- #VE moves the evidence boundary into guest-visible exception handling, which may itself become observable.
- MBEC changes the execute-permission vocabulary; it does not replace CFG, CET, or first-stage execute checks.
- SPP needs special caution because Intel's public advisory for CVE-2024-36242 and CVE-2024-38660 tells VMMs to discontinue SPP support in virtualized environments, and Intel plans to discontinue SPP on future processors.

A report that leans on SPP must trace the exact processor, capability state, VMM support, and fallback path before making a 2026 endpoint statement. In this post, SPP should be read as a legacy and caveated field family, not as a mainstream current endpoint assumption.

The analysis rule is narrow. If a trace lacks a typed VM exit because the design used PML, A/D sampling, or #VE, the absence of exits does not mean the system is clean. The report must show the alternate evidence channel and its loss model.

If a trace says fine-grained write control came from SPP, it must also explain why Intel's discontinuation guidance does not invalidate that explanation, and why a page-level EPT policy would not explain the same observation. Low-exit telemetry becomes strong evidence only after it is tied back to address translation, process memory, game meaning, and behavior consequence.

##### 3.6.2.3 What AMD PML Can and Cannot Say

AMD's March 2026 AMD64 Page Modification Logging document adds an AMD-native dirty-page logging surface for some Zen 6 products. Do not read this as "Intel PML renamed." The analytical shape is similar because both are dirty-GPA logs tied to second-stage dirty-bit transitions, but the evidence fields are AMD fields: CPUID feature state, VMCB control bits, nested paging enablement, `N_CR3`, ASID, VMCB offsets, `#VMEXIT` status, and SEV-ES/SNP automatic-exit context.

AMD PML is a low-exit telemetry path. When enabled, a guest write that sets the Dirty bit in a nested page-table entry causes the processor to log the 4 KB-aligned guest physical address into a 4 KB PML buffer.

The buffer is selected by `PML_BASE`, and the next entry is selected by `PML_INDEX`. The index is decremented after a log entry.

The full-buffer case is important. If the index is outside the valid `0..1FFh` range, the guest write is not performed, the nested Dirty bit is not set, and the processor exits with `VMEXIT_PML_FULL` (`407h`). AMD also states that this exit does not advance guest RIP and is an automatic exit for SEV-ES and SEV-SNP guests.

That means a PML-full event is not an ordinary completed guest store. A confidential-guest context also changes what the hypervisor can directly inspect.

| AMD PML surface | Hardware behavior | Evidence to retain | What not to infer |
|---|---|---|---|
| `CPUID Fn8000_000A_ECX[PML]` bit 4 | reports processor support for AMD PML | CPU family/model/stepping, microcode, CPUID leaf, Zen generation, source revision | assuming every AMD NPT system has PML |
| VMCB offset `090h[11]` | enables Page Modification Logging on `VMRUN` when nested paging is enabled | VMCB physical page, bit value before `VMRUN`, `NP_ENABLE`, `N_CR3`, ASID, clean-bit context | treating a configured VMCB in memory as active hardware state |
| `PML_BASE` at VMCB offset `1C8h` | system physical base of the 4 KB PML buffer | base address, alignment, owner, page hash, accessibility, buffer lifecycle | treating a rendered buffer as independent memory evidence |
| `PML_INDEX` at VMCB offset `1D0h` | quadword index for the next log entry, written back on `#VMEXIT` | index before run, index after exit, expected decrement count, wrap state, reset-to-`1FFh` evidence | reading one index sample as a complete write chronology |
| nested Dirty-bit transition | PML logs when a write sets a nested page-table Dirty bit | nested leaf before/after, logged GPA, page size, A/D state, guest-page-table write classification | treating a dirty page as the exact written field or instruction |
| `VMEXIT_PML_FULL` (`407h`) | buffer-full exit when the next index is invalid; the guest write did not complete | exit code, RIP/nRIP, unadvanced-RIP evidence, handler reset, replay after refill | treating the full-buffer exit as evidence that the triggering store already happened |
| guest page-table writes | AMD notes that PML can also track writes to guest page-table entries | page-walk context, guest CR3, paging-structure GPA, final-data GPA distinction | turning page-table maintenance into game-object mutation |
| SEV-ES/SNP automatic exit | PML-full has confidential-guest exit semantics | SEV-ES/SNP active state, GHCB exposure if relevant, encrypted-state boundary | assuming ordinary SVM register visibility after the event |

Keep Intel and AMD dirty-page logs separate:

| Conclusion | Intel evidence shape | AMD evidence shape | Careful wording before more evidence |
|---|---|---|---|
| dirty GPA was logged | VMCS PML address, PML index, EPTP A/D enable, EPT Dirty transition | `PML_BASE`, `PML_INDEX`, `090h[11]`, `NP_ENABLE`, nested Dirty transition | dirty-GPA telemetry |
| guest write completed | no PML-full exit blocked the access and the Dirty bit transitioned | `PML_INDEX` was valid, `VMEXIT_PML_FULL` did not block the access, nested Dirty bit set | possible completed write |
| process page changed | dirty GPA joins to CR3/page-walk/VAD/working-set epoch | dirty GPA joins to guest CR3, ASID, NPT walk, Windows region epoch | process-memory evidence |
| game state changed | process page joins to object generation, frame/tick, replication authority, and replay evidence | same, plus AMD native NPT and ASID provenance | possible semantic mutation |

PML lowers per-write exit pressure. As evidence, it is delayed, page-granular, dirty-bit-driven, and blind to read-only information flow. A cheat analysis that says "PML saw the object update" is too broad unless it also joins the logged GPA to a final data page rather than a guest page-table page; the write completion state; the target process at that epoch; the relevant field inside the dirty page; and the authoritative object for the game frame being analyzed.

Use this checklist before turning AMD PML evidence into a process or game statement:

```text
AMD PML support is present
  and VMCB PML enable was active at VMRUN
  and nested paging was enabled
  and PML base/index can be replayed
  and logged GPA matches a nested Dirty transition
  and PML-full did not block the write
  and page-table write versus final-data write is classified
  and CR3/ASID/process epoch is joined
```

If the checklist fails, keep the conclusion narrow: "an AMD PML-capable path logged or attempted to log dirty guest-physical pages." That is still useful. It is not a typed access trace, not process-memory evidence, and not game-state authority.

##### 3.6.2.4 Confidential-VM Boundaries Change the Observer

A recent architecture trend also matters because second-stage translation is no longer only a classic host-VMM page-table story. Intel TDX and AMD SEV-SNP put extra trust boundaries around guest-private memory. They are not ordinary bare-metal game-cheat mechanisms, but they are useful cautionary examples: the same words, such as "nested fault" or "second-stage mapping," can mean different things once the observer is a TDX module, a secure EPT structure, an RMP-validated page, a GHCB-mediated exit path, or a host VMM with reduced visibility.

Intel TDX uses secure EPT state and the TDX module to separate ordinary host control from guest-private memory management. AMD SEV-SNP adds the Reverse Map Table, or RMP, so that page ownership and private/shared state participate in access validation. In both designs, a host-side fault-like event is not automatically equivalent to the classic "VMM watched a page and saw the bytes" model.

For this series, the practical lesson is simple:

| Environment | Extra boundary | Reader-friendly interpretation |
|---|---|---|
| classic EPT/NPT guest | host VMM controls the second-stage view | second-stage evidence can be joined to bytes only after root, fault payload, and currentness are retained |
| TDX-style guest | secure EPT and module-owned private-memory rules | a host observation may describe a translation or exit boundary without direct guest-private byte visibility |
| SEV-SNP-style guest | RMP ownership and private/shared page state | an NPF-like event may include access-validation or ownership state, not only NPT permission policy |
| nested or enlightened guest | L0, L1, and guest-visible flush paths can split responsibility | stale-view analysis must name which level and which virtual-TLB context was actually covered |

Do not import confidential-computing language into endpoint anti-cheat writing unless the environment really uses it. For a normal Windows gaming endpoint, TDX and SEV-SNP are mostly evidence-discipline examples, not the expected cheat substrate. Their value here is to make the observer question sharper: who was allowed to see bytes, who was allowed to change translation state, and who only saw an exit or validation boundary?

##### 3.6.3 How EPT Violations Become an Attack Primitive

An EPT violation gives the hypervisor a controlled interruption point below the guest OS. That turns page permissions into a programmable sensor and view switch, but the event is still only a second-stage fault until native payload, root identity, invalidation state, and observer context are joined. In cheat and stealth tooling, the event is usually used for one of these purposes:

| Use of the violation | What the hypervisor learns or changes | Why it is attractive | Where it breaks |
|---|---|---|---|
| access classification | which RIP, core, and context touched a watched page | Identifies scanners, game routines, page-table walkers, or anti-cheat probes without guest hooks | Hot pages create too many exits and classification can be wrong under shared code paths. |
| execute trap | that execution reached a selected page or function region | Acts like a breakpoint without a guest-visible software breakpoint byte | Instruction boundary, page granularity, and exception emulation are fragile. |
| read trap | that an observer tried to inspect a page | Lets the hypervisor decide whether to show a clean or altered view | Distinguishing anti-cheat reads from benign reads is brittle. |
| write trap | that guest logic is updating a selected page | Can observe, delay, block, or transform rare state changes | Broad data pages and high-frequency updates become noisy. |
| split-view switch | which physical page should back the same GPA for this observer | Supports clean-read/altered-execute or observer-specific data views | Per-core races, stale TLB entries, and DMA views can expose inconsistency. |
| lazy mapping | first access triggers creation or refinement of a mapping | Reduces steady-state work and avoids watching unused regions | First-touch timing and map-load bursts become visible. |
| page-walk monitoring | guest paging structures themselves become watched memory | Reveals address-space changes and page-table updates | A/D-bit behavior and OS memory-manager activity are noisy. |

The violation does not identify a process or game object by itself. The handler context still has to bind vCPU, RIP, CR3 or address-space root, guest linear address if valid, guest physical page, active EPTP, invalidation epoch, and time. Until those facts join Windows process state, object meaning, and delivery timing, the careful sentence is only that a second-stage violation occurred under a named context.


##### 3.6.4 The EPT Fault Control Loop

From an analyst's perspective, EPT-fault-based techniques follow a repeated control loop. Each loop iteration must preserve data path, timing model, lifecycle state, failure mode, observable, and minimum cross-check before the event can be described as more than a second-stage primitive:

```text
choose a page or view invariant
  -> encode pressure in EPT permissions or EPTP selection
  -> wait for a read, write, execute, or page-walk access
  -> classify the access from exit qualification and context
  -> temporarily provide the view needed for that observer
  -> restore the watched or shaped state with correct invalidation
```

The loop sounds simple. It is difficult because correctness is cross-core and time-dependent. If the hypervisor changes a mapping on one vCPU and another vCPU still has a stale translation, the wrong observer can see the wrong page. If the design uses monitor-trap-style single-step restoration, it adds ordering and timing pressure. If it uses EPTP switching, it reduces some exits but creates an EPTP-list, VMFUNC, and capability-consistency surface.

| Control-loop dependency | Why it is hard | Defensive pressure |
|---|---|---|
| page selection | a 4 KB page often contains unrelated code or data | decoy adjacency and hot-page selection increase exit noise |
| observer classification | RIP, CR3, CPL, thread, and access type can be ambiguous | cross-check observer identity through independent read paths |
| temporary view exposure | the original or altered page must be exposed at exactly the right time | concurrent readers, DMA, and physical hashes can catch mismatches |
| invalidation | EPT-derived translations survive permission and page-base changes | stale views or excessive INVEPT activity create timing evidence |
| large-page splitting | a narrow target may require splitting a 2 MB mapping | TLB and performance shifts become visible even with clean bytes |
| memory type correctness | EPT memory type must match the real backing range | cache and MMIO anomalies leak below content-level checks |
| SMP coordination | all logical processors must agree on the active view | per-core sampling can reveal drift |

This is the core reason EPT-based stealth is powerful but brittle. It moves control below the guest OS, but it also forces the attacker to preserve memory truth across access type, core, time, cache behavior, and observer identity. If byte identity, permission identity, cache identity, and event history do not survive observer permutation, the strongest safe conclusion is a transient second-stage view rather than a durable stealth mechanism.

##### 3.6.5 AMD NPF Anatomy Compared with Intel EPT Violation

Intel and AMD expose similar strategic power but different forensic surfaces because the root object, fault payload, and invalidation owner are vendor-specific. A reader should preserve the native payload first, then normalize only after the EPTP or `N_CR3`, access bits, page-walk role, ASID/VPID, and invalidation epoch are replayable.

| Analysis dimension | Intel EPT | AMD NPT/SVM |
|---|---|---|
| second-stage root | EPTP in VMCS | `N_CR3` in VMCB |
| event name | EPT violation or EPT misconfiguration | `#VMEXIT(NPF)` for nested page fault |
| event code | VM-exit reason plus EPT-specific qualification | `EXITCODE = VMEXIT_NPF` |
| access details | EPT violation exit qualification | page-fault-style `EXITINFO1` |
| fault address | guest physical address VMCS field, optional guest linear address | `EXITINFO2` carries the faulting guest physical address |
| page-walk distinction | EPT qualification indicates page-walk/final-translation context | `EXITINFO1[32]` and `[33]` distinguish final GPA walk from guest page-table walk |
| invalidation vocabulary | `INVEPT`, `INVVPID`, VPID | `INVLPGA`, `INVLPGB`, `TLBSYNC`, ASID, `TLB_CONTROL` |
| state-cache hazard | VMCS field consistency and per-core VMCS state | VMCB clean bits and per-logical-processor cached state |

Do not translate AMD NPF into "EPT violation" and stop there. Preserve the vendor-native payload first: `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `N_CR3`, ASID, guest CR3, access classification, and final-page versus guest-page-table classification. If those fields are absent, the safe wording is only "normalized second-stage fault," not process-memory evidence.

A normalized comparison should preserve vendor identity until the final statement. A readable checklist is:

```text
vendor-native payload
  -> Intel EPT qualification or AMD EXITINFO
  -> native fault address fields
  -> native entry owner
access class
  -> final guest-physical access
  -> guest page-walk access
  -> instruction fetch or execute
  -> write or Dirty-bit update
  -> reserved or misconfigured entry
ownership class
  -> guest CR3 or ASID epoch
  -> EPTP or N_CR3 epoch
  -> invalidation epoch
  -> VMCS or VMCB cache epoch
safe statement
  -> translation fault only
  -> address-space tracking evidence
  -> data-watch evidence
  -> possible semantic advantage
```

This normal form prevents a common portability bug in analysis. Intel EPT violation qualification, Intel EPT misconfiguration, AMD NPF `EXITINFO1`, AMD `VMEXIT_INVALID`, and ordinary guest page faults are not interchangeable. They may all occur near a watched page, but each has a different owner, payload, and repair path. A cross-vendor document can compare them only after the native payload and ownership epochs are preserved.

The rule is native-payload preservation. Cross-vendor normalization is useful for teaching or dashboards, but the retained evidence must keep the fields that decide ownership:

- Intel EPT qualification and GPA/GLA validity
- AMD `EXITINFO1/2`
- VMCS/VMCB cache epoch
- EPTP or `N_CR3`
- VPID or ASID
- invalidation action

The attacker's advantage is ambiguity collapse. If a report erases vendor-native fields, a page-walk event can look like final data access, a misconfiguration can look like a violation, and stale cached control state can hide behind normalized labels.

The minimum cross-check is native replay. Derive the normalized row twice, once from raw Intel fields and once from raw AMD fields. Both derivations should preserve the same ownership class before any process or game-semantic sentence is written.

##### 3.6.6 What a Fault Pattern Needs

The fault-pattern tables name useful mechanism shapes, but they are not evidence by themselves. Each pattern has to be rewritten into the trace-field checklist in section 3.13 before it can support a process-memory, semantic-object, gameplay, delivery, or endpoint-equivalence sentence. A label such as "read fault," "execute fault," or "NPF" is only an index into the trace store until the native payload and handler transition survive replay.

| Example shape | Minimum native evidence to retain | Handler and currentness evidence | Do not go further until | Careful wording |
|---|---|---|---|---|
| access classification | Intel VM-exit reason, EPT violation qualification, GPA, GLA-valid bit, guest RIP, CPL, EPTP, VPID, vCPU; or AMD `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `nRIP`, ASID, `N_CR3` | classifier inputs before mutation, observer rule, target root, page role, and untouched raw row | CR3 or ASID epoch, first-stage replay, Windows page-state join, route effects, and semantic owner are joined | access-classification evidence |
| execute trap | attempted-instruction-fetch bit, effective leaf execute state, instruction boundary, original and shadow physical backing identity | MTF or equivalent restore edge, old/new leaf, RIP before/after, event injection state, cross-core stale-translation probe | executed bytes, backing page, restoration, and re-arm are replayed under the same root and core set | execute-fault transition evidence |
| read trap or clean-view exposure | attempted-read bit, GLA relation, pre-access EPT/NPT leaf, original and served backing page hashes | view-selection rule, served-view identity, invalidation or no-invalidation rationale, independent read-path comparison | the served view is tied to an observer, a route, Windows read behavior or declared non-equivalence, and a contradiction test | read-view evidence |
| write trap or state shaper | attempted-write bit, old leaf, dirty/A-D/PML distinction, faulting GPA, writer RIP or decode-assist context | handler action as observe, allow, transform, deny, emulate, or delay; new leaf, data delta, retry/advance decision | the write is shown completed or blocked, currentness is closed, and the changed byte range joins a process/page/semantic epoch | write-fault evidence |
| split view or EPTP switch | EPTP or `N_CR3` identity, EPTP-list or root-selection state, VMFUNC/control eligibility, old/new leaf chain | per-vCPU root generation, target core set, invalidation range, view owner, physical hash pair | every observer route either sees the intended view or is declared out of range with evidence | view-switch evidence |
| page-walk monitoring | Intel GLA-valid/final-GPA-versus-page-walk bits, guest CR3, paging-structure GPA, walk level; or AMD `EXITINFO1[32]`, `EXITINFO1[33]`, `EXITINFO2` | page role classifier, A/D effect classification, page-table leaf before/after, OS memory-manager clock | the row separates guest paging-structure access from final data access and binds it to a process address-space epoch | paging-structure evidence |
| AMD NPF variant | `EXITCODE = VMEXIT_NPF`, `EXITINFO1` page-fault-style bits and high bits, `EXITINFO2`, `N_CR3`, ASID, `nRIP`, relevant VMCB clean state | `TLB_CONTROL` or invalidation action, nested leaf mutation, decode-assist state when used, event-continuity fields | AMD-native replay establishes final-page versus page-table role, stale-ASID risk, clean-bit currentness, and Windows/semantic joins | AMD NPF evidence |
| low-exit telemetry such as PML, #VE, or A/D sampling | PML buffer/index or #VE information path, EPT A/D enablement, suppress-VE state, leaf A/D transition, GPA and root | loss model, delayed-log window, exception-routing owner, page role, correlation to a later native fault or independent read | the telemetry is joined to a root, loss budget, event epoch, Windows page-state clock, and stated semantic object | low-exit telemetry evidence |

Use this checklist before a fault example is described as more than a local second-stage event, because every higher conclusion needs currentness, Windows, semantic, and delivery evidence:

```text
native payload retained
  and translation root bound
  and pre-access leaf replayable
  and handler transition replayable
  and currentness action witnessed
  and post-resume or re-arm witnessed
  and Windows view or declared non-equivalence joined
  and semantic bridge named if stated
```

The rewrite rule is simple. Do not write "EPT read fault detected a scanner." Write "A read-qualified EPT violation occurred under EPTP X, with native payload Y, pre-access leaf Z, served-view identity W, and an unresolved process or game join." Do not write "NPF shows hidden object access." Write "An AMD NPF reached GPA X under `N_CR3` Y and ASID Z; object meaning still needs Windows page-state and engine semantic replay." The first form borrows authority from words. The second form says exactly what is known and what is still missing.

#### 3.7 Invalidation, VPID, ASID, and Stale Views

Changing an EPT/NPT entry is not enough because the executing hardware may be using cached products rather than the bytes just written to a paging structure. The cache hierarchy includes guest translations, second-stage translations, combined translations, paging-structure-cache state, VPID/ASID-tagged entries, and in some mixed device paths, IOTLB or device-ATC state. A stale-view conclusion therefore has to name the cache owner, invalidation primitive, completion witness, and core or vCPU epoch before it can explain execution or scan behavior.

Intel stale-view analysis should name the mechanism, cache owner, and invalidation scope for each of these mechanisms. The important question is not whether an instruction mnemonic appears in a trace; it is which cached product the instruction can invalidate, which context tags remain valid afterward, and which core or vCPU observed completion:

- **INVEPT:** Invalidates cached translations derived from EPT under a specified scope. It can support an EPT-currentness conclusion only when the EPTP context, invalidation type, operand, affected cores, and post-invalidation probe are named.
- **INVVPID:** Invalidates translations associated with virtual processor identifiers. It is a guest-translation tag boundary, not evidence that a second-stage remap, Windows process epoch, or game object changed.
- **VPID:** Reduces TLB flush cost by tagging guest translations. It improves steady-state performance but creates lifecycle work: VPID reuse, guest CR3/PCID changes, nested owner changes, and stale combined translations must be separated before a trace can conclude a coherent view.

AMD stale-view analysis should keep ASID ownership, VMRUN timing, and supported invalidation instructions separate. An ASID is a translation-cache tag under an SVM epoch, not a process identity, and a cached translation remains suspect until the VMCB owner, TLB_CONTROL action, INVLPGA/INVLPGB/TLBSYNC path, and post-VMRUN evidence are joined:

- **ASID:** Tags guest translations under an SVM epoch. It is not a process identity and not a semantic object label; reuse and owner changes require explicit stale-translation counter-checks.
- **TLB_CONTROL:** Requests TLB handling associated with `VMRUN` and VMCB state. Its meaning depends on processor support, requested scope, clean-bit state, and whether a post-`VMRUN` probe shows that the old view stopped being consumed.

The engineering tradeoff is correctness versus observability. Narrow invalidation keeps the steady-state path quieter but raises the chance that one observer still sees the old mapping. Broad invalidation simplifies correctness but can create latency, TLB-pressure, or shootdown patterns that correlate with match phases, scanner probes, or hot pages:

| Strategy | Benefit | Cost |
|---|---|---|
| Flush broadly | Simpler correctness | high overhead and timing noise |
| Flush narrowly | Better performance | easy to miss stale translations |
| Use VPID/ASID aggressively | lower steady-state overhead | harder lifecycle and reuse correctness |
| Avoid frequent mapping changes | less invalidation pressure | weaker stealth or lower event fidelity |

Split-view designs are particularly sensitive to stale translations. If one core executes the modified mapping while another core reads through a stale executable mapping, the clean-view story breaks. If the hypervisor over-flushes to avoid that race, it may create timing evidence.

##### 3.7.1 AMD ASID and Broadcast Invalidation

AMD stale-view analysis needs a different evidence set from Intel EPT analysis. `N_CR3` names the nested paging root, `ASID` tags guest translations, `TLB_CONTROL` requests selected flush behavior on `VMRUN`, `INVLPGA` targets a guest virtual address and ASID, and `INVLPGB` plus `TLBSYNC` add a broader invalidation and completion vocabulary on supported processors. A report that says only "NPT entry changed" has not shown when the executing hardware stopped using the old translation.

| Evidence item | AMD evidence | Failure it catches | Careful wording if absent |
|---|---|---|---|
| ASID ownership | ASID value, vCPU/core, guest identity, process or address-space epoch, old owner, new owner | ASID reuse carries stale first-stage or nested translations across guest contexts | possible address-space tag |
| nested root identity | `NP_ENABLE`, old and new `N_CR3`, nested entry chain, large-page state, memory type | a trace assumes the current VMCB memory image was the hardware's active nested root | possible nested root |
| VMCB clean state | clean-bit mask before `VMRUN`, modified groups, especially `ASID`, `NP`, `CRx`, `TPR`, and `AVIC` | hardware may legally use cached VMCB state that software forgot to mark dirty | VMCB-memory snapshot only |
| VMRUN flush request | `TLB_CONTROL` value, `FlushByAsid` support, expected flush range, prior ASID lifetime | a scoped flush is stated on a processor or mode that does not support the requested range | local flush request only |
| address-scoped invalidation | `INVLPGA` address and ASID, issuing core, target guest linear address, reason | a nested GPA or `N_CR3` change is incorrectly treated as solved by a guest-linear invalidation | first-stage invalidation only |
| broadcast invalidation | `INVLPGB` use where supported, invalidation class, ASID or range metadata, participating cores | one core observes the new view while another core retains the old cached translation | partial-core coherence |
| completion barrier | `TLBSYNC` after broadcast invalidation where required, timestamp, core set, post-sync probe | broadcast invalidation is assumed complete before hardware has completed the operation | pending invalidation |
| cross-core counter-check | reread or execute probe on another core, physical hash, nested walk reread, NPF replay | table state and hardware state diverge after the stated invalidation | single-core observation |

This context should be attached to every AMD split-view or NPT-permission statement that changes `N_CR3`, nested entries, ASID ownership, or clean-bit state. `INVLPGA` evidence is useful, but it should not be overstated as evidence that every nested translation changed on every core. `INVLPGB` evidence is stronger only when processor support, range, and `TLBSYNC` completion are present. `TLB_CONTROL` evidence is useful only when paired with the `VMRUN` boundary and the feature bits that make the requested flush range legal.

The stable rule is simple: a VMCB or nested page-table write is not a hardware-view change until the trace shows that the state was loaded, the relevant clean bits allowed reloading, and cached translations were invalidated or made irrelevant. Without that closure, the strongest honest conclusion is local table mutation, not coherent guest execution under a new view.

##### 3.7.2 Feature-Gated AMD Invalidation

`INVLPGB` and `TLBSYNC` should not be treated as a generic "better flush." AMD exposes three separate control surfaces: instruction support, guest execution control, and intercept policy. The APM also ties ordinary VMCB flush requests to the `VMRUN` boundary through `TLB_CONTROL`. A trace that collapses those surfaces into "AMD flushed the TLB" loses the field that decides whether the next guest instruction can rely on the new view.

| Field or operation | AMD behavior | Evidence to retain | What not to infer |
|---|---|---|---|
| `CPUID Fn8000_000A:EBX` | reports the number of ASIDs supported by the processor | CPUID value, maximum ASID, ASID allocator state, old/new owner | using ASID values without showing they are legal or uniquely owned |
| VMCB offset `058h[31:0]` | guest ASID loaded for the guest context | VMCB physical page, ASID value, vCPU/core, guest/process epoch | treating a memory copy of the VMCB as active hardware state |
| VMCB offset `058h[39:32]` `TLB_CONTROL` | `00h` does nothing, `01h` flushes the entire TLB on `VMRUN`, `03h` flushes this guest's entries, `07h` flushes this guest's non-global entries; other encodings are reserved | exact encoding, `VMRUN` epoch, processor support context, expected scope | stating a scoped flush without showing the `VMRUN` boundary and legal encoding |
| `INVLPGA` | invalidates entries for a guest linear address and ASID | virtual address, ASID, issuing core, target context, reason | treating it as evidence that an NPT root or every nested mapping changed |
| `INVLPGB` | invalidates a specified range locally and broadcasts invalidation to remote processors | instruction support, range/class parameters, ASID or PCID context where applicable, issuing core, target core set | treating local table mutation as cross-core hardware-view coherence |
| `TLBSYNC` | synchronizes completion of broadcast invalidation where the feature is used | issued instruction, timestamp, core set, post-sync probe | assuming broadcast completion before synchronization or evidence |
| EFER `TCE` bit 15 | changes how `INVLPG`, `INVLPGB`, and `INVPCID` remove cached upper-level paging entries | EFER value on issuing processor, TCE support, paging hierarchy touched | assuming invalidation removes unrelated upper-level entries in both TCE modes |
| VMCB vector 5 bit 0 | intercept all `INVLPGB` instructions | intercept setting, guest RIP, exit payload, action | treating a guest's attempted invalidation as completed |
| VMCB vector 5 bit 1 | intercept only illegally specified `INVLPGB` instructions | illegal-form evidence, exit code, emulation decision | treating illegal-form interception as a normal flush event |
| VMCB vector 5 bit 4 | intercept `TLBSYNC`; presence is indicated by `CPUID Fn8000_000A:EDX[24]` | feature bit, intercept bit, `VMEXIT_TLBSYNC` trace | assuming the hypervisor could observe synchronization on processors without the control |
| VMCB offset `090h[7]` | enables guest execution of `INVLPGB/TLBSYNC`; when zero, the instructions produce `#UD` in guests covered by the control | CPUID feature state, bit value, SEV-ES exception rule, guest result | stating guest-controlled broadcast invalidation when the guest would fault |
| exit codes `A0h`, `A1h`, `A4h` | identify `VMEXIT_INVLPGB`, illegal `INVLPGB`, and `VMEXIT_TLBSYNC` | `EXITCODE`, `EXITINFO` validity, guest RIP/NRIP, instruction bytes | normalizing the event into a generic instruction intercept |

The analysis sequence should be strict so an observed AMD invalidation instruction, intercept, or VMCB field cannot be overstated before feature, legality, completion, and cross-core evidence agree:

```text
feature present
  -> guest execution enabled or intercepted
  -> operation issued with legal parameters
  -> TCE mode understood
  -> broadcast completion synchronized
  -> cross-core view probed
  -> NPT or ASID conclusion strengthened
```

This sequence closes a common AMD-specific gap. A VMM can set `TLB_CONTROL=03h` and still fail to establish a cross-core view change if the relevant transition happened outside the next `VMRUN`. A guest can execute `INVLPGB` and still fail to establish completion if `TLBSYNC` is missing or intercepted. An analyst can see `VMEXIT_INVLPGB` and still fail to establish invalidation if the exit was caused by the intercept policy rather than completed hardware action. The field-level conclusion should therefore name the exact path: VMCB-flush-on-`VMRUN`, guest-issued broadcast invalidation, intercepted invalidation, illegal invalidation, or synchronized broadcast completion.

Nested Hyper-V adds another owner to this analysis. A guest-visible ASID flush or a visible AMD invalidation instruction is not automatically evidence that the L0-owned nested physical view was retired.

Hyper-V's enlightened TLB and direct virtual flush vocabulary can split the evidence into an L1-visible virtual-address flush, a guest-physical-address-space flush, a VP set, a synthetic completion path, and an L0 second-stage owner.

In AMD nested paths, keep first-stage ASID invalidation, NPT-derived translation currentness, and Hyper-V direct-flush completion as separate facts. A trace should name the hypercall or synthetic route, the virtual or guest-physical address-space identifier, the VP set, the L0/L1/L2 owner, and the post-flush probe before saying stale NPT-derived translations were retired.

#### 3.8 Page Granularity and Large Pages

EPT/NPT permissions are page-granular. A single 4 KB page may contain unrelated variables or instructions. If the page is hot, trapping it creates too many exits. If the guest uses a 2 MB large page and the hypervisor splits it into 4 KB pages, TLB behavior changes. The practical rule is semantic containment: the trapped page, sibling range, page-size transition, memory type, invalidation epoch, and target object lifetime must all be named before a page event can become an object event.

The research question is therefore not whether a page was touched. It is whether the observed page event can be narrowed from a translation-granularity fact to a semantic-object fact without losing neighboring-object, cacheability, invalidation, and cross-core context. Large-page narrowing, selective 4 KB trapping, and shadow-page substitution all change the locality around the target. A serious analysis traces the page shape before and after the event, the sibling range affected by the policy change, and the first missing bridge that prevents an object-level sentence.

The page-size boundary is concrete at the architecture level.

Intel EPT distinguishes 1 GB EPT PDPTE leaves, 2 MB EPT PDE leaves, and 4 KB EPT PTE leaves. Bit 7 is the leaf-versus-next-level discriminator for large mappings, and processor capability controls whether some large-page forms are legal.

The final leaf also carries permission, memory-type, A/D, #VE, shadow-stack, paging-verification, and sub-page-write-related state where supported. Splitting a large leaf is therefore not just "more entries." It changes which architectural fields can differ across the 512 child leaves.

AMD NPT analysis has the same research shape even when the field names differ. Preserve page size, guest/NPT root, ASID, memory type, A/D or dirty-log behavior, and the effect of MTRR/PAT or platform range constraints. AMD's memory-type guidance around large pages spanning incompatible MTRR ranges is a useful caution: a broad mapping can hide a heterogeneous neighborhood, while a split mapping can expose it.

Use this order before treating a page-granular event as object evidence:

```text
page-size capability
  -> pre-event page shape
  -> target byte or field range
  -> sibling range and false-neighbor set
  -> post-event leaf set
  -> memory type and access policy continuity
  -> invalidation and cross-core epoch
  -> observer route comparison
  -> semantic containment
  -> strongest safe statement
```

The practical design rule for defensive analysis is to treat page-granular evidence as a broad physical observation until the report demonstrates semantic containment. A 4 KB trap can implicate a cache line, an unrelated field, a compiler-adjacent object, a page-table walk, an allocator neighbor, a guard page, or a false neighbor inside the same narrowed large-page region. A strong analysis therefore asks whether the observed page event is joined to a current game object, a render frame, an input/action window, and a server or replay consequence.

The split consistency rule has three parts:

- Shape: the parent large page, child leaf set, guest page shape, and semantic object range agree.
- Policy: every child leaf carries the intended read/write/execute, memory-type, A/D, mode-based execute, and optional sub-page policy without accidentally changing unrelated neighbors.
- Epoch: the current VPID/ASID, EPTP/N_CR3, invalidation completion, and remote-core visibility agree with the observation.

If a report names only the leaf that faulted, it has a fault row. If it names the parent/child transition and invalidation epoch, it has a split transition. If it also names semantic containment and replay consequence, it can begin arguing game relevance.

| Analysis question | Required bridge | Failure mode | Safer wording |
|---|---|---|---|
| Did the split change only the intended neighborhood? | parent large-page identity, child leaf list, memory type, and permission diff | adjacent object receives a different policy | split-neighborhood contamination |
| Did every observer see the same shape? | INVEPT/INVVPID or AMD invalidation range, affected CPUs, VPID/ASID, EPTP/N_CR3 epoch | one core keeps the parent mapping while another sees children | split-epoch divergence |
| Did the event represent object access? | GVA/GPA, access class, guest page-table walk status, object lifetime, allocator state | page-walk or unrelated field is treated as object activity | semantic containment missing |
| Did device or DMA visibility agree? | IOMMU domain, requester/PASID if relevant, device IOTLB/ATC invalidation, CPU reread comparator | CPU path and device path observe different bytes or epochs | CPU/device view mismatch |
| Did the cost model remain plausible? | exit rate, TLB pressure, remote shootdown cost, frame/tick correlation, handler tail | split churn creates clustered latency or frame pacing evidence | split-cost evidence |


Minimum cross-check: create a lab mapping with one parent large page, split only one child leaf, and run matched read/write/execute probes from two pinned cores plus a device or IOMMU comparator when available.

Change one variable at a time: memory type, execute permission, A/D policy, VPID/ASID, EPTP/N_CR3, remote invalidation timing, and object lifetime.

Then narrow the wording:

- if the event persists after the semantic object is moved to another child leaf, call it page-neighborhood evidence
- if a remote core or device path sees a different epoch, call it split-epoch or CPU/device mismatch evidence
- if only frame or tick correlation remains, call it split-cost evidence

##### 3.8.3 Page-Neighborhood Causal Model

Page granularity should be read as a neighborhood problem, not as a point problem. The smallest semantic target may be a flag, a pointer, a transform component, a vtable pointer, or one instruction. The smallest second-stage policy unit may be a 4 KB leaf.

The original nested mapping may have been a 2 MB or 1 GB large page. The performance effect may cover a TLB set, a page-walk-cache entry, a sibling 4 KB leaf, or a hot allocator page that contains unrelated objects.

The gameplay effect, if any, may occur several ticks later after an object graph, render frame, delivery path, and input decision have moved on.

Use this causal model before treating a page event as object evidence. The failure modes are stable across vendor terminology because they are caused by page shape, hotness, observer route, and lifecycle currentness rather than by the word EPT or NPT:

| Failure mode | What happened | Why the conclusion is too strong | Safer wording |
|---|---|---|---|
| target-neighborhood inflation | one field or instruction caused a whole page to be watched | the event may belong to another field, function, or object in the same page | page-neighborhood evidence |
| sibling-leaf effect | demoting a large page changed adjacent 4 KB mappings or TLB locality | timing or fault evidence may come from the split, not the target | large-page secondary effect |
| hot-page amplification | the page is naturally hot due to allocator, render, physics, or networking activity | high exit count does not identify the protected object | hot-page pressure |
| false-neighbor semantic join | the analysis joins a page event to the nearest plausible object | the object was not shown to occupy the accessed byte range at that epoch | semantic containment missing |
| cross-observer page drift | CPU, device, dump, or VMI observers sample different page shapes or epochs | byte or timing equality in one observer does not generalize to all observers | observer page-shape mismatch |
| rollback ambiguity | the split or trap was restored, strengthened, or backed off without retained evidence | later clean state does not establish what the faulting instruction saw | page-shape lifecycle incomplete |

The minimum cross-check is neighborhood substitution. Hold the same second-stage page constant and move the semantic target to a sibling field, a neighboring object, a cold page, a large-page-preserving mapping, and a device-observed path. A true object-level conclusion should follow the semantic target. A page-policy signal will follow the page shape, hotness, or observer path instead. If the evidence follows the page rather than the object, the strongest supportable sentence is page-neighborhood evidence, not game-object evidence.

#### 3.9 Memory Type and Cache Coherency

Memory type is a native equivalence boundary, not a footnote. EPT/NPT mappings interact with cacheability, ordering, device coherency, MMIO behavior, and GPU-visible ranges. A page that should be write-back but is mapped as uncacheable, or vice versa, can create timing or coherency evidence before any content mismatch appears. Until the report names the cacheability rule, the translation root that carried it, and the observer whose byte view is being compared, the careful wording is only "memory-type evidence."

For a research document, memory type is a correctness boundary before it is a performance knob. The same byte sequence can be observed through different cacheability and ordering rules, and those rules decide whether a CPU load, instruction fetch, device DMA transaction, GPU access, or dump parser observation can be compared at all. A memory-type conclusion should therefore name the owner of the cacheability rule, the translation root that carried it, the invalidation or ordering event that made it current, and the observer for which equivalence is being stated.

The vendor manuals are precise enough to make this a field-level subject.

Intel EPT separates two memory-type questions. EPTP bits select UC or WB for EPT paging-structure references when `CR0.CD` is clear. Final translated guest-physical accesses depend on the leaf EPT memory type, the IPAT bit, guest PAT selection, `CR0.CD`, and reserved/misconfiguration rules. Intel also states that MTRRs do not affect EPT paging-structure references or guest-physical accesses translated through EPT.

AMD APM Rev. 3.44 describes the long-standing AMD memory-type model around MTRR/PAT combination, `G_PAT`, guest image versus VMM image separation, and undefined behavior when large pages span incompatible MTRR types.

The exact vendor formulas differ, but both make one thing clear: cacheability is hardware behavior, not prose decoration.

Use this order before treating memory-type evidence as equivalent memory evidence:

```text
vendor memory-type rule
  -> first-stage cacheability
  -> second-stage leaf or root type
  -> platform range or device class
  -> page size and sibling continuity
  -> invalidation and ordering epoch
  -> observer path
  -> timing and byte result
  -> game bridge if stated
  -> strongest safe statement
```

The observer crosswalk should stay explicit because equal bytes do not imply equal authority. A CPU data read, instruction fetch, OS copy, DMA requester, GPU/display path, and dump snapshot can all agree on bytes while disagreeing on timing, cache state, secondary effects, and player-visible meaning:

| Observer | What matching bytes can support | What matching bytes do not support |
|---|---|---|
| CPU data read | the CPU data path saw a byte sequence under a named translation and memory-type context | instruction-fetch behavior, device visibility, or player knowledge |
| CPU instruction fetch | executable bytes could be consumed under a named execute path | data-read equality, legal control-flow target, or game relevance |
| kernel copy path | an OS-mediated copy path produced bytes or an error under documented Windows behavior | below-OS equivalence or absence of a split view |
| device or DMA path | a requester/domain/path saw or failed to see a memory range | CPU page-table equivalence, EPT/NPT fault equivalence, or process semantic ownership |
| GPU or display path | a graphics or presentation observer saw an allocation, frame, or possible copy | CPU process-memory equivalence or actual player-visible disclosure |
| dump or VMI snapshot | one acquisition snapshot contained bytes at a captured epoch | live currentness, cache state, ordering, or handler restoration |

The minimum cross-check is observer substitution. Keep the bytes constant and change only the observer: CPU data read, instruction fetch, kernel copy, physical acquisition, DMA/IOMMU route, GPU/display route, and dump/VMI snapshot. If the conclusion survives every observer change without changing its wording, it is probably too broad. A correct sentence should narrow as soon as the missing owner is removed: byte equality under the CPU path, device path not joined, GPU path not joined, or snapshot only.

#### 3.10 Defensive Meaning of EPT/NPT

For defense, EPT/NPT should be treated as a second-stage consistency calculus, not as a binary "hypervisor present" indicator. The useful question is whether the same guest access, observer, and epoch produce a mutually coherent story across first-stage paging, second-stage paging, memory type, cached translations, event delivery, and game-time behavior:

| Defender question | Why it matters |
|---|---|
| Do virtual and physical views agree? | Split-view cheats rely on observers seeing different content |
| Do code bytes match execution behavior? | Execute-view modification may not match read-view hashing |
| Do page permissions match timing and fault behavior? | Hidden traps change latency and exit behavior |
| Do all cores observe the same page state? | Per-vCPU mapping mistakes create intermittent evidence |
| Do memory type and large-page behavior look plausible? | Page splitting and wrong memory types create secondary effects |
| Does behavior change under gameplay load? | Cheats often enable noisy monitoring only during matches |

An EPT/NPT row should carry the observer and cache context explicitly:

| Field | Why it matters | Safer wording if missing |
|---|---|---|
| observer identity | scanner, game thread, OS API, VMI backend, DMA reader, or host debugger may see different routes | observer route not joined |
| first-stage root | CR3/PCID, PTE state, COW/prototype/backing state decide process meaning | process mapping not joined |
| second-stage root | EPTP or `N_CR3`, ASID/VPID, permissions, memory type, and view epoch decide physical access | second-stage owner not joined |
| cache/invalidation epoch | TLB, paging-structure cache, combined mapping, IOTLB, or ATC can preserve old views | currentness not established |
| event and re-entry path | violation/NPF payload, MTF/single-step, reinjection, RIP/NRIP advance decide execution meaning | event lifecycle incomplete |
| semantic bridge | object, frame, visibility, delivery, and behavior join decide game meaning | game meaning not joined |

A mature EPT/NPT conclusion is not a statement that "a page differed." It is a statement about which observer, through which translation root, at which epoch, saw which backing page under which permission and memory-type behavior. The same byte sequence can be reached through a normal guest page walk, a second-stage alias, a device DMA path, a host VMI read, or a stale TLB entry. Those routes do not carry the same authority.

For defensive writing, keep the steps separate so a page observation is not overstated as process memory, game semantics, delivery, or behavior without the missing joins:

```text
page content observed
  -> translation route joined
  -> observer identity joined
  -> invalidation epoch joined
  -> process mapping joined
  -> game semantic epoch joined
  -> delivery or behavior joined
```

Common overstatements:

| Overstatement | What it means | Safer wording |
|---|---|---|
| second stage equals malicious presence | Any EPT/NPT evidence is treated as evidence of malicious virtualization. | virtualization mechanism evidence |
| observer routes are merged | Scanner, game thread, OS API, VMI, DMA, and host debugger paths are not separated. | route-ambiguous memory observation |
| cache epoch is skipped | TLB, paging-structure cache, IOTLB, ATC, or combined mapping state is ignored. | stale-translation possibility |
| page event becomes game meaning too early | Page evidence is treated as game object, delivery, or behavior without the intervening joins. | second-stage consistency hypothesis |

Minimum cross-check: observer-route split. Read the same target through two observers with different authority, such as guest API plus below-OS walk, VMI plus Windows page-state replay, or DMA plus process-root replay. If the report cannot explain why the observers should agree or disagree, it has not reached process-memory or game-semantic authority.

#### 3.11 Translation Caches and Combined Mappings

Second-stage translation is not recomputed from memory on every access. Modern processors cache linear mappings, guest-physical mappings, combined guest-linear-to-host-physical mappings, paging-structure information, and sometimes page-walk effects. That cache behavior is part of the technology, not an implementation footnote, because the cached product can outlive the table write that an analyst is staring at. Every conclusion about a changed view must therefore say which cached product was retired, retained, or shown to be irrelevant.

| Cached concept | Intel vocabulary | AMD vocabulary | Why it matters |
|---|---|---|---|
| guest linear mapping | guest TLB entries tagged by PCID/VPID where enabled | guest translations tagged by ASID and guest paging context | a CR3 change does not automatically mean every useful cached translation vanished |
| second-stage mapping | EPT-derived guest-physical mappings associated with an EPTP | NPT-derived mappings associated with `N_CR3` and ASID | changing an EPT/NPT entry without matching invalidation can preserve an old view |
| combined mapping | linear-to-physical result derived from both guest paging and EPT | guest virtual to system physical result derived from guest paging and NPT | split-view logic must reason about both layers as one cached product |
| paging-structure cache | cached information from guest paging and EPT paging structures | cached VMCB/NPT/page-walk state, with clean-bit and ASID effects | page-table monitors can miss or misclassify events if they ignore cached walks |
| global translation | guest global pages and retained translations | ASID-scoped global-like behavior and TLB control choices | retaining globals improves performance but complicates view replacement |

This explains why invalidation is a first-class subject. Intel separates `INVEPT` for EPT-derived mappings from `INVVPID` for VPID-tagged linear mappings. AMD exposes `INVLPGA`, `INVLPGB`, `TLBSYNC`, ASID management, and VMCB `TLB_CONTROL` behavior. The names differ, but the invariant is the same: a translation view is not changed until the hardware's cached view is changed or made irrelevant.

| Mapping change | Required reasoning |
|---|---|
| guest PTE changes | guest TLB and PCID/ASID behavior determine when the new first-stage mapping is observed |
| EPT/NPT permission changes | second-stage cached permissions may survive until the correct invalidation boundary |
| EPTP or `N_CR3` view switch | old combined mappings may still be associated with the prior second-stage root |
| large-page split | cached large-page translations must not keep covering the 4 KB subpage being watched |
| execute permission change | instruction fetch can be cached differently from data access on some paths |
| memory-type change | cacheability changes require more conservative reasoning than ordinary permission changes |

For analysis, stale translations are not only a performance problem. They are a visibility problem and an evidence-class boundary. If one core sees the old mapping and another core sees the new mapping, the hypervisor has created a measurable inconsistency even if every individual mapping entry looks valid. If a device ATC or IOTLB keeps an older translation while CPU-side invalidation appears complete, the report no longer has one memory view; it has competing observer epochs that must be compared rather than merged.

The rule is translation-cache currentness. A second-stage edit is not a view change until four things are named:

1. which cached product could have retained the old view
2. which invalidation primitive covers that product
3. which processor or vCPU set was covered
4. which post-invalidation witness used the new view

The attacker's advantage is cache-range ambiguity. A view switch can look correct in memory tables while a core, VPID, ASID, EPTP, `N_CR3`, virtual TLB, device ATC, or nested-shadow structure still carries the old product. For defense, the first uncovered cache epoch matters more than the table write itself.

The minimum cross-check is cache-scope separation. Hold the page tables constant and vary only the cache owner:

- run the same access before and after a single-context `INVEPT`
- run it again before and after a global `INVEPT`
- hold the EPTP constant and change only VPID-tagged guest-linear mappings
- split a large page and probe a neighboring 4 KB subpage
- run the access on another logical processor before the remote flush is paid
- in nested Hyper-V, compare L1-visible flush completion with L0 virtual-TLB direct-flush completion

A correct conclusion weakens from "hardware view changed" to "table state changed" at the first cache owner that was not covered. If the sentence does not weaken, it is using "entry changed" as a shortcut for hardware-observed currentness.

#### 3.12 Permission Composition and Fault Priority

EPT/NPT permission is evaluated together with guest paging, not in isolation. A guest virtual access first has to make architectural sense in the guest's paging mode. Then the resulting guest physical access has to be allowed by the second stage. The final outcome depends on both layers and on the priority rules for faults, violations, and misconfigurations.

The analysis object is therefore not a page entry. It is a resolution pipeline. A single observed event can be a guest `#PF`, an Intel EPT violation, an Intel EPT misconfiguration, an AMD NPF, a page-walk effect, an A/D-bit transition, a stale translation, or a handler-created retry. Those outcomes can occur near the same address while establishing different facts. Treating them all as "a memory fault" erases the owner that matters.

```text
guest virtual address
  -> canonicality and mode check
  -> first-stage walk and guest permission
  -> first-stage fault or guest physical address
  -> second-stage root and leaf walk
  -> access role classification
       final data access | guest paging-structure access |
       nested paging-structure access | A/D effect |
       instruction fetch | implicit access
  -> second-stage outcome
       allowed | violation or NPF | misconfiguration or malformed state |
       stale cached translation | handler retry
  -> post-event currentness
  -> strongest safe statement
```

| Question | First-stage paging answer | Second-stage answer | Correct interpretation |
|---|---|---|---|
| Is the virtual address canonical and mapped? | guest page tables, CR0/CR4/EFER mode, U/S, R/W, NX, reserved bits | not reached if first-stage translation fails first | a guest `#PF` is not evidence of EPT/NPT shaping |
| Is the guest physical page present in the second stage? | first stage produced a GPA | EPT/NPT entry presence and reserved-bit validity decide violation vs misconfiguration/fault | missing mapping and malformed mapping are different evidence classes |
| Was the access read, write, or execute? | guest permission permits or blocks the access | second-stage R/W/X policy may still block it | a clean guest PTE can still produce a second-stage event |
| Did the event happen during page walk? | guest page-table entries are themselves memory reads/writes | second stage mediates those accesses too | page-walk events should not be confused with direct game-data reads |
| Are accessed/dirty bits involved? | hardware may update guest paging structures | EPT A/D behavior can make page-walk accesses look write-like | A/D-induced writes can be mistaken for malicious data modification |
| Is memory type valid? | PAT/MTRR/guest attributes contribute to cacheability | EPT/NPT memory-type rules constrain the final type | wrong type can leak through performance and coherency before content checks |

The narrowing rule is mechanical:

- unresolved first-stage walk: possible address-translation evidence
- missing native second-stage payload: normalized fault only
- ambiguous page role: page role not closed
- pre-access and post-handler leaves not separated: repaired view only
- missing invalidation/currentness: stale translation possible
- missing Windows page-state and semantic joins: not process memory and not a game object

The practical conclusion is to preserve fault class, access type, first-stage permission facts, second-stage permission facts, GPA, GLA validity, and page-walk classification. Without those fields, a trace loses the distinction between a normal guest page fault, a deliberate second-stage watch, an invalid paging-structure entry, and a cache/invalidation bug.

#### 3.13 Second-Stage Fault Trace Fields

A useful trace should let another reader answer a small set of questions without trusting the collector's label. Avoid starting with "EPT fault happened" or "NPF happened." Start with the native event and then walk upward.

The short version is:

```text
native fault
  -> translation path
  -> handler action
  -> currentness after invalidation
  -> Windows process view
  -> game meaning and delivery
```

If the trace stops early, the sentence should stop early too.

| Trace field | Intel EPT source | AMD NPT/SVM source | Why it matters |
|---|---|---|---|
| Event class | EPT violation or EPT misconfiguration | `EXITCODE`, especially `VMEXIT_NPF` | separates permission denial, malformed entry, and AMD-native NPF |
| Second-stage root | EPTP, EPTP-list, VMFUNC context if used | `N_CR3`, nested-paging enable state | names which physical view was active |
| First-stage root | guest CR3, PCID, paging mode, CPL | guest CR3, ASID, paging mode, CPL | ties the event to an address-space context |
| Access class | EPT violation qualification bits | NPF error-code and `EXITINFO` fields | separates read, write, execute, page-walk, and A/D-like effects |
| Address evidence | GPA field and GLA when valid | `EXITINFO2` GPA; GVA only if reconstructed safely | prevents a GPA-only event from becoming a user pointer |
| Leaf state | EPT leaf before handler mutation | NPT leaf before handler mutation | shows whether this was policy, redirection, or malformed state |
| Handler action | permission flip, page-base change, EPTP switch, #VE, MTF, reinjection | permission flip, nested-root change, event injection, TLB action | connects the fault to the view change |
| Currentness action | `INVEPT`, `INVVPID`, VPID relation, core scope | `TLB_CONTROL`, `INVLPGA`, `INVLPGB`, `TLBSYNC`, ASID lifecycle | shows whether cached translations could still disagree |
| Windows bridge | region, residency, guard/COW state, read behavior parity | same after guest walk and NPT replay | separates below-OS bytes from process memory |
| Game bridge | object generation, frame/tick, visibility or delivery path, replay/server context | same | separates memory meaning from player advantage |

##### 3.13.1 A Trace Is Not a Verdict

A second-stage fault can be perfectly real and still support only a narrow sentence. For example, an EPT violation can show that a guest-physical access crossed a second-stage policy. It does not show by itself that the access belonged to a specific process, that the bytes represented a live object, or that the player acted on the information.

Use these ceilings:

| If the trace contains | Strongest careful wording |
|---|---|
| only a tool label | a tool reported a second-stage-like event |
| native exit payload and root | a native second-stage event occurred under this root |
| first-stage and second-stage replay | the event belongs to this translation path |
| handler action plus invalidation | this view change became current for the covered CPUs |
| Windows page-state join | the event supports bounded process-memory evidence |
| game object and delivery evidence | the event may participate in a bounded game-meaning chain |

The rule is intentionally plain: do not borrow meaning from a later layer to repair a missing earlier layer.

##### 3.13.2 Fault-Loop Shape

Many EPT/NPT techniques follow the same loop:

```text
arm a page
  -> fault on read, write, execute, or page-walk access
  -> classify the native payload
  -> temporarily allow, redirect, or log
  -> invalidate or synchronize if the view changed
  -> resume the guest
  -> restore or re-arm the watched state
```

The loop can be implemented in different ways: direct permission flips, shadow backing pages, EPTP switching, monitor-trap-style restoration, #VE routing, or hosted VMI events. The details differ, but the evidence questions stay the same:

1. What was the pre-access leaf state?
2. What native event fired?
3. What did the handler change?
4. Which CPUs or VPs saw the changed view?
5. Was the old view restored before another observer could see the temporary state?

If the answer stops at step 2, the trace is only a fault observation. If it reaches step 5, it can support a bounded view-transition statement.

##### 3.13.3 Common Fault Examples

| Example | What it can show | What it still needs |
|---|---|---|
| final-page data read trap | a read-qualified access reached a GPA and crossed second-stage policy | process root, Windows page-state parity, handler mutation, invalidation |
| guest page-walk trap | the CPU touched guest paging structures under second-stage control | evidence that the event was not ordinary address-space maintenance |
| execute-view switch | instruction fetch and data read may see different backing pages | instruction window, backing-page identity, stale-TLB check |
| MTF restoration window | a temporary one-instruction view was used | cross-core check that no other observer saw the temporary state |
| EPT misconfiguration | the entry encoding was invalid or unsupported | do not call it a stealth watchpoint until a valid policy path exists |
| AMD NPF final GPA fault | an NPT event occurred while translating the final GPA | AMD-native `EXITINFO1/2`, `N_CR3`, ASID, and guest walk replay |
| AMD NPF guest-table fault | an NPT event occurred during guest page-table access | avoid turning page-table maintenance into game-data access |
| stale combined mapping | table bytes changed but cached translation may remain | invalidation range, completion witness, and post-flush probe |

##### 3.13.4 Tool Output Needs a Native Carrier

Tools are useful, but their labels are not the same as hardware evidence. HyperDbg, KVMi, Xen altp2m, QEMU/KVM, a dump parser, and a private VMI backend can all report memory events while hiding different amounts of native context.

Treat tool output like this:

| Tool or backend row | Safe use | Do not infer by itself |
|---|---|---|
| HyperDbg EPT hook or monitor event | mechanism lab for EPT fault loops, MTF restoration, and access pressure | production endpoint prevalence, Windows read parity, gameplay consequence |
| KVMi memory event | backend-scoped VMI event | Intel or AMD native payload unless preserved by the backend |
| Xen altp2m or memory-event row | alternate p2m view mechanism | bare-metal Windows behavior or game authority |
| dump or parser row | stable byte snapshot | live currentness or handler transition |

A dashboard label can start the analysis. It should not replace the carrier. If the carrier is missing, the careful wording is still "tool-reported event."

##### 3.13.5 Windows and Game Bridge

The Windows bridge is API and page-state behavior, not a byte-equality shortcut. `VirtualQueryEx` groups pages by state, protection, and type. `ReadProcessMemory` has an all-range read behavior. `QueryWorkingSetEx` can add validity, sharing, locking, bad-page, and large-page information. These are Windows observations, not second-stage truth.

A below-OS byte sample becomes a process-memory statement only when the Windows view is joined or explicitly declared non-equivalent. A process-memory statement becomes a game statement only when object lifetime, frame or tick, visibility, delivery path, and replay/server context are joined.

Use these safer rewrites:

| Too broad | Safer wording |
|---|---|
| "EPT bit 0 means the game read the field" | a read-qualified EPT event exists |
| "bit 8 shows a process pointer" | the row has final-linear-access evidence; process ownership is still separate |
| "NPF `EXITINFO2` shows object access" | AMD NPF names a faulting GPA under this `N_CR3`; object meaning is still separate |
| "TLFS direct flush makes stale views impossible" | nested currentness evidence exists for the covered virtual-TLB context |
| "working-set valid shows a hypervisor event" | Windows page-state is joined; hardware event ownership remains separate |
| "two tools agree, so the endpoint truth is established" | check whether the tools share backend, pause state, symbols, parser input, or timebase |

This section's practical rule is short. Preserve native payload, root identity, handler mutation, invalidation/currentness, Windows page state, and game delivery as separate steps. The first missing step sets the honest ceiling for the sentence.

## Next

Next, the series moves from second-stage memory views into execution control. VM-exit handling, VMI reconstruction, monitoring cadence, overlay paths, and input boundaries become separate but composable surfaces.

## Credits

Credit to @Intel80x86 (@Sinaei on X) and @HyperDbg for the public HyperDbg `!epthook` and `!epthook2` design documentation that informed the split-view, EPT hook, and MTF restoration discussion.

## References

- Intel, Intel 64 and IA-32 Architectures Software Developer's Manual: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- AMD, AMD64 Architecture Programmer's Manual Volume 2, System Programming, Rev. 3.44: https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2
- AMD, AMD64 Page Modification Logging, Publication #69208 Rev. 1.00: https://docs.amd.com/api/khub/documents/bSG~MCDnO9H2gPucB8UbFQ/content
- Intel, Sub-page Permission and INTEL-SA-01196 advisory guidance: https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/sub-page-permission.html
- Intel, Intel Trust Domain Extensions module documentation: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html
- AMD, SEV Secure Nested Paging firmware ABI specification: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
- HyperDbg, Design of !epthook: https://docs.hyperdbg.org/design/features/vmm-module/design-of-epthook
- HyperDbg, Design of !epthook2: https://docs.hyperdbg.org/design/features/vmm-module/design-of-epthook2
- Microsoft, Hyper-V Top-Level Functional Specification: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
- Microsoft, Hyper-V TLFS Feature and Interface Discovery: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
