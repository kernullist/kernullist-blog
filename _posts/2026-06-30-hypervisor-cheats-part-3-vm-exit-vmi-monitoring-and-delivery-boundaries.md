---
title: "About Hypervisor Cheats, Part 3: VM-Exit, VMI, Monitoring, and Delivery Boundaries"
date: 2026-06-30 00:00:00 +0900
categories: [Windows Internals, Anti-Cheat]
tags: [hypervisor, ept-hook, vm-exit, vmi, monitoring, input, overlay, anti-cheat, windows]
---

> A hypervisor is useful to a cheat only when it can choose a small set of exits, resume the guest cleanly, and turn low-level events into OS and game meaning without losing timing coherence. The chain runs from VM-exit selection to VMI and delivery.

## Scope

Part 2 focused on EPT and NPT. This part moves one layer up: EPT hooks, exit selection, event emulation, CR/MSR/I/O surfaces, virtual machine introspection, polling versus event-driven monitoring, overlay and input paths, GPU-facing observations, and the point where a low-level event can safely be discussed as game state.

## Technical Notes

The recent trend is that cheat logic keeps moving away from the game process and into nearby observation or delivery paths. That changes the engineering problem. The hard part becomes keeping three moments aligned: when the data was read, when the cheat turned it into game meaning, and when the hint reached the player or input path.

In this post, a "hint" means any information the cheat gives to the player or to an input helper. Examples include an ESP box, a radar dot, a visibility marker, a trigger-assist signal, an aim hint, or enemy position shown on a second screen. The timing question is simple: did that hint arrive early enough to explain the player's later action?

Four patterns matter for this part:

| Trend | What moved | Cheat-relevant meaning |
|---|---|---|
| VMI-based game cheats | memory reads and event observation move outside the guest process | a byte read must still become current process memory, then game meaning, then player-usable information |
| visual aimbots | target selection moves from memory to rendered frames | capture, display, and input timing become part of the cheat loop |
| external or pre-OS acquisition | reads can move to DMA, firmware-adjacent, or host-side paths | translation freshness and device timing become part of the memory path |
| host, VM-parent, or second-device delivery | the hint is shown outside the game process | the last mile may be a host overlay, stream, second screen, or player-facing hint rather than an in-game overlay |

The VIC paper by Panicos Karkallis and Jorge Blasco is useful here because it shows a VMI-based cheat model for radar, wallhack-style information, and trigger assistance.

AimTrap is useful from a different angle because it treats visual aimbots seriously even when they operate on rendered frames rather than game memory. Both papers point to the same chain: acquisition, reconstruction, delivery, input, and game consequence.

---

## From EPT/NPT Mechanics to Cheat-Relevant Principles

Part 2 described EPT and NPT as second-stage translation mechanisms. They do not form a complete cheat by themselves, but they change what memory observation means. They let a hypervisor sit below the guest OS, choose a second-stage view, and turn selected memory accesses into native events.

The address chain is the first boundary:

```text
guest virtual address
  -> guest page tables under a process root
  -> guest physical address
  -> EPT/NPT under a second-stage root
  -> system physical backing
```

Each arrow is owned by a different layer. The game and Windows mostly work in guest virtual addresses. EPT and NPT mostly work in guest physical pages and second-stage permissions. A hypervisor can observe or shape the second-stage part of the chain, but it does not automatically know the process lifetime, the Windows page state, or the game object meaning.

### Second-Stage Primitives and View Divergence

For cheats, the main primitives are:

| Primitive | Hardware-level meaning | Cheat-relevant meaning | Where it stops being enough |
|---|---|---|---|
| below-OS byte acquisition | a byte is sampled through a physical or second-stage route | ordinary handles, modules, and user-mode read APIs can be absent | process root, Windows region state, residency, and object freshness are still separate |
| permission-to-event conversion | a second-stage read, write, or execute permission causes an EPT violation or NPF | selected page access can become a low-level event | page-level access is not field-level or game-object-level meaning |
| split view | different second-stage leaves, roots, or backing pages expose different bytes or permissions | one observer may see a clean view while another path uses a different view | view owner, switch trigger, invalidation, and core coverage must be known |
| execute/data asymmetry | instruction fetch and data read can be controlled separately where the architecture allows it | code and scanner views may diverge from data views | restoration and exception ordering become part of the state |
| delayed page logging | accessed/dirty state, PML-like logging, or dirty rings record page-level activity | lower exit rate may still reveal coarse page activity | page activity does not name the actor, value, field, or semantic object |
| translation currentness | TLB, EPT/NPT caches, ASID/VPID, EPTP or `N_CR3`, and invalidation decide what actually ran | a changed table is not enough; the running vCPU must consume the new view | stale translations can make table bytes and runtime behavior disagree |

The granularity is important. EPT/NPT events are normally page or translation events. A game object is usually smaller, higher-level, and time-dependent.

One page may contain multiple fields, reused allocations, engine metadata, or unrelated objects. One object may span several pages sampled at different times. Page-level state only becomes game-state meaning after address-space, object-lifetime, and timing state are joined.

View divergence also has more than one form:

| Divergence form | What changes | Typical technical burden |
|---|---|---|
| permission divergence | the same backing page has different read/write/execute permissions | exit reason, access type, and rearm state must be preserved |
| backing divergence | two views map the same GPA to different backing bytes | old/new backing identity, memory type, cache behavior, and invalidation matter |
| access-type divergence | execute, read, and write paths do not receive the same view | instruction boundary, MTF/single-step, and exception ordering matter |
| time-sliced divergence | a temporary view is exposed only around a selected access | switch trigger, per-vCPU coverage, and stale translation checks matter |
| nested divergence | an L1, L2, enlightened VMCS/VMCB, or hosted VMI stack owns part of the route | owner separation is required before treating the signal as native bare-metal behavior |

These distinctions matter because one view is not the whole system. One reader may observe a read-only view, one access type, one core, or one time window while the game executes through another combination.

The reverse is also true: one second-stage event is just a second-stage event until the owner is known. It may come from nested virtualization, a debugger, a VMI tool, a hosted VM stack, or a lab harness.

That is the strength and the limit of EPT/NPT. They can move observation below the guest OS, turn memory accesses into hardware events, and create view divergence. Those facts remain below the game layer.

An EPT violation or NPF means an access reached a guest physical page under a named second-stage policy. Turning that hardware event into game-level meaning requires several timelines and owners to be connected:

| Step to connect | Question it answers |
|---|---|
| process root | did this access belong to the target process epoch? |
| first-stage translation | did the selected guest virtual address really reach this guest physical page? |
| Windows page state | would Windows classify the address as committed, readable, resident, private, mapped, guarded, or paged? |
| second-stage policy | which EPTP or `N_CR3` view, permission, memory type, and invalidation state applied? |
| object generation | did the bytes still belong to the same game object lifetime? |
| game timing | did the sample match the simulation, render, replication, or replay tick being discussed? |
| delivery path | did the reconstructed information reach a visible hint, display, input path, or server-visible action? |

Different cheat effects stress different technical limits:

| Effect class | EPT/NPT pressure | What still sits above EPT/NPT |
|---|---|---|
| radar-like information | can often tolerate lower-rate physical or VMI samples | object lifetime, team, relevance, and stale entity filtering |
| ESP or wall-style information | needs memory freshness plus camera and projection timing | render frame, visibility meaning, capture path, and player-visible hint |
| trigger-like timing | needs event freshness and tight timing alignment | input source, fire state, server tick, and causality |
| aim-like correction | may consume hidden state but is judged through motion and input behavior | smoothing, input cadence, replay path, and server consequence |

Split-view currentness is the subtle part. A second-stage table can say one thing while a vCPU still uses a cached translation. One core may see the restored view while another core is inside the temporary view.

A large page may be split into smaller leaves, changing the local shape of the page tables. A permission flip may require an exit, a handler decision, invalidation, and a rearm path before the original behavior is restored.

These implementation details have architectural meaning because they connect Part 2's EPT/NPT mechanics to Part 3's VM-exit, VMI, monitoring, and delivery boundaries.

### EPT Hooks as Cheat-Relevant Entry Points

An EPT hook is often the first practical bridge from "the hypervisor owns a second-stage view" to "the hypervisor can observe or steer a selected game event." The term hook can be misleading in this context. Here it means a stateful second-stage memory-control loop, rather than a normal inline patch inside the game process.

Most public writeups say EPT hook because the Intel terminology is common and HyperDbg uses EPT in its public examples. The same idea has an AMD-side counterpart through NPT permission state and nested page faults.

The shared concept is second-stage control: change what the guest can read, write, or execute at the physical-page layer, then handle the resulting transition.

#### Second-Stage Ownership

The technical point is ownership. The game executes through guest virtual addresses. Windows translates those addresses through the process page tables. EPT or NPT translates the resulting guest physical page through a second-stage root.

An EPT hook sits at that second-stage boundary. It does not need the game to call a Windows API, load a module, open a handle, or install an ordinary user-mode breakpoint. It waits until the CPU itself needs a page permission or backing decision.

That is why EPT hooks matter to game cheats. They turn memory access into an event source below the guest OS. That event source can be used to wake a VMI pipeline, maintain a split view, hide a breakpoint-like condition from ordinary reads, notice updates around selected game state, or feed a timing-sensitive helper.

The cheat still needs higher-level reconstruction, but the entry point can be the hardware translation path rather than the game process.

At a conceptual level, the loop is:

```text
candidate game address or code path
  -> guest virtual to guest physical translation
  -> EPT leaf or second-stage view selection
  -> permission change, shadow backing, or alternate view
  -> EPT violation or monitor-trap style transition
  -> handler observes context, records state, or changes the temporary view
  -> guest re-enters
  -> hook state is restored, rearmed, or narrowed
```

The loop has to remember more than "a hook exists." It has to remember the root, page, access type, temporary view, invalidation state, and rearm point.

Public debugger designs are useful mechanical references for the same control idea. HyperDbg's `!monitor` shows how memory access classes can become monitorable events.

HyperDbg's `!epthook` and `!epthook2` documentation is useful because it describes hidden EPT hook designs where EPT permissions, copied pages, monitor-trap behavior, and rearm logic decide what the guest sees next. For cheat mechanics, the important part is the page-level state machine rather than the command syntax.

#### Hook Shapes

The table below separates EPT-hook shapes by what they mean. This is the difference between a generic below-OS memory read and a hook surface that can become a cheat entry point.

| EPT-hook shape | Low-level mechanism | Cheat-relevant meaning | Main technical debt |
|---|---|---|---|
| access watchpoint | remove or alter second-stage read, write, or execute permission for a selected page | turn a page touch near a game object or code path into an event | page-level signal, hot-page pressure, rearm timing |
| write-sensitive state watch | make selected writes to a page produce an EPT violation or NPF | notice updates near entity lists, camera state, visibility-like state, weapon state, or match phase data | write to a page is not proof of the exact field |
| execute-sensitive path watch | make instruction fetch from a selected page produce a second-stage transition or execute through a shadow view | observe hot code paths without a normal guest breakpoint | page execution is not full control-flow truth |
| execute-only shadow | allow one execute view while reads see a cleaner or original page | hide breakpoint-like or detour-like code from ordinary read paths | read/write/execute views must stay synchronized |
| split-view memory | serve different second-stage backing or permissions to different observers, access types, or time windows | let a read path see one view while execution or another observer uses a different view | view owner, switch timing, and per-core currentness must be known |
| hybrid trigger | use a narrow EPT event to wake a broader VMI, polling, or delivery pipeline | reduce constant polling while catching high-value transitions | trigger timing is not game meaning until later layers join |
| dirty/access sampling | use accessed/dirty style page state or related logging instead of trapping every access | lower exit volume while retaining coarse page activity | delayed, page-granular signal with weak field identity |

#### Hook State Machine

The state machine is the heart of the technique:

| State | What is true | Why it matters |
|---|---|---|
| candidate selected | a GVA, GPA, page, function page, data page, or semantic marker is believed to matter | a wrong root or stale object makes the whole hook irrelevant |
| page narrowed | large pages may need local narrowing before page-level policy is precise enough | narrowing changes page-table shape and can create locality artifacts |
| armed view installed | the second-stage entry or active view is changed so a selected access class becomes observable | this is the actual hook boundary |
| transition delivered | EPT violation, NPF, #VE path, MTF-style path, or backend event reaches the handler | native payload and access type decide what the event can mean |
| temporary view chosen | the handler may expose original bytes, shadow bytes, writable bytes, executable bytes, or a restored mapping | the guest-visible story depends on this temporary decision |
| guest re-entered | the original instruction or access path continues under the temporary state | incorrect re-entry changes behavior or leaks the hook |
| restored or rearmed | permissions, backing, MTF/single-step state, and invalidation are brought back to the intended monitoring state | without this, the next event and the previous event have different meaning |
| exported upward | the event is handed to VMI, polling, overlay, input, or replay logic | only here can it start becoming a cheat feature |

A practical EPT hook is primarily a coherence problem. The handler has to preserve the native payload, keep page state and views synchronized, decide whether the guest should see original bytes or a temporary view, let the trapped access complete, and return the page to the intended monitoring state.

If one of those transitions is missing, the hook may still exist, but the loop is only partially explained.

For Intel EPT, the useful payload is not just "exit happened." The event carries access class, EPTP or view identity, guest physical page, guest-linear-address availability, final-translation versus page-walk context, and the before/after EPT leaf state.

For AMD NPT, the same idea appears through nested-page-fault state, `N_CR3`, ASID, NPF exit information, and NPT permissions. The names differ, but the state burden is similar.

#### Cheat Meaning

For a game cheat, the most important difference is between "read what exists" and "wake when something happens." A passive physical reader has to poll, guess freshness, and decode object graphs from snapshots.

An EPT hook can instead turn selected access into a timing point. That timing point can say "this page was read," "this page was written," or "this page was executed" under a named second-stage root. This is stronger than a passive byte sample, but it does not by itself establish game meaning.

The cheat value depends on the access class:

| Access class | Example game relevance | Immediate signal | Remaining game-level work |
|---|---|---|---|
| read | code or data read near camera, entity, recoil, visibility-like, or weapon state | a selected page was read under this vCPU/root/view | which field mattered, whether it was current, or whether the player used it |
| write | game code updated a page containing state that may feed object lists, transforms, or match state | a selected page received a write-class access | exact semantic field, server authority, or player knowledge |
| execute | code on a watched page ran or reached a shadowed execution view | execution reached this page or hook view | full branch path, function-level causality, or game outcome |
| read/write mismatch | one path reads clean bytes while another path executes or uses different backing | a split view exists for selected access classes | global stealth or absence of artifacts on other cores |
| event-only wakeup | EPT event starts a later parser or helper | a useful transition happened near the watched surface | radar, ESP, trigger timing, or aim assistance without reconstruction |

This is where EPT hook depth matters for game cheats. A radar-like cheat may use hooks to update object data only when relevant pages change instead of polling all the time. An ESP-like cheat may use hooks to keep camera, transform, or visibility-adjacent state fresh enough for projection.

A trigger-like helper may care about a tighter relation between target state, crosshair state, input moment, and server tick. A stealth-oriented design may care less about reading data and more about presenting one page view to scanners while another view participates in execution.

Those paths depend on different state. A write-sensitive hook near an entity container, a hidden execute detour, a read-side clean view, and a dirty-page signal each fail in different ways and should be treated as separate mechanisms.

#### Cheat-Relevant Examples

The examples below describe page roles rather than game-specific offsets. They are easiest to picture in an Unreal Engine-style FPS client, but the same roles appear in other engines under different names.

- **Object collection churn:** a write-sensitive hook near an entity-container page can tell the higher layer that the object graph may need a refresh. It still has to prove which process root, object generation, team, and replication state the page belonged to.
- **Camera and projection freshness:** a hook near camera or transform-adjacent pages can reduce stale ESP projection. The hook does not solve projection by itself; the render frame, FOV, viewport, and entity transform still have to match.
- **Visibility-adjacent updates:** a hook near visibility, relevancy, or occlusion-like state can wake a parser at useful moments. The risk is over-trusting a client-side field that does not match server-authoritative visibility.
- **Execute-sensitive game path:** an execute watch on a hot page can show that selected code ran without placing a normal guest breakpoint. It does not recover the full branch path or prove the resulting game decision.
- **Clean-view split:** a scanner-facing read view and an execution-facing view can explain why a page looks clean to one observer and behaves differently to another. The hard part is per-core view currentness and restoration timing.

These examples show why EPT hooks matter to cheats: they can convert page access into timing hints. The rest of the cheat still has to perform process reconstruction, object validation, frame alignment, and delivery.

#### Technical Limits

The technical limits are stable:

| Limit | Why it exists | How it can break the cheat meaning |
|---|---|---|
| page granularity | EPT/NPT permissions are page-oriented, not object-oriented | one page can contain unrelated fields or reused allocations |
| large-page splitting | precise hooks may require a different local page-table shape | the split itself becomes part of the state that must stay coherent |
| stale translation | TLB, EPT/NPT caches, VPID/ASID, and invalidation decide what the vCPU really used | table bytes can look armed while a core still uses an older translation |
| multi-core currentness | each logical processor can be in a different phase of the hook loop | one core may see the temporary view while another sees the restored view |
| hot-page pressure | high-frequency pages can produce too many exits or callbacks | the hook becomes a timing artifact or forces coarser monitoring |
| MTF or single-step window | temporary restoration often needs one-instruction progress before rearming | the restoration window can leak wrong bytes or disturb ordering |
| paging and residency | virtual addresses may be paged out, inaccessible, remapped, or materialized | a valid-looking target may not correspond to live process memory |
| memory type and aliasing | second-stage memory type and backing changes can interact with cache behavior | two views can disagree in ways unrelated to game semantics |
| nested owner ambiguity | Hyper-V, VBS, nested virtualization, debugger VMMs, or hosted stacks may own part of the path | an observed hook-like event may not belong to a cheat-controlled L0 |

#### From Hook Event to Game Meaning

For game cheats, EPT hooks usually become useful only after a second layer interprets the event:

```text
EPT hook event
  -> vCPU, access type, GPA, optional GLA, and page root
  -> process root and Windows page-state replay
  -> object or code-path interpretation
  -> frame, tick, visibility, or input timing
  -> visible hint, input helper, or behavior consequence
```

The first row is still a CPU translation event. The later rows are where the cheat meaning starts. A missing process root leaves it below game-process meaning. Missing Windows page state leaves it below process-memory meaning. Missing object lifetime or frame timing leaves it below radar, ESP, trigger timing, or aim assistance. Missing delivery leaves it below player knowledge.

A precise EPT-hook sentence therefore needs at least these fields:

```text
ept_hook_event =
  second_stage_owner
  and root_or_view_identity
  and page_identity
  and access_class
  and native_exit_or_fault_payload
  and old_new_permission_or_backing_state
  and invalidation_or_currentness_state
  and reentry_and_rearm_state
  and process_and_object_bridge_if_game_meaning_is_used
```

If only the first half is present, the mechanism stops at "second-stage hook event." If the process bridge is present, it can become "game-process-adjacent page event." If object lifetime and frame timing are present, it can become "game-state-adjacent event." Only after the visible hint, input helper, or behavior consequence is connected does it become a player-facing advantage path.

This is also why an EPT hook is both powerful and fragile. It removes many guest-local signals, but it adds second-stage costs and state: permission flips, handler latency, monitor-trap or single-step windows, invalidation requirements, large-page splits, view ownership, and per-core currentness. In a nested or Hyper-V/VBS system, it also needs owner separation. Without the active owner, the mechanism remains "second-stage hook behavior" rather than native bare-metal cheat state.

At the mechanism level:

```text
An EPT hook can make a selected page access observable below the guest OS.
It does not by itself prove which game field changed, which player saw the result,
or whether the final action was caused by that event.
```

### VM-Exit Interception Surfaces

Not every hypervisor cheat needs every intercept. Real designs choose a small set because every additional intercept creates an emulation owner, timing debt, event-ordering obligation, and re-entry side effects.

| Surface | Why it matters to cheats | What technical debt it creates |
|---|---|---|
| CPUID | Hide or normalize virtualization identity | Inconsistent leaves reveal fake platform stories |
| RDTSC/RDTSCP and timers | Mask exit overhead or shape timing probes | Drift across TSC, QPC, HPET, APIC, and network timing is hard to hide |
| CR3 loads | Track process address-space changes | Excessive CR3 interception is noisy |
| MSRs | Handle syscall/sysenter, APIC/timer, EFER, hypervisor leaves | Incorrect MSR behavior breaks Windows or reveals partial emulation |
| Exceptions/debug events | Hide breakpoints or implement event tracing | Debug behavior is highly consistency-sensitive |
| EPT/NPT violations | Watch selected memory accesses | Hot-page exits create measurable latency |
| Interrupts/APIC | Coordinate timing, input, or event delivery | Latency and ordering anomalies can appear |

The key theme is consistency across all event families, not just one. A spoofed CPUID leaf still has to be consistent with MSR behavior, timer scaling, APIC delivery, debug exception delivery, VBS/Hyper-V reporting, and device-visible timing. The same guest action should produce a compatible CPU, OS, timer, interrupt, and device story under the same epoch.

In practice, a single exit in isolation is rarely sufficient. Keep the control reason, hardware payload, emulated result, pending-event state, re-entry action, and next guest-visible observation together. A cheat can intercept only the surface it needs and let nearby CPU, timer, APIC, MSR, debug, or device behavior drift. That drift is part of the mechanism itself. A CPUID, EPT, or timer event only makes sense when the neighboring state still tells the same story.

#### Technical Intercept Map

At this level, an intercept involves four components: a hardware control bit, a qualification field, an emulation path, and the state returned to the guest. The same visible VM exit can mean very different things depending on which control routed it.

| Intercept family | Control object | Useful state | Technical invariant |
|---|---|---|---|
| CPUID and feature leaves | VMX secondary controls or SVM instruction intercepts | leaf/subleaf, returned registers, hypervisor-present bit, vendor leaves, Windows feature state | Returned CPU story must match MSRs, Device Guard state, microcode features, and Hyper-V/VBS policy. |
| CR0/CR3/CR4 access | VMCS CR masks/shadows or SVM CR intercepts | old/new value, CPL, RIP, process transition, PCID/LA57 context | CR reads can be virtualized separately from CR writes; a fake CR story must still match scheduler and address-space behavior. |
| MSR access | MSR bitmap, MSRPM, synthetic MSR handling | MSR number, read/write, value, guest mode, VTL/Hyper-V ownership | MSR values must cohere with syscall, APIC, TSC, EFER, CET, Hyper-V, and VSM surfaces. |
| exceptions and debug state | exception bitmap, IDT/vectoring info, DR state, SVM exception intercepts | vector, error code, `DR6/DR7`, pending event state, reinjection path | Exception delivery must preserve architectural ordering, nested exceptions, and debugger-observable state. |
| timer exits and scaling | RDTSC/RDTSCP controls, TSC offset/scaling, Hyper-V reference TSC | raw TSC delta, QPC/HPET/APIC/network correlation, per-core skew | Time must be coherent across local clocks, server observations, and power-management behavior. |
| EPT/NPT faults | EPTP or `N_CR3`, entry permissions, exit qualification or `EXITINFO1/2` | access type, GPA, GLA validity, page-walk/final-page classification, vCPU, EPTP/ASID | A page-view decision must stay coherent across cores, stale translations, physical readers, and memory type. |
| APIC and interrupt controls | posted interrupts, APIC virtualization, TPR/EOI exits, SVM virtual interrupt controls | interrupt vector, delivery mode, pending event, latency, lost or duplicated delivery | Interrupt order must match guest-visible scheduler, DPC/ISR timing, input latency, and timer cadence. |
| I/O and MMIO | I/O bitmap, MMIO exits, device emulation path | port/MMIO address, device range, instruction context, ordering | Device semantics require ordering and state changes; "returning a value" is not enough. |
| monitor-trap and single-step paths | MTF, single-step event, debug state | restoration point, instruction length, branch boundary, pending event | A temporary view must be restored without exposing wrong bytes or corrupting exception order. |

Many weak hypervisors fail in the same place: they trap the event but do not preserve the state around it. Analysis has to keep four things together: why the exit happened, what the CPU reported, what the handler changed, and what the guest observed next.

The lifecycle is `route -> qualify -> handle -> restore or reinject -> re-enter -> observe`. A cheat-facing hypervisor wants to make only the useful exits expensive: the ones that help with information, view control, or timing. Nearby behavior still has to remain coherent. If a CPUID route changes, MSR and feature state must still agree. If an EPT violation is handled, invalidation and resumed execution must still agree. If a timer route is transformed, APIC, QPC, reference TSC, and server-observed timing must still describe one timing story.

CR3 tracking deserves a special caveat on modern Windows. A CR3 load can look like a process-boundary signal, but PCID, KVA shadowing/KPTI, scheduler epochs, thread migration, kernel/user address-space splits, and nested or enlightened virtualization can all change what that transition means. A useful process-tracking loop needs the old root, new root, vCPU, thread/process epoch, PCID context, and first-stage replay. An image name or later PID lookup is not enough.

A local transition check usually needs:

| Check | What changes | What the mechanism can still say if the bridge is missing |
|---|---|---|
| route substitution | keep the event shape, but change the control bit, bitmap, or nested synthetic owner | route owner is still uncertain |
| qualification removal | keep the event, but remove exit qualification, `EXITINFO`, GLA/GPA validity, or instruction information | exit payload is missing |
| emulation replay | replay the same instruction with different flags, MSRs, segment state, debug state, or pending event | emulation correctness is not established |
| return-state replay | keep the handler result, but change RIP advancement, pending event, interruptibility, or invalidation epoch | re-entry state is still uncertain |
| timebase replay | keep the timer intercept, but compare TSC, QPC, APIC timer, Hyper-V reference TSC, and server clocks | timebase is still uncertain |
| platform-route replay | keep guest-visible behavior, but swap native VMX/SVM, TLFS synthetic, nested, or hosted route state | platform owner is still uncertain |
| semantic-bridge removal | keep the intercept state, but remove process, object, frame, input, or replay joins | native intercept state only |

An intercept row names a control-plane event. It does not describe cheat capability until return-to-guest state, semantic bridge, and delivery path all line up in the same epoch.

#### Vendor-Native VM-Exit State Flow

A VM exit is a routed transition from guest execution to a handler. Four pieces of state matter:

1. The control invariant that made the event interceptable.
2. The vendor-native payload written by hardware.
3. The handler decision and any emulated result.
4. The re-entry state that the guest later observes.

Intel and AMD expose different native payloads. A normalized `vm_exit` event is useful for high-level monitoring, but it is too weak for a technical explanation unless the original payload and control state survive.

| State layer | Intel VMX fields or controls | AMD SVM fields or controls | What this layer can really say |
|---|---|---|---|
| route owner | current VMCS, pin-based controls, primary and secondary processor-based controls, exception bitmap, CR masks and shadows, I/O bitmaps A/B, MSR bitmaps, EPTP, APIC-access controls, VMCS shadowing state | current VMCB, intercept vectors, exception intercepts, IOPM/MSRPM pointers, pause-filter state, virtual interrupt controls, `NP_ENABLE`, `N_CR3`, clean bits, ASID, AVIC state where present | Name the control family that could legally route the event before interpreting the exit. |
| raw reason | VM-exit reason field, basic exit reason, VM-entry failure flag, exit-from-enclave context where applicable | `EXITCODE`, SVM exit class, architecture-specific exit value | The reason identifies the hardware path, not the semantic meaning. |
| qualification payload | exit qualification, VM-exit interruption information, VM-exit interruption error code, IDT-vectoring information, IDT-vectoring error code, instruction length, instruction information, guest linear address, guest physical address | `EXITINFO1`, `EXITINFO2`, `EXITINTINFO`, `EXITINTINFO` validity, event-injection fields, `NRIP`, instruction bytes when available | Preserve undefined, invalid, or reason-dependent fields as absent instead of zero-normalizing them. |
| address-root context | guest `CR3`, PCID, paging mode, EPTP, VPID, guest `RIP`, CPL, interruptibility state | guest `CR3`, ASID, `N_CR3`, paging mode, guest `RIP`, CPL, GIF/interrupt shadow state where relevant | A control-register, page, or I/O exit without root context cannot become process-memory meaning. |
| handler mutation | VMCS writes, EPTP or leaf changes, MSR/CR emulation, event injection, MTF enablement, `INVEPT`/`INVVPID` action | VMCB writes, NPT leaf changes, MSR/CR emulation, `EVENTINJ`, clean-bit update, `TLB_CONTROL`, `INVLPGA`, `INVLPGB`, `TLBSYNC` action | Handler action is part of the event state, not an implementation detail. |
| re-entry closure | `VMLAUNCH`/`VMRESUME` result, VM-instruction error on failure, guest-visible register/memory/event result, next exit reason if chained | `VMRUN` result, VMCB consistency result, guest-visible register/memory/event result, next `EXITCODE` if chained | A trapped event is not closed until the returned guest state is recorded. |

That changes the meaning of common intercept descriptions:

| Shortcut description | Missing field that usually weakens it | Mechanism-limited description |
|---|---|---|
| "CPUID was spoofed" | returned leaf/subleaf registers, hypervisor-present bit, vendor leaves, MSR and Windows feature-state join | possible CPUID-return change under one feature-story epoch |
| "CR3 exits track the game process" | process lifetime, thread/vCPU, PCID, KVA split, scheduler epoch, old/new root, first-stage replay | possible address-space transition |
| "MSR exits show a hidden hypervisor" | MSR number/value, MSR bitmap owner, Hyper-V/VBS owner, synthetic MSR rule, guest-visible result | possible MSR virtualization inconsistency |
| "Exception interception hid a debugger" | vector, error code, IDT-vectoring state, pending event, `DR6/DR7`, reinjection result, debugger observer | possible debug-event coherence issue |
| "RDTSC exits masked latency" | TSC offset or scaling, per-core skew, QPC/HPET/APIC/network correlation, power-state context | possible local time transform |
| "I/O or MMIO was emulated" | port or GPA, instruction information, ordering, state changes, device model, guest observer | possible device emulation |
| "EPT or NPT exit shows memory redirection" | vendor-native fault payload, old/new leaf, invalidation, path diversity, Windows page-state join | possible second-stage view change |

#### Control Provenance and Nested Ownership

The key observation is whether the complete path forms one coherent chain: control route, native payload, handler mutation, invalidation or clean-state action, and re-entry result. Variants can rename modules, compress handlers, or move policy into another layer. They still face the same constraint.

This distinction matters in nested and VBS-enabled Windows systems. Intel physical VMCS fields are not the same state as Hyper-V enlightened VMCS fields. AMD architectural VMCB fields are not the same state as Hyper-V's reserved enlightened VMCB area at offset `0x3E0-0x3FF`. A bitmap address carries little authority unless the owning control object, clean-field epoch, logical processor, and capability gate are known. A stale eVMCS clean field can make an L0 hypervisor legally use older cached state. An ASID flush under enlightened NPT may not invalidate the nested-page translations the control path expected to change. Those are control provenance failures, not ordinary logging gaps.

The practical Intel/AMD differences matter more than the field-name differences. Intel #VE and suppress-VE style EPT behavior do not have a direct AMD NPT counterpart. Intel PML-style logging and AMD nested-page-fault or dirty/accessed-state behavior should be described by the signal they produce, not treated as interchangeable names. Intel VPID/INVEPT/INVVPID and AMD ASID/`TLB_CONTROL`/`INVLPGA`/`INVLPGB`/`TLBSYNC` also create different invalidation stories. A portable explanation should name the function, the owner, and the currentness rule rather than assuming an Intel mechanism has an AMD twin.

Control provenance is stricter than CPUID/MSR feature discovery. CPUID and MSR capability state can say a processor can support a field. VM-entry and VMRUN state says a selected control object passed enough checks to run. Exit payload says a specific event arrived. None of those alone says the current observation belongs to an unknown cheat layer. The state chain has to bind all three: capability, current object, and event epoch.

| Mechanism description | Fields that must be present | Common shortcut | Mechanism-limited meaning |
|---|---|---|---|
| Intel VMCS controls configured this exit | current VMCS identity and lifecycle, VMXON state, `IA32_FEATURE_CONTROL`, fixed CR0/CR4 masks, allowed-0/allowed-1 masks, pin/primary/secondary/tertiary/exit/entry controls, exception bitmap, CR masks/shadows, I/O bitmap A/B, MSR bitmap, EPTP, VPID, APIC or posted-interrupt controls, VM-entry result, read-only exit fields | treating an exit reason as enough to say a named VMCS policy was current | possible VMCS policy only |
| AMD VMCB controls configured this exit | VMRUN source, VMCB system-physical address identity, control area snapshot, save-state context, intercept vectors, exception intercepts, IOPM/MSRPM base, ASID, `TLB_CONTROL`, `NP_ENABLE`, `N_CR3`, clean bits, AVIC state when used, `EXITCODE`, `EXITINFO1`, `EXITINFO2`, `EXITINTINFO`, `nRIP` or decode-assist context | using Intel VMCS vocabulary for an AMD exit without VMCB identity and NPF ordering | possible VMCB policy only |
| Nested Hyper-V owns this control plane | root/guest partition role, CPUID leaf `0x40000004` for eVMCS, leaf `0x4000000A` for nested features, VP assist page, eVMCS version and `CleanFields`, eVMCB reserved area and clean bit, `VpId`, `VmId`, `PartitionAssistPage`, direct virtual flush setting, enlightened MSR bitmap state, enlightened NPT TLB state | treating nested behavior as a bare-metal L0 signal, or treating stale clean-field state as fresh control state | possible nested-control state only |
| MSR or I/O bitmap means access was monitored | bitmap physical identity, owner VMCS/VMCB/eVMCS/eVMCB, read/write or port bit calculation, range coverage, clean-field invalidation if enlightened, L0/L1 ownership, exit payload and returned guest value | stating a monitored access from a bitmap pointer without establishing the active owner and clean-field epoch | possible bitmap state only |
| Control state is current across cores | logical processor id, current VMCS/VMCB identity, VMCS epoch or clean-bit value, ASID/VPID/EPTP or `N_CR3`, invalidation action, per-core resume sample, migration or nested-root switch trace | using a single-core sample to explain a multi-core process-memory event | possible stale control state |
| Legitimate Hyper-V, VBS, VTL, or Device Guard explains the signal | hypervisor-present story, TLFS feature leaves, VBS/HVCI/VTL state, synthetic MSR owner, secure-kernel or root-partition context, nested role, eVMCS/eVMCB ownership, endpoint policy source | labeling normal platform virtualization as hostile because a VMX/SVM field exists | platform owner not resolved |

Control state is mechanical because provenance is a chain of consumed owners and epochs:

```text
control_story_ready =
  control_object_identity_bound
  and capability_gate_replayed
  and control_fields_current
  and entry_or_exit_payload_bound
  and mutation_or_clean_field_action_observed
  and per_core_owner_consistent
  and platform_owner_explained
```

If the first four checks hold but the owner is still unclear, the trace stops at possible native control state. If mutation or clean-field action is missing, it stops at possible stale control state. If the platform owner is missing, it cannot separate ordinary Hyper-V, VBS, nested virtualization, hosted-tool behavior, or an unknown layer.

#### Control State to Process-Memory Meaning

This context also tightens process-memory meaning. A second-stage fault that names `GPA X` is not yet a process-memory event. The chain is:

```text
target GVA
  -> CR3/PCID or ASID-bound first-stage walk
  -> GPA
  -> EPTP or N_CR3-bound second-stage walk
  -> SPA or host-backed memory source
  -> active VMCS/VMCB/eVMCS/eVMCB control object
  -> native fault or acquisition payload
  -> invalidation, TLB, or clean-field epoch
  -> Windows page-state and read-behavior parity
  -> engine object, disclosure, and behavior authority
```

| Field family | Intel authority and fields | AMD authority and fields | State needed before higher-layer meaning |
|---|---|---|---|
| CPUID and feature masking | CPUID exiting control, returned leaf/subleaf registers, VM-execution controls, feature MSRs, and hypervisor-present policy | CPUID intercept, returned leaf/subleaf registers, SVM feature leaves such as Fn8000_000A, feature masking policy, and VMCB intercept state | Preserve input leaf/subleaf, returned registers, policy source, and guest-visible OS state. Without the returned register trace and policy owner, the most it can say is that one feature story was presented to the guest. |
| Control-register and address-space tracking | CR0/CR4 masks and shadows, CR3-target controls, exit qualification, guest CR3, PCID-relevant state, and VPID context | CR intercept bits, VMCB CR fields, guest CR3, ASID, `TLB_CONTROL`, and intercept payload | Preserve old/new root, vCPU, thread/process epoch, address-space owner, and first-stage replay. Without a closed root epoch, the row is only a possible CR-context transition. |
| MSR and I/O permission maps | MSR bitmap address, I/O bitmap A/B addresses, bitmap bit calculation, VM-exit instruction information, and returned MSR/I/O value | MSRPM and IOPM bases, `MSR_PROT`, `IOIO_PROT`, VMCB clean-bit `IOPM`, decode assist, and returned value | Preserve bitmap physical source, bitmap hash, bit index derivation, exit payload, emulated value, and re-entry result. Without the bitmap source and bit math, the row stays a permission-map observation. |
| Event injection and interrupted delivery | VM-entry interruption-information field, VM-entry exception error code, IDT-vectoring information field, VM-exit interruption information, and instruction length | `EVENTINJ`, `EXITINTINFO`, exception/error-code payload, interrupt shadow, `nRIP`, and decode assist | Preserve vector, type, error code, pending event, interrupted event, handler action, and reinjection result. If the original event is not joined to the delivered event, narrow to event-continuity state. |
| Second-stage fault payload | EPTP, EPT violation qualification, EPT misconfiguration payload, guest-linear-address valid bit, guest physical address, #VE conversion controls, and suppress-VE state | `NP_ENABLE`, `N_CR3`, NPF exit code, `EXITINFO1`, `EXITINFO2`, guest virtual address where valid, ASID, and NPT permissions | Preserve native payload, old/new leaf, page-walk level, final or non-final translation label, memory type where relevant, and invalidation action. Without native payload retention and leaf replay, the most it can say is that a second-stage payload existed. |
| Invalidation and currentness | `INVEPT` type and descriptor, `INVVPID` type and descriptor, EPTP, VPID, VMCS pointer, and per-logical-processor current VMCS state | `TLB_CONTROL`, `INVLPGA`, `INVLPGB`, `TLBSYNC`, ASID, `N_CR3`, VMCB clean bits, and per-core execution epoch | Preserve target, scope, completion, and stale-translation probes. A field changed without matching currentness state is a possible stale-field row. |
| Interrupt and APIC virtualization | Virtual-APIC page address, APIC-access page, EOI-exit bitmap, virtual-interrupt delivery controls, posted-interrupt descriptor, posted-interrupt notification vector, and virtual APIC page state such as VTPR, VPPR, VEOI, VISR, VIRR, and VICR | VINTR controls, AVIC enable/state, virtual interrupt state, physical/logical APIC backing, and interrupt intercept payload | Preserve vector, priority, posted or virtual state, EOI/TPR relation, injection path, and guest-visible delivery. Without the delivery witness, narrow to interrupt-delivery state. |
| Nested enlightenment | eVMCS field mapping, VP assist page state, enlightened VMCS version, clean fields, synthetic fields without physical encoding, and direct virtual flush parameters | Hyper-V eVMCB bytes in the reserved VMCB control range `0x3E0-3FF`, clean bit 31, enlightened MSR bitmap path, direct virtual flush participation, `VpId`, and `VmId` | Preserve L0/L1/L2 owner, active object, clean-field epoch, selected VP/VM, and whether the field is architectural or synthetic. Without owner separation, the row is only nested-owner state. |
| Time transform and timers | TSC offsetting/scaling controls where available, VMX preemption timer, timestamp-counter exiting policy, Hyper-V reference TSC page relation, and guest-observed QPC/TSC | `TSC_OFFSET`, TSC-ratio support where implemented, timestamp intercepts, virtual timer controls, and guest-observed QPC/TSC | Preserve host and guest time samples, scale/offset, vCPU epoch, migration or reenlightenment state, and per-core skew checks. Without a closed timebase, narrow to local timebase state. |

An observation at the PFN level becomes process/page state only when region ownership, PTE interpretation, physical-page state, backing source, and second-stage acquisition describe the same process/page generation:

```text
field_story_ready =
  source_authority_current
  and capability_gate_replayed
  and control_object_current
  and configured_field_bound
  and runtime_event_state_present_if_needed
  and mutation_currentness_closed_if_field_changed
  and external_bridge_present_for_process_or_game_meaning
```

This is the limiting point. A configured control field without runtime state is only configured policy. A runtime VM-exit payload without the active control object and handler/re-entry trace is only a native event. A changed VMCS/VMCB field without invalidation, clean-field, or per-core re-entry state is possible stale-field state. A second-stage fault without Windows page-state, process-memory, or engine bridge remains a CPU translation event, not a process or gameplay fact.

For Intel VMX, preserve the distinction between VMCS currentness and field contents. `VMPTRLD`, `VMREAD`, `VMWRITE`, `VMLAUNCH`, `VMRESUME`, `VMCLEAR`, `INVEPT`, and `INVVPID` describe operations on a specific logical processor and context. The state chain should name the VMCS pointer, launch/current state, capability MSRs used to validate controls, read-only exit fields, and invalidation descriptors. A dump of an EPTP-like value or a pasted exit qualification is not enough to establish that the field routed a live event.

For AMD SVM, preserve the distinction between VMCB memory contents, cached VMCB state, clean bits, ASID ownership, nested paging state, and TLB control action. `VMRUN` consumes VMCB state, `NP_ENABLE` and `N_CR3` identify the nested paging root, and NPF payload fields identify the native second-stage fault. Because nested paging state such as `nCR3` can be loaded from the VMCB without being written back on every exit, the story must show the load epoch and not just the post-exit VMCB bytes. A stale VMCB snapshot can be true as memory state and still false as event authority.

For Hyper-V nesting, do not collapse enlightened objects into bare-metal VMCS/VMCB semantics. On Intel, eVMCS currentness is mediated by the enlightened VMCS model, clean fields, and VP assist state, with some synthetic fields having no physical VMCS encoding. On AMD, enlightened VMCB state uses TLFS-defined reserved control bytes and clean-bit semantics. A nested trace that cannot identify L0, L1, L2, the active enlightened object, and the clean/current epoch cannot support an unknown-control explanation, even if its field names resemble vendor-native structures.

### Virtual Machine Introspection

VMI means observing a guest from outside the guest, but that phrase hides three separate authorities: how the observer obtains bytes or events, how it reconstructs OS state, and how it turns that state into application semantics. Tools and systems such as LibVMI, vmi-rs, KVMi, HVMI, DRAKVUF, and research systems expose a common pattern:

```text
guest registers + guest page tables + guest memory
  -> OS object reconstruction
  -> process and module context
  -> application or game semantics
```

VMI starts with raw bytes, register state, event notifications, and backend-specific projections. It only reaches "enemy player" after each timeline is tracked: when the bytes were acquired, when OS state was reconstructed, when game meaning was decoded, and when the result was delivered. Those timelines decide whether the bytes describe a live process object, a stale sample, a render-only copy, or a gameplay-authoritative fact.

VMI is an observation discipline with several possible backends. A VMI backend can be a Xen/altp2m monitor, a KVMi event stream, a LibVMI physical or virtual read, a Hyper-V acquisition path, a debugger bridge, a QEMU memory-slot harness, or an offline dump parser. Those backends expose different authority. Some can pause the guest. Some can mutate permissions. Some can read only a snapshot. Some can receive events but lose traces under pressure. A sentence that says only "VMI observed object X" skips the state that decides what was actually observed.

Treat every VMI observation as a four-timeline problem:

```text
vmi_observation_clocks:
  guest_execution_clock:
    vcpu, rip, cpl, cr3, interruptibility, scheduler_state
  memory_visibility_clock:
    first_stage_root, second_stage_root, page_state, cache_or_snapshot_epoch
  observer_clock:
    backend, pause_policy, event_queue, loss_model, mutation_budget
  semantic_clock:
    os_profile, symbol_epoch, object_generation, game_tick_or_replay_tick
```

| Observation | Direct meaning | Do not infer until the next state joins |
|---|---|---|
| LibVMI `vmi_read_pa` or physical access | bytes came from one physical acquisition source | target process ownership, residency, or Windows access parity |
| LibVMI `vmi_read_va` or PID virtual translation | the tool used an OS/profile-mediated address-space interpretation | current process lifetime, COW generation, or game object authority |
| LibVMI page-table lookup or nested lookup | a translation relation was produced under selected roots and page modes | that the translated page was resident, fresh, or semantically correct |
| vmi-rs `AccessContext::direct` | direct physical access through the selected driver | guest virtual or process memory truth |
| vmi-rs `AccessContext::paging` or `AddressContext` | paging-based access with a stated virtual address and root | that the root belonged to the intended process epoch |
| vmi-rs `VmiContext` event | event-time registers and event data were available under that backend | non-mutating observation or endpoint equivalence unless action and backend limits are recorded |
| KVMi event or action | a patched KVM/QEMU/libkvmi stack produced or acted on an event | mainline KVM behavior, Hyper-V behavior, or production endpoint behavior |

A VMI API name tells you what operation was performed, not what the result means. `read`, `translate`, `pause`, `monitor`, `single-step`, and `decode` each stop at a different layer. Carry that layer forward instead of replacing it with "process memory" or "game object."

Keep backend freshness visible before treating a tool result as game memory:

| Backend or tool family | Direct low-level meaning | Missing context before it becomes game memory |
|---|---|---|
| Xen altp2m, DRAKVUF, and Xen vm_event | Xen view-control or plugin-scoped VMI state under a named Xen build, guest profile, LibVMI layer, EPT capability, active view, event stream, and vCPU policy | Xen-view state only until active view id, raw event stream, profile hash, reinjection or action effects, vCPU synchronization, and endpoint CPU/vendor bridge are retained |
| LibVMI events | backend-supported event observation under a named hypervisor, initialization mode, event type, access mode, pause policy, permission relaxation, single-step or re-registration, and callback path | `vmi_backend_event_only` until root epoch, failed-access accounting, raw page hash, OS page-state replay, event loss model, and independent acquisition are retained |
| KVMi, KVM-VMI, and libkvmi | patched-stack introspection ABI state with command and event masks, version, vCPU state, page-access mutation, action reply, and QEMU/KVM bridge | `patched_stack_only` until ABI version, event registration, action transcript, vCPU coverage, trace join, and endpoint comparator are retained |
| HVMI | design or integration state from a named repository, build, downstream, and hypervisor connector | `historical_design_state` unless current maintenance state, build provenance, event payload, endpoint comparator, and support envelope are retained |

Separating the layers prevents a common jump from tool name to game state. A DRAKVUF plugin row may be excellent Xen/LibVMI state; it is not automatically AMD NPF, Hyper-V, or bare-metal Windows behavior. A KVMi notification may be excellent patched-KVM state; it is not mainline KVM or game-client state. LibVMI physical bytes may be excellent acquisition state; they are not Windows access parity, process lifetime, or game authority without the process-memory state set.

Keep the layers separate. `GPA X contained bytes Y` is lower-level than `process P had object O`, and `process P had object-like bytes` is lower-level than `server-authoritative entity O existed`. Each step should keep both the state it can support and the missing joins needed to move higher.

#### Below-OS Process-Memory Acquisition

Below-OS acquisition reaches process memory only after several ownership transitions line up. A hypervisor, host debugger, dump parser, or VMI backend may obtain bytes without using `OpenProcess`, without holding a Windows handle, and without matching the exact `ReadProcessMemory` behavior. That is a strength for acquisition and a weakness for meaning. The mechanism changes depending on whether the below-OS sample is equivalent to, weaker than, or stronger than an OS-mediated process-memory read.

| Acquisition step | Owner of the fact | State to preserve | Common shortcut | Meaning if isolated |
|---|---|---|---|---|
| address-space root selection | scheduler, process object, CPU context | PID plus process lifetime key, CR3/DTB, PCID or ASID, vCPU/core, thread context, TSC/QPC window, KVA or compatibility view | a later PID or image name is treated as the event's process | address-space state |
| first-stage reachability | guest paging architecture and Windows page state | GVA, canonicality, paging mode, PTE chain, large-page stop, U/S, R/W, NX, present, transition, prototype, COW, guard, demand-zero, pagefile or unknown backing | valid GPA means Windows would expose the byte | translation state |
| second-stage reachability | EPT/NPT owner or hosted acquisition backend | EPTP or `N_CR3`, GPA/PFN, leaf chain, permissions, memory type, A/D state, ASID/VPID, invalidation or stale-translation state | clean guest PTE means no lower-layer shaping | second-stage byte state |
| physical or host read | VMM, host, dump, VMI driver, or debugger | backend, pause/freeze policy, missing-page policy, page hash, partial-read status, mutation footprint, raw source id | a physical byte is current live process memory | acquisition sample |
| Windows region parity | Windows memory manager behavior | `VirtualQueryEx`-style base/allocation/protection/type/state, guard/writecopy/image/private/mapped class, query epoch | below-OS bytes inherit OS access semantics | process-region state |
| residency and private-generation parity | working-set and backing-source behavior | `QueryWorkingSetEx`-style validity, Shared bit, large-page or AWE state, locked/resident state, COW/private generation, section or pagefile source | image/mapped bytes, private COW bytes, and paged-out bytes are the same class | process-byte state |
| OS-read equivalence | documented read-access behavior | range accessibility, page-boundary coverage, fault materialization policy, `ReadProcessMemory` parity or explicit non-equivalence | any successful VMI read equals `ReadProcessMemory` | OS-readable state |
| coherent range assembly | acquisition layer plus OS memory manager | per-page hashes, same epoch, no handler mutation before sample, no torn pointer chain, same object generation | one page is treated as a multi-page structure | coherent process range |
| semantic bridge | engine, replay, and server authority | object root, class state, allocation generation, replication/relevance, prediction/replay tick, delivery or behavior bridge | bytes that decode as an object are treated as player knowledge | semantic-object state |

The key question is which semantic boundary the read actually crossed. Microsoft documents `VirtualQueryEx` as a region query over pages sharing state, protection, and allocation attributes; it also notes that copy-on-write pages may still be reported as mapped or image, and that the Shared bit from working-set information is needed to identify privatization.

`QueryWorkingSetEx` reports extended page information for selected virtual addresses, including addresses outside the current working set but still part of the process. `ReadProcessMemory` requires readable access across the requested range and fails if the range crosses inaccessible memory.

A below-OS sample that bypasses those OS read semantics may be valuable, but it carries different authority from an OS-mediated process read.

When the chain is incomplete, the mechanism stops here:

| Surviving state | Mechanism-limited meaning |
|---|---|
| GPA/PFN plus raw bytes only | below-OS byte sample |
| GVA, CR3/DTB, and first-stage walk only | address-space translation state |
| first-stage plus EPT/NPT or backend state | second-stage acquisition state |
| Windows region and working-set parity | process-byte state |
| range coherence and no mutation contamination | coherent process-memory state |
| object generation plus engine/replay authority | semantic-object state |
| semantic object plus delivery, input, or behavior bridge | gameplay-relevant information state |

#### When a Below-OS Read Becomes Process Memory

The invariant is acquisition-to-process equivalence. A below-OS byte read does not inherit Windows process-memory semantics just because the page-table walk succeeds or the PFN can be sampled. It becomes process-memory state only when every authority transition lines up: process identity to address-space root, first-stage translation to second-stage or backend acquisition, raw sample to Windows region/residency semantics, and coherent range to game-semantic use.

For cheats, the attraction is access without ordinary guest-local ownership signals. A hypervisor, host VMI stack, DMA coordinator, or debugger path can avoid handles, modules, and user-mode API traces inside the guest. That relocation is meaningful, but it also removes the OS behavior that would normally say which process, which range, which protection, which residency state, and which failure behavior applied. The first missing bridge matters more than the mere presence of bytes:

| Missing bridge | What the sample can still support | What it must not imply |
|---|---|---|
| root epoch missing | raw or address-space state | that PID or image name owned the sample at event time |
| first-stage walk missing | GVA hypothesis | that the guest page tables reached the byte |
| second-stage currentness missing | guest translation state | that the VMM/backend delivered current physical memory |
| Windows region join missing | below-OS acquisition state | that Windows would classify the address as committed/readable process memory |
| working-set join missing | region state | that the page was resident, shared/private, large-page, AWE, or COW-correct |
| OS-read parity missing | below-OS byte sample | that `ReadProcessMemory` would have succeeded across the same range |
| range torn across pages | per-page state | that a multi-page pointer chain or object was coherent |
| semantic bridge missing | process-memory state | that the bytes were game-authoritative player knowledge |

A process-memory path needs OS-equivalence state in addition to raw acquisition state. The minimum cross-check is to hold the raw bytes stable while changing one authority layer. Reuse the PID after process exit, switch CR3 under the same image name, split the requested range across a guard or inaccessible page, force copy-on-write privatization, evict or page out the backing, cross a large-page or AWE boundary, pause only one vCPU while another mutates the object, or keep the object-shaped bytes while changing the allocation generation. If the meaning does not narrow when any of those changes removes the corresponding bridge, the path is being treated as stronger than it is.

#### Where Process-Memory Reconstruction Fails

A below-OS process-memory path is composed state, not a primitive. It can fail before the first byte is read, during either translation stage, at the Windows region model, at residency, during range assembly, at execution-policy interpretation, or when raw bytes are turned into an engine object. The field names below are state requirements, not implementation steps.

| Failure surface | State that must be retained | What it can support | If it is missing |
|---|---|---|---|
| root-epoch ambiguity | PID, process object or generation, image identity, creation time, CR3/DTB, PCID or ASID, vCPU, thread, CPL, KVA or compatibility view, TSC/QPC | the sampled address root belonged to the intended process epoch | address-space state |
| first-stage walk ambiguity | canonicality, LA57 or four-level mode, PML5/PML4 through PTE chain, large-page stop, U/S, R/W, NX, present, accessed/dirty, page-fault class, prototype/transition marker when sourced from Windows | GVA translated to GPA under the selected root and paging mode | translation state |
| second-stage reachability | EPTP or `N_CR3`, EPT/NPT leaf chain, GPA, SPA, permission bits, memory type, A/D state if enabled, SPP/MBEC/#VE or NPF attributes where present, invalidation epoch | physical backing was reachable under a named second-stage root | acquisition state |
| OS region mismatch | `MEMORY_BASIC_INFORMATION` `BaseAddress`, `AllocationBase`, `AllocationProtect`, `RegionSize`, `State`, `Protect`, `Type`, query time, allocation/protection epoch | the address belonged to a Windows-classified region | process-region state |
| working-set/private-generation ambiguity | `PSAPI_WORKING_SET_EX_BLOCK.Valid`, `Win32Protection`, `Shared`, `ShareCount`, `Node`, `Locked`, `LargePage`, `Bad`, invalid-entry interpretation, COW/private generation | the page had selected process working-set attributes at that query epoch | process-byte state |
| read-behavior mismatch | handle rights, requested VA range, all-page readability, inaccessible-boundary behavior, guard/COW state change, bytes-read result, guest fault or OS oracle result | the below-OS sample is equivalent to a named OS-mediated read behavior | below-OS sample only |
| guard or one-shot state | `PAGE_GUARD`, underlying protection, first guarded access epoch, exception or fault result, clear/re-arm observation, page boundary | access semantics were guard-sensitive and one-shot behavior was accounted for | byte sample without access-semantic parity |
| CFG/CET/execution-policy mismatch | NX, executable protection, `PAGE_TARGETS_INVALID`, `PAGE_TARGETS_NO_UPDATE`, dynamic CFG update source, CET or shadow-stack relevance, HVCI/KCFG/KCET owner when cited | the page had a bounded execution-authority context | data-byte state only |
| range assembly and torn snapshot | per-page hash, per-page epoch, vCPU pause/freeze state, handler mutation, missing pages, pagefile or dump source, object pointer-chain epoch | the range is coherent process-memory state | page-fragment state |
| semantic bridge gap | object root, allocator generation, class/schema source, module/symbol epoch, lifetime marker, replication/relevance/visibility/server epoch | bytes can be discussed as object state under a named semantic authority | raw process-memory state |

#### Replaying Windows Page State

Windows page-state has more than one clock. A page-table walk names a translation epoch. `VirtualQueryEx` names a region epoch. `QueryWorkingSetEx` names selected page attributes at a query epoch. `ReadProcessMemory` names all-range access behavior for one handle and caller context. A hypervisor, dump parser, or VMI backend may see bytes that are real while still being wrong about which Windows clock would have accepted the access. The worksheet below keeps those clocks separate.

Use this split when a below-OS sample is being turned into Windows process-memory meaning:

| Replay question | State that must agree | Failure label |
|---|---|---|
| Was the address inside a committed Windows region? | `State`, `Protect`, `Type`, region start/end, allocation base, query epoch, page-boundary split | region not established |
| Did region protection and page protection agree? | `Protect`, `AllocationProtect`, `Win32Protection`, executable/readable/writecopy bits, DEP/NX relevance | protection clocks disagree |
| Did COW change byte ownership? | `MEM_IMAGE` or `MEM_MAPPED` type, writecopy protection, working-set `Shared` bit, share count, private generation, mapped file offset | COW generation not established |
| Was the page resident, transition, demand-zero, paged, or store-backed? | working-set `Valid`, transition or demand-zero state, pagefile/store hint, acquisition miss policy, fault counter or debugger-derived state | residency clock not established |
| Did a guard page change state during observation? | `PAGE_GUARD`, first guarded access epoch, exception or service failure, clear/re-arm observation, second-read behavior | guard one-shot behavior not established |
| Would the exact range satisfy `ReadProcessMemory`? | handle rights, all pages readable, inaccessible-boundary split, bytes-read count, failure code, explicit non-equivalence if bypassed | OS-read parity not established |
| Did a large page or AWE allocation escape ordinary working-set assumptions? | large-page bit, AWE or locked mapping state, `QueryWorkingSetEx` coverage, first-stage large-page stop, second-stage narrowing state | nonpageable mapping not resolved |
| Did mapped file, image, or section aliasing change meaning? | section or file object identity, view offset, image/data type, relocated image state, private COW fork if present | section alias not resolved |
| Did execution policy matter? | execute protection, `PAGE_TARGETS_INVALID`, `PAGE_TARGETS_NO_UPDATE`, CFG update source, CET or shadow-stack context, second-stage execute permission | execution-policy context not joined |
| Did the acquisition path mutate the state being checked? | below-OS read route, page-in or materialization action, handler write, freeze/pause, snapshot age, raw source hash | acquisition changed the page state |

| State shape | Wording that still fits |
|---|---|
| below-OS bytes without Windows clocks | below-OS byte sample |
| translation plus committed region only | region-bound byte state |
| region plus working-set/private-generation replay | process-page state |
| region, working set, guard/COW, and all-range access parity | Windows-read equivalent sample |
| below-OS read reaches nonresident, paged, or store-backed bytes without OS-visible state changes | stronger acquisition than OS APIs, weaker OS semantics |
| CPU, Windows clocks, range coherence, and semantic object epoch all align | coherent process-memory state |

Compressed or store-backed pages need a narrower authority model. Microsoft documents the working-set, page-state, and pagefile APIs publicly, but the detailed association between compressed pages, store-manager structures, and original process pages is research-derived and version-sensitive.

A Black Hat 2019 compressed-memory paper shows one public method for walking from a software PTE toward the virtual store and warns that structure details changed across Windows releases. Windows 10 and Windows 11 builds can keep changing internal store and memory-manager layouts, so a 2019-era reconstruction is best treated as a method example rather than a stable ABI map.

Treat such state as research-derived backing reconstruction unless the Windows build, symbols, structure derivation, raw source, and a second verifier are all named. A decompressed page without a replayed owner remains backing-source state, not process-memory state.

#### Backing Sources and Compressed Pages

A common shortcut in below-OS memory reading is "the page was not resident, but the value was recovered." Recovery only proves a backing-source path; ownership still has to be shown. A page can be committed and nonresident, backed by a mapped file, backed by an image section, in transition, demand-zero, pagefile-backed, represented by a compressed-store path, or absent from the acquisition source. Each case changes how close the sample is to live process memory.

Microsoft's public APIs give three stable anchors. `VirtualQueryEx` is a region oracle and can continue to report a privatized copy-on-write page as `MEM_MAPPED` or `MEM_IMAGE`; the working-set `Shared` bit is the posted check for whether the page became private.

`QueryWorkingSetEx` is a selected-page oracle and can query virtual addresses that are not in the ordinary working set, including AWE and large pages. `PSAPI_WORKING_SET_EX_BLOCK` names page-level fields such as `Valid`, `ShareCount`, `Win32Protection`, `Shared`, `Node`, `Locked`, `LargePage`, and `Bad`, plus an invalid-entry interpretation.

Microsoft's memory-compression material only gives product-level behavior: trimmed memory may remain preserved in RAM in compressed form rather than immediately requiring a disk hard fault. The Black Hat compressed-memory work is useful, but it is research-derived structure traversal, not a Microsoft memory-manager ABI.

A more precise split is:

| State shape | What it can say | Missing bridge | If it is missing |
|---|---|---|---|
| `VirtualQueryEx` region only | region behavior for the queried process epoch | residency, COW generation, page content, access state change | region-clock state |
| `QueryWorkingSetEx` valid page | selected page was resident with reported page attributes | backing owner, object lifetime, second-stage view, gameplay epoch | resident-page state |
| working-set invalid entry | selected page was not a normal valid resident page under that oracle | transition/prototype/pagefile/compressed source and fault result | nonresident-page state |
| COW page with `Shared` cleared | page was private at the working-set query epoch | source byte generation and write epoch | COW private-generation state |
| mapped file or image backing | byte may be recoverable from a file or image section | process-private fork, relocation, section offset, current view epoch | file-backed source state |
| pagefile index and offset | possible backing-store location exists | live materialization result, process epoch, pagefile coverage | pagefile-backing observation |
| compressed-store path from research | compressed backing can be reconstructed by a version-specific method | documented ABI, build-stable structure state, second verifier | research-derived backing reconstruction |
| renderer zero-fill or missing-page repair | tool produced bytes despite missing backing | state showing that zeros or repaired bytes existed in the process | renderer-produced bytes |

Source and ownership discipline matter here. The page can be real, the decompressor can be correct, and the final bytes can still carry the wrong meaning. A compressed-page reconstruction establishes a path from a specific PTE interpretation to a backing source under a pinned Windows build and parser.

It does not establish that a user thread would have observed the same value, that the game object was live, or that a below-OS acquisition was equivalent to `ReadProcessMemory`. To move higher, the mechanism still needs process identity, range coherence, COW/private generation, fault replay or explicit non-equivalence, second-stage owner, and semantic epoch.

Nonresident-page handling needs these control comparisons:

| Check | What it contradicts | Required state |
|---|---|---|
| guest-side reread after materialization | decompressed or file-backed value differs from live process value | reread epoch, page-fault state change, byte hash |
| alternate parser or debugger | one tool's store/PTE interpretation is wrong | raw PTE, build symbols, parser version, second decoded value |
| pagefile or mapped-file offset replay | backing offset is stale, absent, or not the stated file | file identity, offset, hash, timestamp |
| COW private-generation check | shared file bytes were mistaken for process-private bytes | working-set `Shared`, writecopy protection, dirty/private generation |
| range torn-snapshot check | adjacent pages come from different clocks or sources | per-page source class, hash, acquisition epoch |
| zero-fill control | renderer filled missing memory and created a plausible object | missing-range map, renderer policy, raw acquisition state |

When those checks are missing, the state remains "backing-source observation" or "tool-derived reconstruction," not live process memory. This matters in game-memory reconstruction because an object parser can transform a missing-page repair into a believable entity. The semantic layer should not inherit authority from a reconstructed backing store until the Windows clocks and engine epoch have both been replayed.

#### Comparing Acquisition Routes

Hypervisor-backed memory access is often described as one capability: "read process memory from below the OS." That hides the meaning problem. A route that passively reads a host physical page, a route that arms an EPT/NPT fault, a route that samples dirty/accessed state, a route that freezes a VM and dumps memory, and a route that asks a hosted debugger for a guest page all cross different authority boundaries. They may all return bytes. They do not have the same semantic value.

The route itself sets the first limit:

| Route class | Direct fact | Main state change or blind spot | What it can say before joins |
|---|---|---|---|
| second-stage fault | a configured EPT/NPT policy boundary was crossed under a named root | handler mutation, MTF window, invalidation, page-walk ambiguity | second-stage access state |
| passive physical read | bytes were read from a physical or host-backed page | process owner, residency, COW/private generation, and semantic epoch are not inherent | below-OS byte sample |
| shadow or split view | different observers can be served different backing or permission state | view classifier, active root, currentness, and observer identity must be established | view-difference state |
| A/D, dirty log, or PML sampling | page-granular state changed or was logged | delayed, page-granular, write-biased or access-biased, not a typed object read | page-activity state |
| pause or freeze snapshot | a guest or process image was captured under a scheduler policy | torn range risk changes, but liveness and behavior timing are weakened | snapshot acquisition state |
| hosted debugger or LiveCloudKd-style acquisition | a host or debugger exposed selected guest memory through a declared backend | selected-VM identity, pause/write policy, volatility, and backend fragility dominate | hosted acquisition state |
| dump parser or memory-as-filesystem view | a parser decoded bytes from a static or live acquisition source | parser profile, symbol drift, unsupported ranges, and shared acquisition dependency | decoded-source state |
| OS oracle comparison | Windows API or debugger oracle described region, residency, or readability | the OS oracle does not establish second-stage ownership | Windows parity state |

Describe equivalence as a comparison across specific axes. A passive physical read can be stronger than `ReadProcessMemory` because it bypasses handle rights and guard-path failures. It is weaker than `ReadProcessMemory` when the meaning needs Windows all-range readability, COW/private generation, guard semantics, or user-thread observation. A paused dump can be stronger for range coherence and weaker for live action timing. A hosted debugger can be stronger for controlled acquisition and weaker for endpoint equivalence. Write the changed axis explicitly.

| Comparison axis | State that makes routes comparable | narrowing when missing |
|---|---|---|
| address equivalence | same CR3/DTB epoch, same GVA, first-stage walk, GPA, second-stage or backend mapping | address equivalence not established |
| byte equivalence | page hashes, range assembly id, retry policy, missing-page handling, materialization marker | byte equivalence not established |
| Windows semantic equivalence | region tuple, working-set state, COW/private generation, guard/read-behavior parity | OS-read equivalence not established |
| mutation equivalence | old/new leaf, pause/write capability, MTF or single-step state, page-in state change, backend write log | mutation budget missing |
| time equivalence | TSC/QPC, scheduler pause, frame/tick/replay epoch, acquisition order, dirty/access state | epoch equivalence not established |
| endpoint equivalence | same trust root, same nested role, same platform posture, same tool absence, independent endpoint comparator | endpoint equivalence not established |
| semantic equivalence | decoder profile, object generation, module/schema version, server or replay consequence | semantic equivalence not established |

The route works at the layer it actually reaches. For example: "the route produced a below-OS byte sample for GVA X under CR3 Y and EPTP Z; it is not yet OS-read equivalent because region, working-set, COW, and range-read parity are missing." If the route came through a hosted debugger, the host and backend matter. If it came through a fault loop, the handler mutation matters. If it came through a dirty-log surface, it is page activity rather than a read. The mechanism is easier to reason about when the authority boundary stays visible.

#### Where Each Tool Output Starts

Tool output does not enter the process-memory state chain at a uniform point. A HyperDbg `!monitor` row usually begins as a second-stage access event with EPT mutation and MTF/rearm state. A LibVMI read begins as a backend-mediated address or byte operation. A DRAKVUF plugin row begins as a Xen/LibVMI event interpreted through a guest profile.

A KVMi row begins as a patched KVM/QEMU/libkvmi action or notification. A LiveCloudKd or LeechCore `hvmm` observation begins as Hyper-V host acquisition. A Volatility row begins as a parser projection over layers and symbols. A QEMU or WHP row begins as a harness transition.

These starting points fall below Windows process-memory meaning until the missing state joins are connected.

A tool result only becomes process memory after its route context is attached:

| Tool family | What the tool can fill directly | Process-memory fields still missing | Maximum process-memory meaning before joins |
|---|---|---|---|
| HyperDbg `!monitor`, `!epthook`, `!epthook2` | access class, VA or PA mode, PID/core filter, event context, EPT permission mutation, page-in or materialization caveat, buffer/loss mode, MTF or rearm boundary | process epoch, Windows region, working-set and COW state, all-range read parity, range coherence, semantic object epoch | second-stage tool event |
| LibVMI and vmi-rs | physical, virtual, symbol, register, pause, snapshot, translation, typed address/access context, backend identity, failed-access row | Windows page-state clocks, process lifetime key, cache invalidation, COW/private generation, OS-read equivalence, independent acquisition | VMI address or byte state |
| DRAKVUF with Xen, LibVMI, and altp2m | Xen domain, LibVMI version, supported guest profile, raw vm_event stream, plugin row, altp2m/view-control context, vCPU/timebase | endpoint CPU/vendor equivalence, Windows page-state replay, plugin decode independence, live delivery or behavior bridge | Xen plugin event |
| KVMi, KVM-VMI, and libkvmi | patched-stack ABI, allowed command/event mask, pause/resume state, page-access mutation, event/action reply, GVA translation or physical read, ftrace or `trace_kvmi` row | mainline or production endpoint equivalence, Windows region/read behavior, mutation budget, process epoch, semantic bridge | patched-stack memory event |
| LiveCloudKd, LeechCore `hvmm`, MemProcFS Hyper-V acquisition | selected VM id when provided, Hyper-V host acquisition path, volatile live read/write route, VMRS saved-state read-only/static route, missing-range accounting, repeated page hash, parser handoff | dynamic-memory completeness, selected-VM state, guest page-state replay, OS-read parity, live process epoch, endpoint delivery bridge | Hyper-V host acquisition state |
| Volatility, MemProcFS parser view, WinDbg/KD projection | layer stack, symbol/PDB or profile source, plugin/command row, renderer output, raw offset where retained, failed-access inventory | acquisition independence, live epoch, state-change parity, range coherence, endpoint process view, engine semantic authority | parser or debugger projection |
| QEMU/KVM, WHP, gdbstub, QMP, and trace harnesses | machine or partition identity, vCPU/run context, memory slot or GPA map, QMP/gdbstub transcript, trace backend, virtual clock, synthetic stimulus | native endpoint VMCS/VMCB or EPT/NPT payload, production timing, Windows process clocks, game-authority bridge | hosted harness memory state |
| SimpleVisor, Bareflank/MicroV, bhyve, HyperPlatform, SimpleSvm, hvpp, and other baselines | source commit, vendor path, exercised launch/lifecycle, VMCS/VMCB/EPT/NPT fields when recorded, SDK or extension boundary | deployed endpoint owner, production control object, event-loss model, process-memory route, Windows and semantic joins | mechanism baseline only |

A tool result becomes process-memory state only after several joins. The tool's carrier, backend, address route, Windows page state, mutation budget, and dependency breaker all have to reach the same meaning layer:

```text
tool_to_process_memory_bridge =
  official_source_or_local_build_pinned
  and raw_carrier_retained
  and direct_tool_verb_preserved
  and route_starting_layer_named
  and address_path_replayed
  and windows_region_and_page_state_joined
  and read_behavior_or_explicit_non_equivalence_written
  and mutation_loss_budget_closed
  and range_coherence_closed
  and dependency_breaker_reaches_the_meaning_layer
```

If the first four terms hold, the result is a strong tool observation. If the address path also replays, the result has route state. If the Windows clocks join, it becomes process-page state. If read parity is absent but the route deliberately bypasses OS semantics, write that as non-equivalence rather than pretending to be `ReadProcessMemory`. If range coherence is absent, stop at page state. If the dependency breaker reaches only a parser layer, stop at parser-independent state. If it reaches Hyper-V host acquisition but not the guest's OS clock, stop at hosted acquisition.

Empty results have narrow scope for the same reason. A clean HyperDbg monitor result can mean the chosen page, access class, core, PID mode, buffer policy, or page-in state was not covered. A silent DRAKVUF plugin can mean the profile, plugin, view, event subscription, or supported-guest surface missed the event. An empty Volatility table can mean the layer stack, symbol table, plugin requirement, or acquisition image was incomplete. A MemProcFS filesystem view can be a renderer over LeechCore acquisition, not completeness. An empty result should carry the unsupported path before it is treated as absence.

For a tool observation, keep the covered fields and missing fields together so a strong tool result is not confused with process-memory authority:

```text
Tool T produced carrier C at layer L under backend B and epoch E.
The carrier covers fields P and leaves fields M missing.
Therefore the process-memory sentence can only say S.
```

Empty-route results need the same treatment. A clean route result only rules out the route that was actually covered. A clean EPT hook does not rule out passive physical reads. A clean OS read does not rule out a below-OS non-equivalent route. A clean parser result does not rule out a live route with a different page-state clock. The same fields are needed as for a positive result, plus the unsupported path that kept the result limited.

#### Semantic Reconstruction Layers

| Layer | Needed knowledge | Typical errors |
|---|---|---|
| CPU context | active vCPU, CR3, mode, interrupt state | reading during context switch or with wrong CR3 |
| OS context | process list, module list, kernel symbols, VADs, object lifetime | OS version drift and stale offsets |
| Engine context | world, object arrays, components, camera, transforms | game updates and object reuse |
| Temporal context | tick, frame boundary, interpolation, network replication | mixing values from different frames |

Different game engines expose object graphs in fundamentally different ways. In an Unreal Engine client, a reconstruction path often moves through a world object, level or scene state, actor collections, pawn/controller relationships, components, transforms, meshes, camera state, and replicated properties.

In a Unity client, the path may move through scene objects, `GameObject`/component state, transform hierarchies, managed/native bridges, or ECS-style chunks. The exact names differ, but the same rule holds: a byte pattern becomes useful only after object identity, lifetime, owner, transform, and authority are all current.

For games, temporal correctness has the same weight as address correctness. A reconstruction loop has to carry the simulation tick, render frame, camera sample, entity transform epoch, animation or bone epoch, network replication epoch, and delivery or input moment it is joining.

A camera matrix from frame N and an entity transform from frame N+1 is a different snapshot, not just a slightly stale one. It can create overlay drift, pre-aim against a state the player should not know, or a decision row that no replay timeline can reproduce. Until those timelines line up, the result is temporally incomplete object state.

One practical cross-check is a time-shift test: hold the decoded object identity constant, shift only the camera, transform, replication, or delivery time, and require the stated advantage to move or narrow with the shifted time.

Semantic reconstruction works by progressive refinement. Each layer narrows the previous layer's meaning, but each layer also adds a new way to be wrong. The layer needs its own owner, epoch, validation rule, and cross-check instead of inheriting truth from the byte source.

| Semantic layer | What it can show | What it cannot show alone | Cross-check |
|---|---|---|---|
| CPU/register state | which address root and execution context were sampled | process ownership, object lifetime, or game visibility | scheduler event, thread/process identity, CR3 transition trace |
| Windows memory state | whether bytes fit a process region, protection, residency, and backing-source model | live game object identity or server authority | `VirtualQueryEx`-style region state, working-set state, module list, section object state |
| engine object state | whether bytes match a known object/class/component surface | whether the object is relevant, replicated, visible, or current for this client | object root, class metadata, component graph, allocator generation, lifetime marker |
| network authority | whether the state is replicated, relevant, dormant, predicted, or server-confirmed | whether the player saw or used it | replication relevance, dormancy, movement prediction, server tick, rollback state |
| replay authority | what the server or replay model can reconstruct | the exact local memory acquisition path | replay tick, DemoNetDriver data class, replay-only fields, viewer override or spectator model |
| delivery authority | whether reconstructed information reached perception or input | how the bytes were acquired | output path, capture observer, input source, moment of action, server consequence |

This split matters for hypervisor cheats because a below-OS observer can be close to physical bytes while far from gameplay authority. To turn a raw sample into radar, ESP, or trigger timing, the cheat has to keep engine identity, replication authority, frame timing, and hint delivery time in the same time window. Object churn, replication boundaries, replay-only state, and delivery delay can make a technically correct memory sample produce a wrong hint even when the address translation was correct.

VMI tooling starts with low-level carriers, not game meaning. LibVMI-style APIs can read guest physical or virtual memory, access vCPU registers, pause a VM, and translate addresses. KVMi-style interfaces can expose vCPU state, page-access events, MSR events, pause/resume control, and page-permission mutations. DRAKVUF-style systems can trace execution without an in-guest agent. Those are powerful carriers, but the semantic profile is outside the carrier. The profile decides which OS build, symbol source, process object, module epoch, engine version, class surface, allocator generation, network authority, and replay model turn bytes into game-state meaning.

For a cheat, the reconstruction chain looks more like a dataflow:

```text
machine_state_sample
  -> address_route
  -> os_identity
  -> process_memory_state
  -> decoder_profile
  -> object_lifetime_epoch
  -> authority_surface
  -> temporal_snapshot
  -> disclosure_or_delivery_window
  -> input_or_game_consequence
```

A practical check is to break one arrow at a time. Keep the low-level memory route constant, then change only the decoder profile, object generation, map transition, replication state, prediction-correction point, or delivery route. If the supposed radar or trigger hint does not change when one of those arrows breaks, the low-level read was not the cause of the advantage. At that point the read was only a data source.

#### Semantic Gap Failure Modes

VMI literature uses "semantic gap" to describe the distance between raw machine state and OS/application meaning. For hypervisor-cheat mechanics, the gap has four separate layers. A variant may solve one and still fail another.

| Gap layer | Required model | How a cheat loses meaning | State that must remain joined |
|---|---|---|---|
| architectural gap | CPU mode, CR3/PCID, paging depth, canonicality, CPL, interrupt state | wrong address space during context switch; stale PCID or ASID interpretation | vCPU, RIP, CR3, PCID/ASID, CPL, paging mode, timestamp |
| OS gap | process lifetime, VAD/working set, module list, kernel symbols, memory compression/paging state | reads a valid page that no longer belongs to the intended process object | process object identity, generation, image path, module version, page residency |
| engine gap | object root, allocator, entity lifetime, component graph, replication authority | follows a real object that is not gameplay-authoritative or is intentionally decoy-like | object type, lifetime epoch, owning subsystem, server-visible authority |
| temporal gap | tick/frame, prediction, interpolation, render thread, server reconciliation | mixes camera, bones, and visibility from different times | frame/tick identifiers, local prediction state, snapshot boundary, read batch ID |
| delivery gap | overlay/input/stream path from extracted semantics to the player | memory view is clean but behavior reveals unavailable information | delivery channel, capture path, input timing, replay-visible decision |

Replication state determines whether an object is gameplay-authoritative. A replicated object may be present because the server sent state to the client, but that does not always mean the player can legitimately act on it. A relevant object is inside the server's update interest for that client. A dormant object can remain in client memory while receiving few or no active updates. A predicted object may briefly exist in a client-side future that later rolls back. A server-confirmed object has survived the authoritative game timeline. A cheat that treats all of these as the same category will produce stale radar, premature pre-aim, or trigger decisions that do not match replay.

A successful memory read is one stage in the cheat chain. It does not by itself constitute a working cheat. Every later semantic layer has to stay current: process identity, object lifetime, replication authority, camera frame, visibility state, hint delivery, and the final input or player decision.

The semantic gap behaves like an ordered state machine. A cheat may have valid bytes at `G0` and `G1`, but the advantage should roll back when a later state breaks: process lifetime, object generation, replication authority, render/camera timing, normal in-game visibility, or delivery route. If the explanation still jumps to "player knowledge" after a later state breaks, it treats the semantic bridge as monotonic even though it is conditional.

#### Semantic Drift and Cheat Robustness

The semantic gap is not a one-time bridge. It drifts during a match. A schema can remain byte-valid while losing authority because the object changed generation, moved from replicated to dormant state, became cosmetic, entered a replay-only view, or stopped being relevant to the local player. This is one reason real cheat engineering is harder than "read the entity list." The trace may contain real bytes, a real CR3, a real object-like structure, and a real display or input event, while the object authority is stale or belongs to a different observer.

| Drift class | How it appears in a VMI trace | Why it fools shallow parsing | State needed for a usable cheat hint |
|---|---|---|---|
| object reuse | the same address or allocation now holds a different object generation | pointer chain still resolves | generation marker, allocator epoch, destruction/reuse event |
| dormant replication | object remains client-resident while no longer actively relevant | memory presence is mistaken for current server relevance | dormancy state, replication relevance, last update tick |
| prediction rollback | local predicted state is later corrected by the server | the poller saw a plausible but non-authoritative future | correction epoch, server tick, replay comparison |
| replay or spectator override | replay view includes objects the live player should not know | replay state is treated as live player knowledge | viewer identity, DemoNetDriver or replay stream context, live-client comparator |
| cosmetic or UI state | visible or replicated data is not gameplay-authoritative | object looks useful but carries no decision authority | owning subsystem, gameplay authority surface, server consequence check |
| plausible non-authoritative state | object-like state exists outside the information the live player can legitimately use | parser confidence is mistaken for truth | normal visibility window, control object, hint gating |
| cross-thread snapshot tear | game thread, render thread, network thread, and input thread epochs differ | each field is individually valid | read-batch boundary, frame/tick join, torn-range test |
| delivery-only hint | overlay, stream, or input trace exists without an established hidden-state source | the output path looks convincing even when acquisition is unresolved | hidden-state timing, delivery route, ordinary in-game hints |

The reconstruction breaks at the first drifting authority. Valid bytes plus a stale object generation are not a current object. A valid object without resolved replication authority is not hidden information. Hidden information without a delivery route is not player knowledge. Delivery and input timing without game consequence is not game authority. Semantic reconstruction is powerful only while each layer remains current.

#### Live VMI Consistency and Observer Isolation

Recent live-VMI research, including the OSDI 2026 "Inside Out" work, adds a missing dimension to older VMI explanations: the observer has its own lifecycle. The mechanical state is not only "an external monitor read guest memory." It also includes whether the target was paused, where the observer ran, how memory was mapped or copied, and whether multiple observers shared one result or raced each other.

For cheat mechanics, moving the observer out of the guest does not make the observed state automatically coherent. A host-side observer can be outside the guest process list and still read a torn application state. An observer VM can have fast mapped access and still know nothing about game authority. A shared monitor can reduce pause overhead and still introduce ordering ambiguity. The memory view, synchronization rule, and isolation rule are part of the mechanism rather than background details.

Moving observation out of the guest can reduce guest-local traces, but it does not remove synchronization cost. Both sides matter: what the guest was doing while observed, and what the observer was allowed to do while observing. A useful stress point is observer substitution. Keep the same target VM and semantic fact, then switch from paused read to live read, host process to observer VM, single observer to shared observer, or mapped memory to copied memory. The meaning narrows when the observer behavior changes.

### Polling vs Event-Driven Monitoring

Hypervisor and VMI observation can be polling-based, event-driven, or hybrid. The API style matters less than where the design spends cost: freshness, VM exits, stale semantics, rearm work, observer mutation, buffer loss, or delivery delay. A clean poll is still stale until freshness is joined. A precise event is still intrusive until rearm, buffering, and handler changes are explained.

| Mode | Description | Strength | Weakness |
|---|---|---|---|
| Polling | Read selected memory on a schedule | Simple and stable | stale data, periodicity, bandwidth patterns |
| Event-driven | Trap or subscribe to selected page or execution events | low latency for narrow triggers | hot pages cause exit storms |
| Hybrid | Poll broad state and event-watch narrow state | practical balance | needs backoff and page selection |

Game data often tolerates polling. Radar does not need every update at render-frame precision. A 50-100 ms-old position may still explain a broad awareness hint, while a 16 ms render-frame difference can matter for crosshair, visibility, or shot timing. Trigger timing or narrow state transitions may benefit from events, but only if the watched page is not noisy.

No mode is simply "better." The design chooses which resource to spend: exits, bandwidth, semantic staleness, guest perturbation, or trace completeness. Polling hides VM-exit pressure but creates cadence and freshness problems. Event-driven monitoring improves locality but pushes cost into fault handling, re-entry, buffering, and page selection. Hybrid designs reduce obvious weaknesses but create phase changes around map load, combat, entity churn, and target-process activation.

Polling, trapping, dirty logging, view switching, and snapshotting do not remove cost; they move it between timelines. A cheat can reduce VM exits by accepting stale state, reduce polling by using hot-page faults, or reduce guest-visible changes by delaying export. The first timeline that no longer lines up is usually the limit: trigger, delivery, mutation, rearm, semantic use, or export. Change only one timeline at a time, such as sample interval or trap arming, and the resulting hint should narrow to the weakest timeline that still matches.

| Design axis | Polling pressure | Event-driven pressure | State to keep joined |
|---|---|---|---|
| freshness | sample interval and stale cache risk | trap latency and rearm window | tick/frame, acquisition start/end, object generation |
| overhead | memory bandwidth, cache pollution, host/guest contention | VM-exit count, MTF/single-step cost, hot-page storms | per-page count, vCPU/core, scheduler and power state |
| route visibility | periodic access pattern, burst schedule, phase correlation | native fault payload, handler mutation, dropped events | route state, buffering/loss counters, backend sequence |
| state changes | mostly read-side cache and timing effects | permission flips, invalidations, event injection, pause policy | mutation budget, invalidation epoch, re-entry witness |
| semantic risk | stale object graph and torn multi-structure reads | overfitting to one page or transition | schema version, object lifetime, missed-transition class |

#### Event Fidelity, Exit Budget, and View Churn

Polling, page faults, PML/A-D style page logging, altp2m-style view switching, and KVMi-style event subscriptions all occupy different points in the same design space. Each route trades fidelity, mutation footprint, pause policy, loss model, re-entry burden, and semantic latency differently, so the event name alone does not describe the mechanism's depth.

| Mechanism | Fidelity | Cost shape | Cheat-relevant caveat |
|---|---|---|---|
| fixed-interval polling | low to medium | predictable bandwidth and cache pressure | periodicity can align with frame or tick cadence and create stale snapshots |
| adaptive polling | medium | bursty around map load, combat, entity churn | backoff logic itself becomes phase-correlated behavior |
| EPT/NPT permission fault | high for selected pages | exit per access on hot pages | precision depends on page selection and qualification quality |
| accessed/dirty or PML-like page logging | medium | lower exit rate, delayed observation | tells that a page changed or was touched, not which semantic field mattered |
| Xen altp2m alternate p2m view | high for split views under Xen-style view control | lower guest modification footprint but higher active-view tracking complexity | multi-vCPU guests require strong per-view synchronization and raw vm_event context |
| Intel EPTP or view-root switch | high for split views under EPT-root switching designs | lower per-access remap cost but higher root/currentness complexity | EPTP identity, vCPU coverage, invalidation, and switch trigger must stay joined |
| #VE or guest-delivered notification | high but changes guest-visible behavior | less root exit pressure in selected cases | the guest may observe or perturb the exception path |
| full VM pause/snapshot | high coherence | disruptive latency | useful for offline study, not real-time gameplay stealth |

Event fidelity depends on six timelines:

1. **Trigger timeline:** when the monitored condition becomes true.
2. **Delivery timeline:** when the observer backend receives a trace.
3. **Mutation timeline:** when the observer changes permissions, views, pause state, or guest-visible exception routing to let execution continue.
4. **Rearm timeline:** when the observer restores the condition needed to catch the next event.
5. **Semantic timeline:** when the game object, scheduler state, or render/network tick consumes the value.
6. **Export timeline:** when the side channel, overlay, input helper, replay trace, or host-side path makes the observation visible outside the monitor.

The common mistake is to collapse those timelines. An EPT read violation can be precise when the access happened and still be weak at the game-meaning stage if the page is shared, the process root is stale, or the object generation changed before export. A PML or dirty-bit drain can be weak at the exact-instruction stage and still useful for a batch-level mutation hypothesis if the drain epoch, buffer fullness, and replay window are preserved. A full pause can create a coherent memory image while destroying the timing relation that made the event useful for a live cheat loop.

The chosen mechanism also tells you what the design is trying to avoid. Broader polling trades local VM-exit precision for semantic staleness. Narrow faults trade freshness for hot-page risk. Multiple views trade lower remap frequency for view-coherence risk. Pauses improve snapshot coherence but lose the live interleaving needed for real-time assistance.

Xen altp2m and Intel EPTP switching should not be treated as the same mechanism. They both create alternate second-stage views, but they differ in ownership, switching path, event model, and endpoint comparability. The shared cheat-relevant question is narrower: which view was active for this vCPU, this access type, and this time window?

Timeline separation is a useful stress test. Keep the same target page and change only one timeline or budget: delay delivery while preserving the trigger, rearm late while preserving the first event, overflow or coalesce the dirty/PML buffer, switch the view on one vCPU but not another, preserve the byte sample while changing object generation, or preserve the object while removing export. The mechanism should narrow to the first missing timeline. If it still says "high fidelity" after trigger, delivery, mutation, rearm, semantic use, and export disagree, it is treating observer precision as semantic truth.

#### Observer Backpressure and Event Loss

Event-driven monitoring shifts the correctness burden from "how often did the monitor sample?" to "what delivered, delayed, coalesced, or lost the event?" LibVMI documents the basic shape: synchronous events pause the vCPU related to the page fault or VM exit so a callback can inspect consistent state; memory events require page-permission changes so the guest access can eventually complete; single-step or re-registration is then needed to catch later events.

KVMi exposes the same rule at another layer: a host-side application can pause or resume vCPUs, query vCPU state, alter shadow/EPT page-access bits, and receive optional events that may require an explicit action.

HyperDbg makes the buffer side visible: EPT hooks and monitor events need preallocated event and hook buffers, and immediate delivery trades latency for higher overhead. These details decide how usable the event really is.

| Mechanism | Event source | Pause/rearm cost | Loss or distortion risk | Meaning if isolated |
|---|---|---|---|---|
| fixed polling | timer or external loop | no trap rearm | stale snapshots, aliasing, torn ranges | sampled byte or state |
| adaptive polling | heuristic scheduler | backoff and priority logic | observer bias, missed transitions, phase correlation | prioritized sample |
| EPT/NPT permission trap | second-stage violation or fault | VM exit or NPF, handler decision, optional MTF/single-step, invalidation | exit storm, permission trace, stale combined translation | second-stage access |
| PML or A/D dirty logging | hardware dirty/accessed state | batch drain and buffer management | page-granular only, overflow/full-buffer ambiguity, no value semantics | dirty-page state |
| #VE or guest notification | guest-visible virtual exception or notification path | guest handler and reinjection path | guest tampering, notification routing ambiguity, changed guest-visible behavior | guest-notified second-stage event |
| Xen altp2m or EPTP view switch | alternate second-stage view | view selection, switch trigger, per-vCPU synchronization | view-coherence drift, active-view ownership error | active-view state |
| LibVMI memory event | backend memory event | vCPU pause, permission relaxation, single-step or event re-registration | callback skew, unacknowledged event state, multi-vCPU race after permissions are lifted | VMI backend event |
| KVMi event | KVM introspection channel | pause/resume, page access-bit mutation, explicit action reply for selected events | patched-stack ownership ambiguity, ABI/version drift, host/backend timing | KVMi-reported event |
| HyperDbg EPT hook or monitor event | debugger-managed EPT hook, monitor, or instant event path | HyperDbg VMM event handling, optional immediate delivery, preallocated event and hook buffers | buffer exhaustion, debugger-state trace, lab VMM mutation footprint | HyperDbg-observed event |
| full VM pause or snapshot | hypervisor/tool snapshot | global or selected-vCPU pause | observer-created timing distortion, lost live interleaving | paused snapshot |

Rearming is part of the mechanism. If a page is made readable or writable so the trapped instruction can complete, the monitor has changed the condition that created the event. If MTF or single-step is used, the next event is partly a restoration event.

If altp2m, EPTP switching, or an alternate NPT view is used, the active view and switch trigger are part of the state. If PML or A/D bits are used, the monitor may receive a delayed page-granular signal without the instruction, value, or actor. If a KVM/QEMU dirty ring is used, the ring identifies dirtied GFNs under that harness; it is not a process write trace.

Use narrower labels when the monitoring route is incomplete:

| narrowed label | Use when | Missing state before game meaning |
|---|---|---|
| event seen | a backend delivered a callback, message, exit, or trace row | native payload, subscription, vCPU/core, timebase, and re-entry result |
| event loss possible | queue, ring, PML buffer, socket, callback, or preallocated tool buffer loss cannot be excluded | depth/overflow counters, drain epoch, dropped-trace accounting, replay window |
| observer changed permissions | the observer changed second-stage access bits, backing pages, view selection, or guest-visible exception routing | old/new leaf, invalidation scope, restore/re-arm state, independent read path |
| dirty page only | PML, A/D, dirty bitmap, or dirty ring identifies page-level change | field-level readback, actor ownership, process/page-state join, semantic epoch |
| hot page amplified the signal | a noisy shared page turns a narrow subscription into repeated exits or callbacks | page ownership split, large-page narrowing trace, backoff decision, shared-page control |
| pause may have skewed the sample | vCPU/VM pause can change scheduling, timers, object lifetime, or multi-thread interleaving | host/guest time mapping, paused-vCPU set, scheduler epoch, post-resume replay |
| backend event only | the trace came from HyperDbg, LibVMI, KVMi, DRAKVUF, HVMI, QEMU, or another backend | version, backend, target profile, raw event, mutation budget, independent endpoint bridge |

The value of event-driven monitoring depends on loss, mutation, re-entry, and semantic reconstruction. A narrow EPT hook with no buffer-loss accounting can be less useful than a slower polling pass with clean process-memory replay. A LibVMI or KVMi event without pause and rearm state is a backend event, not a complete guest history. A HyperDbg EPT hook trace teaches the control loop, but its debugger VMM also created the mapping mutations being measured. Every event monitor observes the system and also disturbs it. The context has to account for that disturbance.

#### Polling Aliasing and Snapshot Coherence

Polling deserves the same care as event handling because it can look quieter while carrying a different failure class. A poller does not usually create one obvious VM-exit storm, but it can still create a timing-shaped trace: reads cluster around render frames, game ticks, network updates, map loads, object churn, or human-visible decisions. The technical problem is deciding whether a sampled value was current when the player acted or merely plausible under a repeated schedule.

| Polling surface | State required | Failure class | Meaning if isolated |
|---|---|---|---|
| sample clock | TSC/QPC or host clock, guest tick, frame id, sampling interval, jitter policy, phase relation to render/network ticks | fixed cadence aliases against game ticks or probe timing | sample-clock only |
| range assembly | per-page read order, retry count, page hash, missing-page policy, pause state, object generation | multi-page object assembled from different epochs | possible torn snapshot |
| semantic cache | decoded object id, lifetime, team/visibility state, transform, camera, schema version, cache age | stale but smooth object survives after authoritative state changed | semantic-cache state only |
| adaptive scheduler | priority rule, backoff rule, hot-object selection, map-load/combat/entity-churn phase | polling rate changes become phase-correlated behavior | adaptive polling posture |
| read-side perturbation | cache pressure, memory bus pressure, page materialization, A/D bit change, debug or VMI backend read effect | "read-only" observation changes timing or page state | read perturbation not closed |
| control comparison | same poller with delayed phase, randomized phase, no-target process, replay-only run, or removed hint route | the hint survives after the stated semantic target is removed | polling correlation only |

Polling also has a hidden observer-bias problem. A poller tends to observe what its schema already knows how to decode. When an engine patch changes object layout, replication timing, map streaming, or visibility authority, the poller may continue returning well-formed stale objects. That failure can look cleaner than an event loss because the data type still decodes. A cheat loop needs cache-generation state, not just a valid pointer chain.

Sampling-phase perturbation is the simple stress test. Keep the address route constant and perturb only the sampling phase. Add jitter, delay the poll until after the player action, sample the same object after server reconciliation, remove the target process while preserving the decoder profile, or replay the same match with the poller disabled but the behavior model unchanged. If the supposed hint or input does not change, the sampled value was not the causal part of the cheat loop. It was a correlation between a schema, a timeline, and a behavior row.

### Device, Overlay, and Input Virtualization

Turning memory access into a player advantage requires a delivery path. The information must become a visible hint or control signal and influence either human perception, input timing, or downstream decision quality inside a bounded game moment. A below-OS read without that bridge is acquisition state, not player knowledge.

| I/O path | Mechanism | Main boundary |
|---|---|---|
| Host overlay | Draw outside the guest OS | hint exists outside guest render authority |
| Guest overlay | Draw inside the game OS | hint shares the guest graphics path |
| Virtual input | Send events through VM monitor or virtual HID | input enters through a virtualized device path |
| Hardware input bridge | External device emits HID-like input | input enters through a physical-device-like path |
| Second-device display | Send radar/ESP to phone or second PC | hint reaches the player through a side display |
| Cloud stream | Host or provider sends augmented stream | hint and input pass through a remote presentation loop |

A read-only VMI cheat may avoid guest process traces, but the advantage still has to appear in one of the last-mile paths: what the player sees, what an input helper sends, what a stream shows, or what the server later records. If that last-mile timing is missing, the cheat cannot be described as player knowledge. A clean process-memory scan still leaves the delivery path unresolved, because the last mile may be outside the process.

Keep delivery authorities separate. Memory acquisition, visual disclosure, input provenance, and game consequence are different owners even when a feature calls all of them "ESP" or "aim assist." A cheat can keep the guest process clean while moving the hint to a host overlay, external display, stream, or human-assisted channel. The missing delivery timing might be the render frame, capture frame, moment when the hint appeared, input event, server tick, or normal in-game visibility check. If the hint no longer reaches the player before the action, the mechanism stops before it becomes player knowledge.

#### Presentation and Input Paths

Do not collapse delivery into "overlay" or "input." The delivery path has separate authorities: the game render path, the guest windowing path, the desktop compositor, the GPU scan-out path, the capture path, the host or VM parent path, the HID/input stack, and the server replay path. A hypervisor may own second-stage translation while owning none of those delivery authorities. That is why a clean process memory scan, a clean guest screenshot, or a plausible HID report can coexist with an external advantage path.

The map below keeps pixel, capture, input, host-overlay, and server-replay authority separate until the same hint and player action are connected:

| Delivery path | Source-backed Windows surface | What it can show | What it cannot show alone | State to keep aligned |
|---|---|---|---|---|
| game render path | swap chain, render target, engine frame counter, window or exclusive/fullscreen mode | the game or guest graphics path produced pixels | host overlay, capture overlay, second display, or operator channel absence | game frame id, swap-chain/window id, render-target lineage, capture visibility, frame pacing |
| DWM composition | DWM off-screen surfaces, composed desktop image, top-level HWND relation | windowed content was composed into a desktop image under DWM | all player-visible pixels match the game render output | HWND/session, z-order or window relation, DWM composition state, desktop frame epoch |
| Desktop Duplication | `IDXGIOutput1::DuplicateOutput`, `AcquireNextFrame`, dirty rects, move rects, pointer shape/position | a specific output duplication session observed a desktop image and metadata | absence of host overlay, hardware plane, second monitor, capture-card preview, or off-device hint | output id, frame timestamp, dirty/move rect processing, pointer metadata, dropped/timeout frames |
| Windows Graphics Capture | capture item, `GraphicsCaptureSession`, `Direct3D11CaptureFrame`, `SystemRelativeTime`, border/cursor/dirty-region settings | a user-mediated capture item produced frames with QPC timing and session options | every pixel seen by the player or every host/remote delivery path | item identity, session options, consent/capability path, frame content size, QPC time, cursor/border state |
| display-affinity protection | `SetWindowDisplayAffinity`, `WDA_MONITOR`, `WDA_EXCLUDEFROMCAPTURE`, DWM requirement | an application requested a public OS capture-protection behavior for its own top-level window | DRM-grade secrecy, protection from cameras, kernel/driver capture, or host-side capture | HWND owner, affinity value, DWM composition state, OS build, capture API tested, failure code |
| host or VM parent overlay | VM window, host compositor, stream preview, provider overlay, second output | a hint may be presented outside the guest OS and outside guest process state | guest process modification or guest render-path trace | host process/window id, VM display topology, capture source, stream session, timing against guest frames |
| Raw Input and HID | `RegisterRawInputDevices`, `RAWINPUTDEVICE`, `WM_INPUT`, `RAWINPUTHEADER.hDevice`, `RAWHID`, `RID_DEVICE_INFO` | registered software saw device-scoped input data from a HID top-level collection | human intent, device trust, or absence of higher-level injection | usage page/usage, flags, target window, `hDevice`, device info, report size/count, queue timing |
| injected or brokered input | `SendInput`, low-level hook flags such as `LLKHF_INJECTED` and `LLMHF_INJECTED`, UIPI boundary | simulated input or injected-flagged messages existed in a session and integrity context | that the input was cheat-driven or linked to hidden information | return count/status, integrity level, foreground target, hook flags, `dwExtraInfo`, event order |
| server and replay authority | server tick, replay tick, authoritative hit/movement/cooldown/inventory event | the action had game-state consequence | exact local delivery path if endpoint state is missing | match id, replay marker, server tick, action id, ordinary-discovery moment, ordinary in-game hint |

These are normal Windows surfaces too. Desktop Duplication is common in collaboration, streaming, testing, and accessibility tools. Windows Graphics Capture is a normal system capture path with session options and QPC frame time. `SetWindowDisplayAffinity` is a public content-protection request for specific OS capture paths while DWM is composing the desktop.

Raw Input is the normal way games and tools distinguish device-scoped input. `SendInput` is a documented simulation path constrained by UIPI. For cheat mechanics, no single surface explains a cheat by itself. A working advantage has to join hidden state, delivery, input or decision effect, and game consequence.

For each hint or input path, keep a per-path trace. Most mistakes come from merging paths too early. A capture frame without host or external display coverage is a capture-scope gap. A HID report without hidden-state timing is an input-provenance gap. A clean guest frame with no host-parent view is only a guest-view fact. A server replay action with no endpoint delivery path is a consequence without a delivery route.

A practical check is path substitution: keep the hidden-state source, but replace only the presentation or input path. If the behavior persists when that hint path is removed, the mechanism is about decision timing or ordinary in-game information, not about that overlay or input route.

#### Joining Delivery State

Delivery state becomes useful only if the context crosses all four boundaries:

```text
delivery_loop_ready =
  hidden_state_time_bound
  and delivery_surface_or_operator_channel_bound
  and input_or_decision_effect_bound
  and server_or_replay_consequence_bound
  and ordinary_in_game_information_checked
```

| Surface | Authority owner | Join key to preserve | Mistake it prevents | Meaning if isolated |
|---|---|---|---|---|
| game render output | game engine, graphics API, swap chain, render target | game frame, present id, swap-chain/window identity, render-target lineage | assuming engine pixels are the same as player-visible pixels after compositor, host, stream, or external overlays | render-output fact |
| DWM desktop image | DWM session and desktop compositor | desktop frame, HWND, off-screen surface relation, z-order, occlusion state | treating a window capture or screenshot as every visible plane | composed-desktop state |
| MPO hardware plane | WDDM display miniport, UMD/KMD MPO path, scan-out hardware | plane id, VidPN source, allocation, support/caps result, post-present state | assuming software capture sees every hardware-composed plane or that a missing plane establishes absence | hardware-plane state |
| Desktop Duplication | DXGI output duplication object | output id, `AcquireNextFrame` result, dirty rects, move rects, pointer metadata, access-lost/timeout state | treating one duplicated output as the user's full visual field or as host-overlay absence | output-duplication observation |
| Windows Graphics Capture | user-mediated capture item and capture session | item identity, picker/consent path, `SystemRelativeTime`, content size, cursor/border/dirty-region settings | treating a selected item capture as all-screen or all-session visibility | selected-item capture observation |
| display affinity | owner process and DWM capture-protection path | top-level HWND, affinity value, DWM state, OS build, tested capture API | reading capture exclusion as DRM-grade secrecy or host/camera/device capture protection | API-scope protection request |
| Raw Input | HID stack, raw input registration, target window queue | usage page/id, flags, `hDevice`, `RID_DEVICE_INFO`, report size/count, foreground or `RIDEV_INPUTSINK` state | treating device-scoped input as human intent or as absence of brokered input | device-input observation |
| low-level hook source | Win32 hook path and message source metadata | `LLKHF_INJECTED`, `LLMHF_INJECTED`, lower-IL flag, `INPUT_MESSAGE_SOURCE`, message time, `dwExtraInfo` | treating an injected flag as cheat causality or a missing flag as physical trust | message-source observation |
| `SendInput` or brokered injection | caller integrity, UIPI, package capability, broker or remote operator | return count, target integrity, foreground target, restricted capability, event order | equating simulated input with hidden-state-driven automation | simulated-input state |
| server/replay consequence | game server and replay system | server tick, replay marker, action id, target state, legitimate-disclosure deadline | using endpoint input or capture facts without game-state consequence | behavior consequence fact |

For the last mile, scope matters. A clean game screenshot does not rule out a host overlay, a hardware plane, a second output, a stream overlay, or a person looking at a second display. A Desktop Duplication frame shows what one duplication object received for one output and frame, not what every capture path or human saw. A WGC frame shows what the selected item delivered at its compositor QPC time, not that all UI or secondary windows were included. A Raw Input trace shows a device path only within the registered usage, queue, and target-window conditions. A low-level hook flag can show injection, but causality still needs hidden-state timing and game consequence. The required join is:

```text
delivery_epoch_join =
  render_or_capture_scope_named
  and user_visible_or_operator_channel_named
  and input_source_scope_named
  and hidden_state_time_aligned
  and server_or_replay_consequence_aligned
  and ordinary_capture_input_paths_accounted
```

#### GPU Timeline and Presentation Boundaries

The GPU timeline is useful only when each layer's state connects to the next layer's owner in the same frame or transaction clock. A row may advance only when the previous owner, such as GPUVA space, allocation mapping, residency, queue/fence epoch, CPU/device memory bridge, presentation observer, and game authority, is retained in that shared window:

| State | Minimum state | What it can safely say | If isolated | First missing bridge |
|---|---|---|---|---|
| G0 graphics label only | a GPU, WDDM, D3D, DWM, fence, or doorbell label | this is a graphics-stack signal | GPU label only | adapter, process, and source revision |
| G1 GPUVA space bounded | process GPUVA space, adapter/node, WDDM version, and driver model are named | this GPUVA belongs to a bounded graphics address-space context | GPUVA without allocation mapping | allocation mapping and segment |
| G2 allocation mapping bounded | allocation handle, segment, GPUVA mapping, page granularity, and root/page-table epoch are retained | this allocation mapping could be consumed by a GPU engine | allocation without residency | residency and paging state |
| G3 residency or paging bounded | MakeResident/Evict/Trim, residency reference, paging queue, fence, budget, or notify operation is retained | this allocation was resident, evicted, trimmed, or paging-relevant under this device timeline | residency without execution state | queue execution or fence completion |
| G4 queue or fence epoch joined | submission model, HWQueue, doorbell, monitored/native fence, waiter, interrupt, or completion is retained | this GPU timeline reached or waited on a bounded fence/queue state | GPU timeline without CPU or presentation bridge | CPU/device memory bridge or presentation bridge |
| G5 CPU or device memory joined | CPU VA/PFN, EPT/NPT, IOMMU/domain, GPU-PV host bridge, or CPU reread joins the allocation | this GPU state joins bounded CPU/device memory state | GPU memory without Windows or delivery context | Windows page state or display/capture path |
| G6 presentation or capture joined | present/flip, DWM/MPO, duplication/WGC, host/guest compositor, or protected-content result is retained | this graphics state joins bounded presentation or capture state | presentation without player-knowledge bridge | hidden-state, input, and replay/server join |
| G7 game authority joined | engine epoch, hidden-state source, delivery/operator channel, input or decision effect, and replay/server consequence are joined | the row can support bounded game-authority state | game-authority state | none for the stated scope |

Some graphics facts look stronger than they are:

| Positive-looking fact | What it shows | What it does not show | Layer where the mechanism stops |
|---|---|---|---|
| a per-process GPUVA exists | a graphics address-space value exists for the process GPU context | CPU virtual address, process read parity, or game-object truth | G1 GPUVA space bounded |
| a VidMm allocation is mapped | the driver model can name a GPU allocation and mapping | that the allocation is resident, current, CPU-visible, or player-visible | G2 allocation mapping bounded |
| MakeResident succeeded or returned a paging fence | the device residency requirement path advanced under a paging queue | that a GPU engine consumed the content or that a CPU read would match it | G3 residency or paging bounded |
| a monitored or native fence reached value N | a GPU/CPU synchronization timeline reached a value under that fence object | which pixels were visible, which game object was hidden, or whether a player acted on it | G4 queue or fence epoch joined |
| a user-mode submission doorbell was mapped or rung | a supported HWQueue submission path may have notified a GPU engine | presentation path truth, hidden-state disclosure, or endpoint equivalence | G4 queue or fence epoch joined |
| WDDM GPU-PV object exists in a guest | guest graphics objects were marshaled to a host GPU virtualization path | bare-metal endpoint equivalence or guest-owned VidMm/VidSch authority | hosted GPU-PV state |
| Desktop Duplication or WGC captured a frame | one capture authority received a frame and metadata | all player-visible planes, host overlays, second outputs, or hidden-state causality | G6 presentation or capture joined |
| CPU bytes match a GPU allocation snapshot | one CPU/device bridge matched bytes for an epoch | OS read equivalence, allocation freshness, player knowledge, or server consequence | G5 CPU or device memory joined |

GPU-PV needs path-specific handling. A GPU-PV object belongs to a Hyper-V paravirtual graphics path, not generic GPU virtualization or bare-metal WDDM by default. If the environment uses a hosted VM, a generic virtual GPU, passthrough, or GPU-PV, that path changes the comparison against a normal endpoint.

The handoff between layers is strict. A GPUVA allocation and residency epoch are still only graphics memory context. A GPU fence and queue epoch are still only synchronization context. A capture-path observation is still only presentation context. The row becomes game authority only after the GPU allocation, residency, queue/fence, CPU or device memory bridge, presentation/capture path, hidden-state epoch, input or decision effect, and replay/server consequence all name the same window.

#### Cheat Delivery Patterns

Recent cheats often look different at the implementation layer but similar at the delivery layer. They all have to move information from some hidden source into a player decision or input event.

| Pattern | Hidden source | Delivery path | Technical trap | Mechanism-limited meaning |
|---|---|---|---|---|
| VMI radar or wallhack-style information | guest memory reconstructed outside the game process | host overlay, second screen, stream, or companion process | treating a VMI byte read as player-visible knowledge | below-OS acquisition until object, visibility, and hint delivery line up |
| VMI-assisted trigger timing | crosshair, target, or visibility state reconstructed from memory | local input helper, virtual HID, or player-facing hint | treating a memory event as the shot cause | timing state until input and server tick line up |
| visual aimbot | rendered frames, screenshots, or capture stream | automated aim decision or player-facing hint | treating clean process memory as clean gameplay | frame observation until capture, decision, and input timing line up |
| external DMA or device-assisted read | physical memory or translated memory through an external path | second PC, external display, or hardware input bridge | treating physical access as fresh process memory | device/acquisition state until translation freshness and Windows page state join |
| hosted or cloud relay | game runs in a VM or remote environment | augmented stream or relayed input | treating the endpoint as the whole trust boundary | remote-delivery state until account, stream, latency, and replay context join |

Hardware input bridges come in several forms. They can include microcontroller-style HID emulation, FPGA-based USB or HID presentation, capture-and-relay rigs, or a companion machine that receives hidden-state hints and emits input-like events. The technical boundary is the same in each case: the input path may look physical or device-scoped, while the decision source still came from a hidden memory, VMI, visual, or remote observation path.

Delivery is the final step that connects acquisition to player advantage. The acquisition route can be VMI, DMA, visual capture, hosted VMI, or a plain local process read. The advantage still needs the same last mile: a hint must reach the player, an input must be produced, or a decision must appear in server or replay data. Without that last mile, the mechanism stops at acquisition or reconstruction.

## Next

Next, the series moves from individual exits and delivery paths into the harder question: can the same story survive a real multi-core system? Part 4 looks at SMP behavior, interrupt delivery, VMCS/VMCB field currentness, invalidation scope, time coherency, and secure-memory boundaries.

## Credits

Credit to Sina Karvandi / Sinaei [@Intel80x86](https://x.com/Intel80x86) and the [@HyperDbg](https://x.com/HyperDbg) project for the HyperDbg `!monitor`, `!epthook`, and `!epthook2` documentation that informed the EPT-hook, monitoring, and event-delivery discussion.

Credit to Omar Sardar, Dimiter Andonov, and the FireEye FLARE / Black Hat USA 2019 researchers behind "Paging All Windows Geeks: Finding Evil in Windows 10 Compressed Memory." That work informed the compressed-page caution in the Windows page-state section.

Credit to Panicos Karkallis and Jorge Blasco for [VIC: Evasive Video Game Cheating via Virtual Machine Introspection](https://arxiv.org/abs/2502.12322), which informed the VMI game-cheat examples and the acquisition-to-delivery chain.

Credit to Jianing Wang, Chuqi Zhang, Yuancheng Jiang, Adil Ahmad, and Shanqing Guo for the AimTrap paper, which informed the visual-aimbot and frame-only cheat discussion.

Credit to Dufy Teguia, Louis Duval, Teo Pisenti, Kahina Lazri, Daniel Hagimont, Thomas Pasquier, Renaud Lachaize, and Alain Tchana for the OSDI 2026 "Inside Out" VMI work that informed the observer-isolation discussion.

## References

- Intel, Intel 64 and IA-32 Architectures Software Developer's Manual combined volumes PDF: https://cdrdv2-public.intel.com/825743/325462-sdm-vol-1-2abcd-3abcd-4.pdf
- AMD, AMD64 Architecture Programmer's Manual Volume 2, System Programming: https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2
- Microsoft, Hyper-V Top-Level Functional Specification: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
- Microsoft, Hyper-V TLFS Nested Virtualization: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/nested-virtualization
- Panicos Karkallis and Jorge Blasco, VIC: Evasive Video Game Cheating via Virtual Machine Introspection: https://arxiv.org/abs/2502.12322
- USENIX OSDI 2026, Inside Out: A Paradigm Shift In VM Introspection: https://www.usenix.org/conference/osdi26/presentation/teguia
- Jianing Wang, Chuqi Zhang, Yuancheng Jiang, Adil Ahmad, and Shanqing Guo, Shoot the Honey, Cloak the Player: Towards Zero-Runtime-Overhead Proactive Defense and Detection for Visual Game Cheating: https://arxiv.org/abs/2606.25734
- LibVMI, Introduction and API documentation: https://libvmi.com/docs/gcode-intro.html
- KVM-VMI, KVMi documentation: https://kvm-vmi.github.io/kvm-vmi/master/kvmi.html
- DRAKVUF, project documentation: https://drakvuf.com/
- Bitdefender HVMI, project repository: https://github.com/bitdefender/hvmi
- HyperDbg, monitor command and event-monitoring documentation: https://docs.hyperdbg.org/commands/extension-commands/monitor
- HyperDbg, Design of !epthook: https://docs.hyperdbg.org/design/features/vmm-module/design-of-epthook
- HyperDbg, Design of !epthook2: https://docs.hyperdbg.org/design/features/vmm-module/design-of-epthook2
- QEMU, QMP specification: https://www.qemu.org/docs/master/interop/qmp-spec.html
- Black Hat USA 2019, Paging All Windows Geeks: Finding Evil in Windows 10 Compressed Memory: https://i.blackhat.com/USA-19/Thursday/us-19-Sardar-Paging-All-Windows-Geeks-Finding-Evil-In-Windows-10-Compressed-Memory-wp.pdf
- InfoconDB, Paging All Windows Geeks presentation metadata: https://infocondb.org/con/black-hat/black-hat-usa-2019/paging-all-windows-geeks-finding-evil-in-windows-10-compressed-memory
- Microsoft, Kernel DMA Protection for Thunderbolt: https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
- CERT/CC, VU#382314: Pre-boot DMA access exposure on systems with kernel DMA protections: https://kb.cert.org/vuls/id/382314
