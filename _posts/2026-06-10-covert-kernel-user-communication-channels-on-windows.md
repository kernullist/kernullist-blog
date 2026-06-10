---
title: "Covert Kernel/User Communication Channels on Windows: Rootkits, Game Cheats, and Detection"
date: 2026-06-10 00:00:00 +0900
categories: [Windows Internals, Anti-Cheat, Malware Analysis]
tags: [kernel, user-mode, ipc, alpc, rpc, wsk, registry, firmware, callbacks, byovd, rootkit, malware, covert-channel, windows]
---

> A modern Windows kernel-assisted threat is rarely a single user-mode module doing all the work. It is a stack: a user-mode controller, a kernel-mode component loaded through a vulnerable-driver chain or a signed-but-abusive driver, and sometimes an external auxiliary such as DMA hardware, a hypervisor, or an input emulator. The component defenders often underestimate is the *communication channel* between these pieces. `DeviceIoControl` against a custom device object would solve every engineering problem; it would also be inventoried quickly by a competent anti-cheat, EDR, or incident-response tool. Mature rootkits, BYOVD malware, and high-end game cheats therefore hide the channel inside Windows features that are already noisy, under-monitored, version-dependent, or hard to attribute to a specific driver after the fact. The rest of this article follows those surfaces from the defender side.

The layout matches the other Windows internals posts in this blog: threat model first, evidence model next, then a surface-by-surface pass from ordinary IPC down to hardware and hypervisor paths, ending with production detection. Do not memorize "bad APIs"; track how ordinary Windows behavior gets repurposed as a rendezvous point, wake edge, selector plane, payload plane, or reply plane.

Game cheats remain the main operational lens because anti-cheat work forces these channels to be detected on live consumer machines with low false-positive tolerance. The same surfaces also apply to rootkits, malicious signed drivers, BYOVD malware, boot-time loaders, and stealthy post-exploitation implants. When the text says "cheat", read it as the concrete game-security case; when it says "kernel-assisted threat", read it as the broader family.

Reference posture is **2026-06-10 KST**. Public API statements should be checked against Microsoft documentation and the local WDK. Private structure, callback-list, system-information-class, graphics, and syscall-provider claims are build-sensitive and should be validated against the target kernel image, symbols, and clean baselines before they become production enforcement logic.

## 1. Threat Model

### 1.1 The Kernel-Assisted Threat Stack

A kernel-assisted threat usually splits three concerns: *access* (reading, writing, hiding, or brokering privileged state), *control* (deciding what to do with that state), and *delivery* (overlay, input, persistence, configuration, proxying, payload execution, or cleanup). Game cheats, rootkits, and BYOVD malware emphasize different outcomes, but the stack shape is similar:

1. A user-mode controller inside, adjacent to, or merely correlated with the protected process. In game-cheat cases this is often an injected module, overlay helper, launcher-side service, or configuration UI. In malware cases it may be a service, broker process, updater, injected payload, or short-lived staging process.
2. A kernel-mode component loaded through a vulnerable-driver (BYOVD) chain, an abused signed driver, an OEM-looking helper, or a custom mapper. It provides privilege the user-mode side cannot legitimately obtain: kernel reads, callback registration, page-table manipulation, MSR access, object routing, or hidden persistence.
3. Optional external support: a PCIe DMA card, a coupled hypervisor, a second machine running screen capture and computer vision, an input emulator, or external virtualization. External support exists because the protected host is increasingly hostile to on-machine code.

The boundary defenders need to understand is the one between user-mode control and kernel-mode authority. The threat does not simply load a driver and forget about it. It needs a *continuous* command-and-control path:

- User mode asks kernel to read protected memory, write a small patch, hide an object, register a callback, route an I/O path, or perform a privileged scan.
- Kernel asks user mode to render overlay state, update aim logic, decrypt configuration, fetch licensing or operator state, invoke a user-mode payload, or ship telemetry.
- Both sides need synchronization, watchdogs, health checks, and state exchange.

If that boundary is `IOCTL 0xDEAD_BEEF` against `\\\\.\\CheatDevice`, the defender wins on day one. Modern stacks instead choose boundaries that look like ordinary operating-system activity.

### 1.2 Why Hide the Channel

Three properties make a channel attractive:

- **Noise.** The OS itself or a popular vendor product already uses this surface so often that an extra subscriber, port, or pointer write does not stand out.
- **Under-monitoring.** EDR, anti-cheat, and incident-response tooling developed during one Windows era often miss surfaces that came online afterward (WNF, ALPC private ports, Filter Manager ports, ETW providers, MSI-X provisioning).
- **Attribution friction.** The surface ties activity to an object, such as a port, section, or callback, rather than directly to the attacker's driver image. When the defender finds the artifact, it points to a legitimate-looking owner or to "something" without a clean trace back to the attacker module.

A channel that hits all three is a P0 problem for the defender. A channel that hits one is still operationally useful for the attacker, because the cost of *finding it* and the cost of *acting on it without false positives* dominate detection economics.

The signals that keep paying off are:

| Signal | Implication |
|--------|-------------|
| A protected process, game, service, or helper talks to an ALPC/RPC/pipe/socket endpoint whose owner has no product role | Hidden control plane behind ordinary IPC |
| A callback, dispatch entry, or writable control pointer lands outside a valid owner function | Kernel redirection or manual-mapped code |
| A firmware provider, registry callback, WFP callout, or minifilter appears only during protected workload activity | Registered OS surface being used as a rendezvous or trigger |
| A section, MDL-backed buffer, GPU resource, or WNF state has command-shaped cadence | Payload plane split from the visible wake edge |
| Handle tables, object namespace, ETW, VADs, or file-object routing disagree | Cross-view spoofing, path confusion, or per-object route substitution |

### 1.3 Attacker Layers

A consistent taxonomy makes the rest of this document tractable. Channels live in layers, and defender visibility depends almost entirely on the layer the channel inhabits:

| Layer | Surface | Typical Defender Visibility |
|-------|---------|------------------------------|
| **L1** | Ordinary user-mode IPC and storage (pipes, mailslots, registry, atoms) | High if the defender watches the protected workload's object namespace and IPC handles |
| **L2** | Legitimate kernel API and driver communication surfaces (FltMgr port, WSK loopback / egress, WMI, custom device interface) | Medium: needs a kernel inventory and object telemetry |
| **L3** | Kernel `.data`, callback, process-structure, or other non-code control pointers (`HalPrivateDispatchTable`, `ObTypeIndexTable`, callback arrays) | Medium-to-hard: needs baseline integrity and version-aware parsing |
| **L4** | Hypervisor, EPT, syscall path, CPU state manipulation | Hard: requires platform or hypervisor visibility |
| **L5** | External hardware (DMA, microcontroller HID emulators) | Very hard: defense moves to policy and hardware attestation |
| **L6** | External virtualization, visual capture, off-machine compute | Nearly impossible from inside the protected process |

The market shape depends on the defender. For competitive games, mid-2026 planning still puts most software cheats in L1-L3 (commodity engines, BYOVD loaders, sections, registry, ALPC, WSK, dispatch pointers, and callback abuse), a smaller but important population in L4 (custom hypervisors), and a high-impact FPS-focused population in L5/L6 (DMA hardware, visual capture, VMI, or off-machine compute). For malware and rootkits, L1-L4 overlap heavily with signed-driver abuse, callback misuse, network proxying, persistence, and object-hiding tradecraft. L1-L4 are still partly software-defender territory. L5 and L6 push the problem into hardware policy, IOMMU/DMAr enforcement, server-side behavioral detection, attestation, and controlled hardware environments.

### 1.4 PatchGuard Safety Tags

Where this document discusses kernel modification, the relevant question is not "does it work" but "does it survive PatchGuard." A consistent labeling helps:

| Tag | Meaning |
|-----|---------|
| **PG-Safe** | Outside known PatchGuard coverage. Reads are generally safe; writes may still be blocked by HVCI/KDP, object invariants, reference counting, or ordinary kernel correctness rules. |
| **PG-Caution** | Reading is usually safe, but writes or hooks against the same surface can be risky on some builds. |
| **PG-Risky** | Works only by racing or by restoring state between PatchGuard checks. Long-running attacker tooling needs a watchdog and replay loop. |
| **PG-Conflict** | Reliably triggers a PatchGuard bugcheck on modern systems. Treat as non-viable for production attacker tooling. |
| **PG-Bypass** | Uses a legitimate or alternate mechanism that PatchGuard's classic checks do not cover. |

Attacker selection bias is heavy: PG-Conflict techniques have largely been abandoned, PG-Risky techniques persist where the channel value justifies a restore loop, and PG-Safe / PG-Bypass surfaces are where active engineering happens. Defenders should weight detection investment the same way.

### 1.5 Defender Position

The most demanding practical defender in this document is still a production anti-cheat, because it must inspect consumer machines during live gameplay without breaking legitimate drivers. A comparable EDR or incident-response stack may have different policy power, but the evidence problem is similar. A production anti-cheat realistically has:

- A signed kernel driver loaded at boot or at protected workload launch.
- A user-mode service for orchestration, telemetry shipping, and UI.
- ETW consumers: generally for kernel-process, image-load, and registry providers, sometimes for security-relevant providers.
- A game-process module that sees PEB, TEB, loaded modules, and the IPC namespace.
- Baseline snapshots captured at boot, at driver load, and at protected workload launch.
- Vendor allowlists for security products, GPU drivers, input drivers, overlays, and anti-malware.

It generally does *not* have:

- Full PatchGuard-equivalent coverage of arbitrary kernel state.
- Visibility into SMM, external DMA, or a malicious hypervisor running below it.
- Zero false-positive freedom when inspecting kernel `.data`.
- Stable undocumented offsets across every Windows build it must support.

These gaps determine which sections of this document are P0 (production must cover), which are P1 (high-value but harder to operationalize), and which are policy concerns where software detection alone cannot win.

### 1.6 Channel Design Properties

Each channel in the rest of this document is evaluated on six axes. Knowing the axes up front makes the technique chapters tractable:

- **Bandwidth.** Bytes per second. Distinguishes mailbox-style shared memory (megabytes per second) from MSR-based one-bit storage (a handful of bits per query).
- **Direction.** KM→UM only, UM→KM only, or bidirectional. Some surfaces are naturally one-way (Mailslot, PsSetCreate); bidirectional channels typically require either an explicit second back-channel or an object both sides can observe (section, ALPC port).
- **Trigger model.** Polling, callback, exception, object event, or hardware event. The trigger model determines what the attacker's runtime looks like in CPU and ETW telemetry.
- **PatchGuard exposure.** From the table above.
- **Attribution difficulty.** Whether a normal driver, OS component, or application can plausibly produce the same signal. A signal that is unique to unauthorized tooling is more actionable than one that overlaps with five legitimate products.
- **Build fragility.** Whether offsets, structures, or object layouts shift across Windows builds. Drives the cost of a robust detector.

### 1.7 Attacker Channel Construction Model

The most useful way to read the following techniques is to treat each one as a protocol assembled from Windows primitives, not as a single API trick. Mature kernel-assisted threats rarely rely on "call this one function and send bytes." They split the channel into pieces so that each artifact looks mundane in isolation:

1. *Rendezvous surface.* The place where UM and KM agree that a channel exists: an ALPC port name, firmware provider signature, registry path, section handle, file object, WNF state name, device stack, or callback registration.
2. *Trigger edge.* The operation that wakes the hidden logic: a registry set, firmware table query, IRP dispatch, ALPC message, thread-pool completion, page fault, event signal, object open, or VM exit.
3. *Selector plane.* Small fields that identify the command family: registry value type, firmware `TableID`, IOCTL code, file create options, ALPC message type, WNF state name, completion key, status code, buffer length, or timing slot.
4. *Payload plane.* Where bytes actually move: a section view, MDL-locked user buffer, ALPC view, pipe body, socket stream, firmware output buffer, mapped GPU resource, or external hardware mailbox.
5. *Reply plane.* The observable result: output buffer contents, returned size, NTSTATUS, completion status, shared-memory status word, event state, callback side effect, or delayed thread-pool work item.
6. *Lifecycle and cleanup.* How the channel appears, rotates, idles, and disappears: registration at boot, activation only during protected-session runtime, pointer restore after use, generation counters, heartbeat/timeout, and teardown when defender pressure is detected.

This split explains why shallow single-surface checks fail. A registry write may only carry an opcode, while the payload sits in an MDL-backed heap buffer. An ALPC message may only advance an epoch, while the real data moves through a shared view. A firmware table query may look like hardware inventory, while the provider handler is actually a request/reply dispatcher. A thread-pool completion may not contain data at all; it simply makes a normal worker consume a mailbox that was prepared earlier.

The attacker-side state machine usually has the same shape across surfaces:

1. *Bootstrap.* Establish the hidden endpoint and prove both sides are present. This can be a one-time pointer transfer, provider registration, section duplication, callback registration, or borrowed handle placement.
2. *Capability negotiation.* Exchange build number, feature mask, protocol version, pointer size, encryption/compression flags, and supported command classes. Size-probe APIs and "buffer too small" replies are often repurposed for this phase.
3. *Operational epochs.* Each command carries a generation, sequence number, command ID, flags, input length, output length, status, and optional integrity value. Ring buffers also carry producer/consumer indices and wrap counters.
4. *Synchronization.* The channel chooses between polling, event signaling, ALPC replies, completion queues, `WaitOnAddress`, APC delivery, thread-pool callbacks, or hardware traps. High-quality implementations try to keep this edge consistent with the surface being mimicked.
5. *Error and fallback.* If the primary path is blocked, the protocol may fall back from ALPC to registry, from a section to MDL pages, from a socket to firmware-table replies, or from a visible helper to a broker process.
6. *Teardown and anti-inspection behavior.* The channel restores patched pointers, unregisters providers/callbacks, zeroes headers, rotates names, drops handles, or goes read-only when it detects inspection.

Several protocol fields are worth calling out because they reappear everywhere: magic/version, build guard, channel ID, role, generation, sequence, command ID, flags, input length, output length, status, heartbeat, timeout, cancellation bit, feature mask, nonce, and checksum or MAC. The transport changes; the grammar does not. When reverse-engineering a suspected channel, identify these fields first. The moment a "random" registry value, firmware table ID, ALPC payload, shared memory page, or completion status starts behaving like this grammar, the object stops being ordinary OS traffic and becomes a covert protocol candidate.

### 1.8 Defender Strategy

Use a layered strategy:

1. *Inventory* the normal communication surfaces at boot and at protected workload launch: device objects and IOCTL paths, sections, ALPC ports, named pipes, RPC endpoints, COM local servers, named objects, WNF state names, Filter Manager communication ports, WFP providers / callouts, virtual HID stacks, Cloud Files / ProjFS provider roots, I/O rings, CLFS logs, and transaction-backed file/registry activity.
2. *Baseline* the high-risk kernel pointers (`HalPrivateDispatchTable`, `ObTypeIndexTable`, callback arrays, dispatch tables) under known-clean conditions.
3. *Correlate* cross-layer behavior. A suspicious callback plus a suspicious user-mode mapping is stronger than either signal alone.
4. *Treat unknown signed drivers as untrusted* until their objects, callbacks, sections, and memory mappings are accounted for.
5. *Prefer version-aware parsers* and symbol-backed validation over hard-coded offsets. The most common reason a production detector regresses is not a missed technique: it is a Windows build that shifted a structure by 8 bytes.

The document is organized along the surface axis: user-mode IPC namespace first (§2), system-information and kernel-reflection channels (§3), documented KM-UM mediation surfaces including WFP, virtual HID / class-input paths, eBPF, and provider-backed file-system callbacks (§4), kernel callback infrastructure (§5), driver-object and dispatch surface (§6), kernel `.data` pointer surface (§7), memory-backed bidirectional channels including MDL-backed mailboxes and I/O rings (§8), the GPU / DXGK / D3DKMT subsurface that is new in v8 (§9), execution-flow and signal channels (§10), CPU and hypervisor channels (§11), persistent storage and firmware including CLFS, ACPI method evaluation, and KTM-backed transactions (§12), and external hardware plus PCIe / CXL boundary drift (§13). Sections 14 to 16 cover recent research, the detection engineering program, and realistic limits.

---

## 2. The User-Mode IPC Namespace Surface

The most accessible covert channels live in user-mode IPC primitives that Windows ships and that overlays, launchers, anti-malware, and accessibility tools have been using for decades. A defender's first inventory pass is *the object namespace as observed when the protected workload starts*: what exists that should not, what was created after the suspect driver loaded, what is owned by an unknown image, what name is fresh enough to have rotated since the last scan. In anti-cheat deployments, the protected workload is usually the game plus launcher and helper processes; in malware response, it may be a service, browser, EDR-adjacent process, or injected host. This section walks the primitives in roughly increasing order of subtlety.

### 2.1 Mailslots

Mailslots are an old single-direction message-based IPC: a process creates a mailslot with `CreateMailslotW` and other processes write to it via `\\\\.\\mailslot\\Name`. The Win32 path is a DOS-device view over the NT mailslot device namespace; a kernel component should be modeled as opening `\\Device\\Mailslot\\...` or a resolved local DOS-device alias through native file APIs, not as relying on the literal Win32 string. The classic covert-channel layout reverses the usual direction:

- *KM writer* opens `\\Device\\Mailslot\\X_name` or the build/session-resolved local alias from the kernel component.
- *UM reader* creates `\\\\.\\mailslot\\X_name` and reads messages.

A reply path requires a second mailslot or another IPC primitive: mailslots are one-way per slot. Windows mailslots do support domain-style broadcast, but that is a network fan-out feature, not a useful buffered reply path for a same-host KM-UM channel.

**Why attackers still use it.** Mailslots are *old*. Many modern telemetry pipelines treat them as legacy and either skip them or down-prioritize alerting. Commodity cheat loaders and lightweight malware stagers favor them because they require no custom driver device object and the user-mode side is two API calls. The bandwidth is poor: remote/network mailslot messages are limited to 424 bytes, while local mailslots can be configured with larger per-slot limits but remain one-way, queue-like, and weakly synchronized. They therefore tend to appear for command framing and configuration, not for memory dumps.

The protocol shape is usually simple: fixed-size command records, a sequence number, a command ID, and a small payload or pointer to another channel. Because there is no natural reply on the same slot, mature stacks pair a mailslot with a section/event pair, a registry trigger, or a second reverse-direction slot. A one-way mailslot that only appears during the handshake and then goes quiet is often a rendezvous channel, not the final bus.

**Detection.** Enumerate `\\Device\\Mailslot\\` when the protected workload starts and at intervals during runtime; alert on mailslots created after launch by workload-adjacent or unknown processes. Store creator PID, server handle owner, slot path, first/last write time, message-size distribution, writer processes, and whether the slot is paired with a second IPC object. Random-looking, cheat-style, or service-mimicking names ("MsiSync", "WinSec", "GpuCacheW") that resolve to unsigned or unknown image owners are the signal. Legitimate mailslot use is rare on consumer gaming systems; most positive matches in production telemetry are enterprise software that has no business on a gaming machine.

### 2.2 ALPC and LPC Private Ports

ALPC is the native local IPC mechanism behind a large fraction of Windows service plumbing. LPC-era APIs are effectively legacy vocabulary; on modern Windows the interesting object is ALPC: named connection ports, per-client communication ports, request/reply messages, optional shared views, handle attributes, completion integration, and security context. CSRSS, LSASS, RPCSS, audio, brokered COM, UWP infrastructure, EDR, anti-malware, browser sandboxes, game launchers, DRM, and overlay stacks all use ALPC or sit above a local RPC/COM layer that may lower into ALPC. That makes the surface common enough that "ALPC exists" is worthless as a finding, but it also makes ALPC one of the most practical L2 command channels in kernel-assisted threat stacks.

The object model matters. A server creates a *connection port* under a namespace such as `\RPC Control\...`; a client connects; the kernel gives each side connected *communication-port* handles. The connection port is the advertised rendezvous object. The communication ports are the actual per-client endpoints. A detector that records only the advertised name misses the handle topology that proves who talked to whom. This distinction is exactly why ALPC is more useful than a named pipe for mature attackers: the visible name can be boring, while the real data path is per-client, handle-based, and short-lived.

#### ALPC Structural Model: Ports, Queues, Messages, and Attributes

ALPC should be modeled as a small object graph, not as one named object. The minimum graph has three port roles and several optional side structures:

1. *Server connection port.* The named rendezvous object. Clients discover or bind to this object, often through a raw `\RPC Control\...` name or indirectly through Local RPC / COM activation.
2. *Client communication port.* The unnamed endpoint handle held by the client after a successful connection. This is the client's session object.
3. *Server communication port.* The server-side per-client communication endpoint. A server with many clients has many per-client relationships even if it advertises only one connection port.
4. *Message queues.* Requests, replies, wait states, and queued messages are associated with the port graph. A thread may be waiting for a new message, waiting for a reply, or unwaiting because of timeout/cancel/close.
5. *Section/view state.* ALPC can associate shared-memory views with communication, so a small message can point at a much larger data plane.
6. *Handle and context state.* ALPC can carry or associate object handles and context-like metadata, which means object transfer and per-message state can happen without a namespace name.
7. *Completion state.* Asynchronous replies can be observed through completion-list, event, or I/O-completion style behavior. In practice, this makes ALPC both a message transport and a wake-source transport.

The normal flow is:

```text
Server setup:
    server creates / registers connection port
        |
        v
Client bind:
    client connects to the named endpoint
        |
        v
Kernel session state:
    client communication port <-> server communication port
        |
        v
Exchange:
    request / reply messages
    optional view, handle, context, security, token, or completion attributes
        |
        v
Teardown:
    disconnect, close, queue drain, view/handle lifetime cleanup
```

For defenders, the important point is that the advertised connection port is only the first node. The evidence usually lives in the session graph: which client holds which communication-port handle, which server owns the matching side, whether the message queue behavior matches the claimed service, and which side objects appeared immediately after the connection. A port name that looks ordinary but creates a new page-file-backed section, event, completion port, or process handle in the protected process is not ordinary.

The message itself has two layers. The visible body may look like a small opaque binary blob, but the effective message includes header-like metadata, message type, request/reply relationship, sender identity, timeout/cancel behavior, attributes, and side-object lifetime. That is why message-size histograms alone are weak. A 16-byte message can be the entire command, a wake edge for a section mailbox, a handle-transfer envelope, or an RPC method dispatch.

#### Attacker Mechanics: ALPC as a Brokered Control Plane

ALPC is attractive because it is not just "messages over a named port." It is a brokered local IPC mechanism with endpoint objects, message queues, optional attributes, security context, handle transfer, shared views, completion-style delivery, and RPC/COM layers above it. A cheat can use any one of those pieces as the channel, or use ALPC only long enough to broker a different object.

A practical ALPC attacker model looks like this:

1. *Advertise or borrow a connection surface.* A helper, broker service, injected module, or legitimate-looking local server exposes a connection port, often under `\RPC Control\...` or behind an RPC/COM activation path. More subtle designs do not expose a fresh obvious name; they reuse a broker that already has a reason to speak ALPC.
2. *Bind and create per-client state.* After connection, the meaningful evidence moves from the named connection port to the connected communication-port handles, per-client context, and side objects. The visible name is only the lobby; the communication port is the session.
3. *Negotiate a small protocol.* Early messages usually carry magic, version, build number, feature mask, process identity, session nonce, and a descriptor for the real payload channel. If the payload is a section or MDL-backed mailbox, ALPC may only carry "generation N is ready" messages afterward.
4. *Broker side objects.* ALPC can associate message attributes with handles, views, security context, and per-message context. That lets the channel pass or reference unnamed sections, events, completion ports, jobs, process/thread handles, or other rendezvous objects without placing a stable object name in the namespace.
5. *Separate payload from wake edge.* The message body can stay tiny while an ALPC data view, page-file-backed section, GPU shared resource, or MDL-backed private buffer carries the real data. Alternatively, the message body can be empty and the arrival order, timeout, cancellation, reply status, or disconnect itself is the signal.
6. *Retire aggressively.* Mature stacks close the connection port, leave only connected handles, rotate the advertised name, or move from a visible helper to a broker-owned endpoint after bootstrap. This makes after-the-fact namespace snapshots weak.

That is why ALPC shows up so often in high-end user/kernel-adjacent control planes. It blends with Windows service traffic, supports request/reply and asynchronous patterns, can lower from RPC/COM so raw ALPC is not visible in application code, and can create object relationships without object names. A named pipe mostly gives bytes. ALPC gives bytes, identity, handles, views, completion, and broker semantics.

The protocol grammar usually appears in one of five forms:

1. *Raw fixed-record messages.* The body is a compact binary record: magic, command, sequence, flags, input length, output length, status, and optional payload. This is common in commodity helpers because it is easy to reverse and easy to fuzz.
2. *Epoch-only messages over shared memory.* The ALPC body is a small counter or opcode. The actual command and result live in a shared view, section, or MDL-backed mailbox. Message-size telemetry looks harmless because the port only carries wakeups.
3. *Handle-broker messages.* The message carries or refers to a handle-like attribute so the receiver gains access to an unnamed object. The important artifact is the newly reachable object, not the message bytes.
4. *RPC/COM method camouflage.* Local RPC/COM supplies interface UUIDs, NDR framing, activation identity, authentication, and method numbers. The cheat hides an opaque blob in a method parameter or uses a private local server whose lower transport is ALPC.
5. *Completion and queue semantics.* Asynchronous replies, completion-list behavior, I/O completion ports, direct-event style wakeups, timeout/cancel status, and queue depth become low-bandwidth signals or execution triggers.

Mature ALPC use is not "create port named X." It is "make the game or helper obtain the right endpoint, side object, security context, and wake source, then move the payload somewhere else."

The common cheat shapes are:

1. *Private service-looking port.* A helper creates a port with a vendor, telemetry, updater, crashpad, audio, browser, or RPC-like name shortly before the protected workload starts. The protected process, injected module, or loader connects and sends fixed-size command records. This is the commodity version.
2. *Section-view transport.* ALPC messages are only the control plane. During connection or early handshake, one side associates a section/view and then uses tiny ALPC messages as epochs, opcodes, or "data ready" notifications. The payload moves through the shared view, so message-size telemetry looks harmless.
3. *Handle shuttle.* The ALPC message carries handles or handle-like attributes for a section, event, completion port, job, process/thread object, or another rendezvous object. The ALPC port is not the final channel; it is the broker that makes an otherwise unnamed object appear in the game or helper process.
4. *Broker camouflage.* The cheat hides behind local RPC or COM. User mode appears to call a local service, COM server, or endpoint-mapper-resolved interface, but the lower transport is an ALPC port whose method payloads are opaque binary blobs. This is common because many legitimate Windows and vendor components already expose RPC/COM endpoints.
5. *Notification-only channel.* The message body is irrelevant. Arrival order, reply status, timeout, cancellation, disconnect, or thread-terminate port notification (§10.10) carries the state. This is low bandwidth but useful for phase changes, watchdogs, and teardown.
6. *Kernel-assisted endpoint insertion.* A kernel driver duplicates, inherits, or plants a connected ALPC handle into the protected process, so the endpoint appears without a clean user-mode parent path. More aggressive variants tamper with ALPC kernel objects or queues so a user-mode inventory sees a plausible relationship while the kernel object graph tells a different story.

ALPC has several attributes that are especially useful to attackers and especially important to defenders:

- *Message attributes.* ALPC supports optional attributes beyond the raw message body, including security, context, view, and handle-style metadata. The exact native structures are private and build-sensitive, but the security model is not simply "bytes on a port." A detector should store which attribute families appear, not just body length.
- *Section and view state.* A shared view turns ALPC into a high-throughput shared-memory rendezvous. The port message can be a 16-byte epoch while megabytes move in a mapped section. This is why ALPC must be correlated with VAD/section inventory (§8.1), not analyzed as an isolated IPC primitive.
- *Handle graph mutation.* Handle passing or driver-assisted duplication can create object relationships with no namespace name. Capture it as a graph: source process, target process, object type, granted access, duplication time, inherit flag, and whether the object later appears in an ALPC attribute or message cadence.
- *Security and impersonation.* ALPC is designed for service security boundaries, so tokens, SIDs, security quality of service, impersonation level, and server-side client identity checks are normal. A suspicious channel often gets these wrong: overly broad DACL, anonymous or low-integrity client where a vendor service would require a service SID, impersonation enabled with no documented reason, or a port name that claims to be system-owned but is created by a per-user helper.
- *Completion and high-rate delivery.* ALPC integrates with completion-style delivery. Windows headers expose ALPC tracing flags and ALPC-specific status values such as `STATUS_ALPC_CHECK_COMPLETION_LIST`, which is a reminder that high-throughput ALPC can look like asynchronous queue traffic rather than a simple blocking request/reply loop.

#### Attribute Abuse: Views, Handles, Context, and Direct Events

The public documentation surface is intentionally thin, but public research and Windows Internals-derived material consistently point to the same security-relevant attribute families: security/QoS, view/data, context, handle, token, direct event, and work-on-behalf-style state. For covert-channel analysis, the exact private layout is less important than the role each attribute plays.

1. *View/data attribute.* This turns ALPC into a rendezvous for shared memory. The port message can carry only an epoch while a mapped view holds command records, entity snapshots, or feature configuration. A defender that records only message length misses the data plane.
2. *Handle attribute.* This is the unnamed-object broker. A sender can make a receiver gain access to a section, event, file, process, thread, completion port, job, or another object without advertising that object in `\BaseNamedObjects` or `\RPC Control`.
3. *Context attribute.* Per-message or per-port context gives the protocol a place to store sequence IDs, correlation IDs, client role, generation, or state-machine phase without placing everything in the visible message body.
4. *Security/QoS and token state.* These fields are normal for service boundaries, but they are also where role mismatch appears. A service-looking port accepting anonymous or low-integrity clients, or enabling impersonation without a product reason, is much more interesting than a random ALPC name.
5. *Direct event and completion state.* Asynchronous replies can be delivered through completion-style paths, shared events, or queue polling. This lets ALPC become a wake source for thread-pool work (§10.12) while the payload is elsewhere.

For reverse engineering, label every observed ALPC conversation by *which attribute family changes the object graph*. If the message body is boring but a new section handle appears in the protected process, it is a handle/view channel. If no side object appears but wait/reply timing is precise, it may be a completion or notification channel. If a service-looking port accepts a client with a security context that the real service would reject, the bug is in role and policy, not bytes.

#### Kernel-Assisted Endpoint Insertion, Spoofing, and Blinding

A kernel component does not have to respect the user-mode story of an ALPC connection. Recent ALPC research demonstrates that driver-level manipulation of ALPC structures can create mismatched or illegitimate connection graphs: one side believes it is connected to one peer while messages are routed elsewhere, or a legitimate peer is blinded because messages no longer arrive on the expected queue. For defenders, that matters even if the attacker never targets EDR directly. A privileged driver can make user-mode handle enumeration, namespace enumeration, and observed message flow tell different stories.

This produces three attacker-relevant variants:

1. *Endpoint insertion.* A connected ALPC handle appears in the protected process without a plausible launcher, broker, COM activation, or handle-duplication lineage. The handle is real, but the user-mode creation path is missing.
2. *Graph spoofing.* Client-side and server-side views of the connection disagree. The client believes it is bound to a benign broker; kernel object relationships or message flow show another server, queue, or communication-port relationship.
3. *Blinding or selective diversion.* A legitimate endpoint remains visible, but selected messages are consumed, redirected, delayed, or made to arrive at another queue. This can hide a control plane behind a service that still appears alive.

The defender response is cross-view consistency. For each suspicious ALPC connection, compare: namespace port, server process, client process, connection-port object, client communication port, server communication port, handle table entries, message send/receive ETW, wait/reply ETW, VAD/section deltas, and side-object handle transfers. A single view can be spoofed. A coherent graph across all of those views is harder to fake.

#### Presented Case Notes: ALPC and RPC Over ALPC

Public ALPC/RPC presentations are useful because they show how the same primitive appears in real Windows services, not only in theoretical rootkits.

1. *REcon 2008, LPC/ALPC privilege-escalation work.* The relevant lesson is that LPC/ALPC endpoints are security boundaries, not just IPC names. For this document, the transferable technique is endpoint-role validation: who can connect, what identity the server believes the client has, what message classes are accepted, and whether the server's policy matches the object namespace and token evidence.
2. *HITB 2014, ALPC Fuzzing Toolkit.* The presentation framed ALPC as the substrate below RPC, DCOM, custom raw endpoints, and common Windows services, and emphasized mapping connections and monitoring messages. For this document's detection model, that maps directly to graph capture: enumerate destination ports per process, map connected endpoints, record message cadence, and look for raw custom endpoints that behave like private protocols.
3. *PacSec 2017, A view into ALPC-RPC.* The important technique is RPC-over-ALPC reduction. A suspicious call may be visible as an RPC interface UUID and method number rather than a raw ALPC opcode. The case examples around service interfaces and UAC/AppInfo-style flows show why endpoint name, interface UUID, opnum distribution, NDR payload shape, and impersonation behavior must be captured together.
4. *DEF CON 32, ALPC security features against RPC services.* The practical lesson is that ALPC/RPC security metadata can be the attack surface. Authentication level, impersonation level, security QoS, direct event/completion behavior, and server-side assumptions should be treated as protocol fields. An attacker helper that copies a service-looking endpoint but uses permissive or inconsistent security settings is leaving exactly this kind of evidence.
5. *ALPChecker / HITB 2023 and arXiv 2024.* Spoofing and blinding research is a reminder that a privileged component can make one ALPC view lie. Therefore ALPC evidence must be multi-view: namespace, handle table, client/server communication ports, message ETW, VAD/section deltas, side-object transfer, and kernel object graph. This is the difference between "unknown ALPC port" and a defensible endpoint-insertion finding.

**Why attackers use it.** ALPC gives a mature bidirectional transport without a custom device object, custom IOCTL, TCP listener, or obvious named section. It blends with service traffic, survives simplistic "no suspicious device" policies, supports both small request/reply records and section-backed payloads, and can be hidden one layer below RPC/COM. It also lets the attacker split evidence: the port name is benign-looking, the payload is in a view, the wake signal is an empty message, and the handle graph is created by a broker or driver.

**Detection.** Treat ALPC as a state machine, not as a list of names:

1. *Namespace and owner inventory.* Enumerate ALPC/LPC port objects under `\RPC Control` and related object directories before launch, when the protected workload starts, and during protected-session runtime. Store port name, object type, server process, signer, image path, service identity, session, SID, security descriptor, creation time, and deletion time.
2. *Connection topology.* For every protected-workload-adjacent process, build a handle graph of ALPC port handles. Separate connection ports from connected communication ports where the object information allows it. Store server PID, client PID, handle access, connection count, duplicated/inherited handles, and whether the endpoint appeared without a plausible `CreateProcess` / broker / launcher path.
3. *Message cadence.* Use ETW where possible. Microsoft documents `EVENT_TRACE_FLAG_ALPC` and event types for send, receive, wait-for-reply, wait-for-new-message, and unwait; Windows Performance Recorder also exposes connect, close, send, receive, wait, and unwait-style ALPC kernel events. Store message-size histogram, request/reply ratio, timeout/cancel status, burst timing, and whether messages cluster around memory reads, overlay updates, or input decisions.
4. *Attribute and side-channel evidence.* Track whether a conversation carries section/view-like attributes, handle-like attributes, security/context attributes, direct-event/completion behavior, or work-on-behalf-like state. A small stable message paired with a new mapped section or event handle in the protected process is stronger than either signal alone.
5. *Section/view correlation.* When an ALPC connection appears, diff the game/helper VADs and section handles. Look for page-file-backed sections, anonymous mappings, or views that appear immediately after the connection and then receive high-frequency writes while ALPC messages remain small.
6. *Handle-broker correlation.* Diff unnamed handles before and after connection: section, event, I/O completion, job, file, process, thread, token, and port handles. Record source/target process, granted access, inherit flag, duplicate time, and whether the handle becomes a mailbox, wake object, or brokered capability.
7. *RPC/COM lowering.* Correlate local RPC endpoint mapper entries, COM `LocalServer32` / `LocalService` activation, interface UUIDs, method cadence, authentication level, impersonation level, and ALPC ports. A per-user COM or RPC server that appears only during protected workload runtime and lowers into a private ALPC port is a more realistic attacker shape than a naked `\RPC Control\Cheat` name.
8. *Cross-view validation.* Compare object-namespace enumeration, handle-table data, ETW ALPC events, VAD/section state, kernel object walks, and client/server communication-port relationships where available. Public research on ALPC attacks shows that kernel-level ALPC object manipulation can blind or spoof user-mode views; therefore a production detector should not trust a single user-mode inventory.
9. *Teardown behavior.* ALPC channels often disappear cleanly at match end. Record disconnect order, close timing, orphaned communication ports, whether the shared view or passed handles survive after the advertised port closes, and whether a broker-owned endpoint remains while the helper exits.

Do not stop at "unknown ALPC port." A stronger package is: unknown or role-mismatched owner, protected-process/helper endpoint handle, short lifetime tied to the protected session, fixed binary message cadence, section or handle transfer near connection time, and no vendor-manifest explanation for the namespace being mimicked.

False positives are real and broad. Browsers, launchers, crash handlers, anti-malware, DRM, accessibility tools, voice chat, overlay platforms, RPC/COM brokers, and Windows services all create ALPC traffic. Ownership and relationship decide the finding: a stable service-owned port with documented clients is normal; a per-session helper-owned port, a fake service namespace, or a driver-assisted connected handle inside the protected process is not.

### 2.3 Custom Symbolic Links

A driver can create an object-manager symbolic link with `IoCreateSymbolicLink` (or with native object routines for unnamed directories) that points at a device, a section, an object directory, or another link. The link name can be rotated, made to look like a normal vendor component, or hidden under a private object directory accessible only through a kernel side.

The link itself carries very little: its *existence*, its *target*, or the result of opening it can encode state, and rotating the target gives the channel a kind of clock. This is a *rendezvous* primitive more than a data primitive. It rarely appears on its own; it almost always feeds into a section, device, or directory channel.

The subtlety is namespace placement. A link under `\\??` or `\\GLOBAL??` is easy for user mode to resolve through DOS-device paths. A link under a per-session `\\Sessions\\...\\DosDevices\\...` directory scopes discovery to one logon session. A link under a private object directory can be reachable only after another channel discloses the directory handle or name. A cheat can also chain links: the visible link points to a second link whose target rotates, so a shallow resolver stores the benign first hop and misses the real endpoint.

The user-mode side usually does not care that the object is a link. It tries to open a normal-looking path and interprets success/failure, final target type, returned handle type, or returned status as state. The kernel side can change the link target or delete/recreate the link to signal phases. This makes the primitive useful for "current endpoint is ready", "switch to section generation N", or "fall back to pipe mode" rendezvous.

#### DOS-to-NT Path Normalization and MagicDot-Style Namespace Camouflage

Black Hat Asia 2024's MagicDot research is not a kernel driver talk, but it matters to covert KM-UM channels because many detectors still store only the path string they received from Win32 APIs. MagicDot shows the same object can be seen differently depending on whether the observer records the raw DOS path, the normalized NT path, a shell path, an archive extraction path, a short 8.3 name, or a handle-derived final path. For a channel that is already hiding behind symbolic links or object directories, this creates a second camouflage layer: the rendezvous object can be opened through one path form while scanners, UI tools, and allowlists report another.

**Presented case note.** MagicDot's transferable communication lesson is path-identity disagreement. A covert endpoint does not need to hide its bytes if it can make different observers disagree about which object was opened. For this document, the relevant fields are raw input path, normalized NT path, resolved symbolic-link target, handle-final path, file ID, short-name expansion, section object path, and process image path. Any IPC endpoint, section-backed payload, or helper process launched through a path-confusion chain should be scored as a rendezvous-camouflage case, not only as a file-system oddity.

The communication value is in *identity confusion*, not bandwidth. A helper can advertise a benign-looking path, then reach a different NT object after DOS-to-NT conversion strips trailing dots or spaces from selected path elements. A symbolic link can also point at a path whose display name differs from the object manager name, causing one component to record "normal vendor path" while another component opens the real channel endpoint. In process telemetry, the same idea appears when the image path used for launch, the section object's file name, the handle-derived final path, and the displayed process path do not agree.

Operationally, this pairs with:

1. *Symbolic-link rendezvous.* The link name is innocuous, while the target path relies on path-normalization ambiguity.
2. *Private object directories.* The disclosed name is a DOS-device style alias; the real object sits under an NT object directory that naive Win32 enumeration never reaches.
3. *Section-backed payloads.* The path is only the discovery artifact. After opening, the payload moves through a section or ALPC view, so the path anomaly is a bootstrap signal.
4. *Process-helper camouflage.* A short-lived helper launched through a confusing path can make Task Manager, Process Explorer, prefetch analysis, and handle-based inspection disagree about what executable actually backed the process.
5. *Archive or updater staging.* The same class of path conversion issues appears when launchers, patchers, or repair tools unpack files before the protected workload starts. An attacker can abuse that window to create a disguised endpoint before defender baseline capture.

**MagicDot-specific detection.** Store multiple path views for every high-risk file, section, process image, symbolic link, and device path: raw input path, native NT path, recursively resolved symbolic-link target, handle-derived final path, short-name expansion, file ID / volume serial, and section-file object name. Never allowlist only a display path. Flag paths with trailing dots, trailing spaces, `\\?\` prefixes, `GLOBALROOT`, per-session DOS-device aliases, alternate data stream lookalikes, unusual short-name collisions, or path elements whose raw and normalized forms diverge. For process images, compare `CreateProcess` input, PEB image path, section object path, file ID, signer, and ETW image-load path. The high-confidence finding is not "a dot in a path"; it is one executable, section, or IPC endpoint presenting different identities across independent Windows views during protected workload runtime.

**Symbolic-link detection.** Enumerate object-manager symbolic links before protected workload launch and during runtime; resolve targets recursively and validate the owning driver. Store link name, directory, target string, final object type, security descriptor, first-seen time, last-seen time, and target history. Treat link churn as evidence: create/delete/recreate cycles during a protected session are often more important than any single name. The most useful signal is links created by drivers with no plausible reason to expose user-openable namespace entries to the protected process. Virtual-input drivers, RGB controllers, anti-cheat, and security products legitimately create links; an unsigned or recently signed driver that creates a link whose target points at a private section is high severity. Also store the path-normalized identity described above for every link target; otherwise a MagicDot-style target can defeat an otherwise correct link inventory.

### 2.4 Anonymous Named Objects

Named objects such as events, sections, mutants, semaphores, and directory entries can carry state in their *name* alone. A cheat can create an object with a GUID-like or random-looking name under `\\BaseNamedObjects`, a private object directory, or a device-specific namespace, and use object presence as a state bit, the name itself as a small payload, or the wait state as a synchronization primitive.

This is reliable and easy to rotate. It pairs naturally with shared memory and event signaling: a section carries the data, an event signals "new payload ready", and the name of either object encodes the channel epoch.

Private namespaces raise the ceiling. `CreatePrivateNamespace` lets user mode create a namespace with a boundary descriptor; objects are named as `prefix\\object`. Microsoft documents that multiple namespaces can share the same alias prefix when their boundaries differ. That gives a cheat a useful ambiguity: a scan that records only `prefix\\Ready` without resolving the boundary descriptor and creator identity cannot tell which namespace was used. Microsoft also documents a subtle lifetime behavior: after the namespace handle is closed, later `OpenPrivateNamespace` calls fail, but operations on already created objects in the namespace continue to succeed. A helper can use that to separate discovery failure from object lifetime.

Anonymous handles are the other half. An event or section can be unnamed and still shared through inheritance, handle duplication, or broker handoff. That is why namespace inventory must be paired with handle inventory. A protected process receiving an inherited event handle from a launcher or service parent can be normal; receiving a section/event pair from an unrelated helper immediately after an unknown driver loads is not.

**Detection.** Snapshot the object namespace at protected workload launch and watch deltas. Store object type, name, namespace root, private-namespace alias and boundary where visible, security descriptor, handle count, pointer count, creator process if captured, and mapped/opening processes. The signals are: GUID-like or random names created after launch by unknown processes, ACLs that grant access to specific suspect SIDs, private namespace aliases that mimic vendor components, and objects whose creator does not have a documented reason to expose a private namespace entry to the protected process.

Game launchers, overlays, anti-cheat, browsers, and engines all create many named objects; the discriminator is *novelty relative to a clean baseline* and *correlation with an unknown driver load*.

### 2.5 Symlink Farm Rotation

A *farm* of symbolic links rotated on a schedule defeats one-shot namespace snapshots. The cheat creates and destroys links, retargets active links, or moves the "current" link through a sequence of names. The active link, the target, or the rotation phase encodes state. The defender that scans every five minutes sees a different name each time and may never connect the observations.

The rotation family usually has stable hidden features even when names change: same target driver, same parent directory, same ACL template, same name length, same character alphabet, same deletion delay, same two-hop target pattern, or same owning service. Some variants maintain several live links and encode state in which link resolves successfully; others keep one stable name and rotate only the target. Both defeat IOC-style matching.

Evidence is family-level, not link-level. Treat a rotating set as one object with many aliases: parent directory, creator, target object class, target driver, ACL hash, name alphabet, lifetime distribution, and creation cadence. This also catches the two-hop variant where visible links point at a stable intermediate directory while the final target changes.

**Detection.** Do not rely on snapshots; track create/delete *rates* for symbolic links over time. Validate target history and owning driver. Cluster links into families by parent directory, target type, owner module, ACL hash, name-shape features, and lifetime. Store failed open attempts too: a farm often exposes only one valid link at a time, and repeated failed probes from the helper reveal the sequence. A driver stack that creates transient links during normal operation is rare; high-frequency rotation during protected workload runtime is unusual outside of compatibility-shim software, and the owner image will usually be a known vendor in those cases.

### 2.6 Hidden Window Properties and Message-Only Windows

Windows allows arbitrary named properties to be attached to a window via `SetProp` / `GetProp`. A hidden or message-only window (the `HWND_MESSAGE` parent) can carry state in property names, property values, the class name, or the window's extra bytes. This is naturally UM-to-UM, but KM can trigger it via an APC, callback injection, or `KeUserModeCallback`-style GUI path manipulation (§8.5).

Many overlays and launchers already create hidden windows for legitimate reasons, which makes the surface noisy and the signature hard to write narrowly.

Message-only windows are particularly useful because Microsoft documents that they are not visible, have no z-order, are not reached by ordinary broadcast messages, and are found through `FindWindowEx(HWND_MESSAGE, ...)` or equivalent enumeration. Registered window messages add another layer: `RegisterWindowMessage` maps a string to a system-unique message ID in the `0xC000`-`0xFFFF` range, returns the same ID to cooperating processes that register the same string, and keeps the registration until the session ends. A cheat can therefore use the registered message string as a rendezvous name, the message ID as a compact selector, `WPARAM` / `LPARAM` as small payload fields, and window properties as backing state.

The practical pattern is:

1. A helper creates a message-only window with a service-looking class name.
2. It registers one or more message strings whose names look like vendor telemetry, update, or overlay events.
3. The game-side module posts messages, reads properties, or treats property presence as state.
4. A kernel path wakes or injects the UM helper through APC, GUI callback manipulation, or a separate trigger so the window channel becomes the visible UM half.

**Detection.** Enumerate hidden and message-only windows owned by unknown processes. Validate window class names against owner image signers; enumerate properties with `EnumPropsEx`-style logic; record registered message strings where instrumentation allows; and map HWND -> owning thread -> process -> module. Alert on non-standard properties on protected-workload-adjacent windows. Property names that look like opaque hex blobs or per-session GUIDs are especially suspicious on windows owned by processes that have no display, no overlay, and no obvious accessibility role.

### 2.7 Clipboard Custom Format

`RegisterClipboardFormatW` registers arbitrary custom clipboard format names, after which UM processes can exchange binary blobs through the clipboard under that format. KM cannot drive the clipboard directly, but a UM helper can be triggered through APC, callback injection, or a separate cheat-controlled foreground process to write and read.

Custom formats are *named*. The name persists for the lifetime of the user session. A cheat that wants persistence across overlay restarts can register a custom format, leave it registered, and use clipboard contents under that format as both data and presence.

Clipboard channels become more reliable when paired with a listener window. `AddClipboardFormatListener` causes a window to receive `WM_CLIPBOARDUPDATE` when contents change. A hidden window can register a format, subscribe for updates, and treat sequence-number changes as a trigger. The payload can be delayed-rendered, binary, or disguised as a common custom format. Because every desktop app can touch the clipboard, the attacker gets plausible cover; because the clipboard is session-global, the helper and game do not need a direct handle relationship.

Protocol variants include single-slot overwrite, sequence-number only, delayed rendering, and dual-format handoff (one format carries the opcode, another carries the payload). A careful cheat avoids clipboard content that looks like shellcode and uses the format name, ownership, and update cadence as the real signal.

**Detection.** Monitor custom clipboard format *registration* during protected workload runtime (less noisy than clipboard *content* changes). Capture format name, format ID, registering/opening process, clipboard owner HWND, listener HWNDs, sequence-number deltas, data size, and data entropy for suspicious formats. High-entropy or executable-looking blobs under a recently registered format are a strong signal, but a format whose contents are always empty while listener wakeups align with helper activity is also suspicious. Correlate with overlay/helper processes that have access to the clipboard. False positives come from IMEs, password managers, accessibility tools, and collaboration software; the discriminator is owner image, listener role, and registration timing relative to workload launch.

### 2.8 Global Atom Table

`GlobalAddAtomW` stores a string of up to 255 bytes in the system global atom table and returns a 16-bit atom ID. This is a UM-UM channel by construction, but KM can drive it indirectly through APC or by hooking a UM helper. Atom names can carry base64, hex, or compact command strings; the table is system-wide and persists across processes.

The atom table is the original AtomBombing surface: a 2016-era trick where one process writes a payload into the atom table and uses APC-style execution to invoke atom APIs in a target process. On current Windows builds, mitigations such as ASLR, CFG, ACG/CIG policy, bitness mismatch, and ordinary APC delivery constraints make reliable code execution through that historical chain much less attractive. The *channel* itself remains useful for low-bandwidth configuration and rendezvous.

Atoms have state beyond the string. Microsoft documents that adding an existing string returns the existing atom and increments its reference count, and that global atoms are not automatically deleted when the process exits. That lets a channel encode presence in reference count, leak state across helper restarts, or use delete/re-add behavior as a clock. String atoms also preserve the case of the first added string, which can create small but stable fingerprinting artifacts.

The channel is weak but very cheap: 16-bit atom ID as selector, atom string as payload, reference count as presence, first-case preservation as fingerprint, and delete/re-add cadence as clock. Its best role is discovery: "the helper is alive and the real endpoint name is embedded in the atom string."

**Detection.** Periodically dump the global atom table; flag names that look like base64, hex blobs, compact encrypted tokens, or product-specific magic strings. Correlate with `GlobalAddAtom` / `GlobalDeleteAtom` usage from protected-workload-adjacent processes, and track reference-count-like behavior where available. Legacy GUI software, IMEs, accessibility tools, and shell components all use atoms, so the signature is "shape of the name and timing of registration", not presence.

### 2.9 Registry as Storage and Trigger

The registry is two things at once: durable key-value storage and a trigger surface that fires `CmRegisterCallback` notifications in kernel mode (§5.2). A cheat can use it as either, and almost always uses it as both.

The storage half is straightforward: values are written to keys with SACL tricks, restricted SIDs, symbolic-link keys, unusual Unicode names (combining characters, BIDI overrides, NUL-prefixed names that bypass naive enumeration), volatile keys, or ACLs that block the most common enumeration tools. Configuration, license state, and reboot-persistent command state all live well here.

The trigger half is more interesting. A driver registering a registry callback (§5.2) can treat a *write to a specific key by a specific process* as a command. The UM side simply writes a registry value with the right name and the KM side receives a callback. This is a UM→KM signal that does not require any custom device object, looks identical in ETW to ordinary registry activity, and is trivial to attribute to "Explorer.exe touching its own settings" if the cheat is willing to encode commands inside writes to genuine system paths.

**Detection.** Combine three signals: registry callbacks from unknown drivers (the *trigger* side, §5.2), registry writes by the protected process or its helpers to paths outside the product's normal configuration scope (the *channel* side), and ACL or symbolic-link anomalies on suspected key paths (the *storage* side). Each alone is noisy; in combination they are strong. Resolve registry symbolic links before trusting any path string: the same key string can be redirected to different physical hives without naive enumeration noticing.

### 2.10 Job Object Limit Notification

Job objects can deliver notifications for limits and lifecycle events through a completion port. A cheat can encode low-frequency state through job membership, limits, or completion-port messages.

This is not a high-bandwidth channel. It is useful for lifecycle, watchdog, and "the launcher knows the helper is alive" signaling. The strength of the surface is that job objects already carry sandbox, child-suppression, and process-group semantics for browsers, anti-malware, and launchers, so an attacker helper that joins a job and watches for completion-port messages is hiding behind legitimate sandbox infrastructure.

The important implementation detail is the association between a job and an I/O completion port through `JOBOBJECT_ASSOCIATE_COMPLETION_PORT`. The completion key and message stream become a small out-of-band protocol. A helper can watch for process-start, process-exit, active-process-limit, memory-limit, or end-of-job-time style notifications and treat those lifecycle events as command epochs. Nested jobs add ambiguity: the game may be in a launcher job, an anti-cheat job, and a browser/overlay job at the same time.

The channel is lifecycle-bound. It is good for "helper alive", "child exited", "memory limit reached", "teardown now", or "switch profile"; it is bad for high-frequency payload. That makes it especially useful around launch, restart, and anti-cheat shutdown, where many legitimate lifecycle events already occur.

**Detection.** Inspect the protected process's job membership and limits, and validate the owners of any completion ports attached to those jobs. Store job object handle source, completion-port owner, completion key, process membership, limit classes, UI restrictions, breakaway settings, notification message types, and message cadence. Cross-process job membership where the parent is not the launcher or expected service parent is unusual; completion-port ownership by a non-launcher, non-AV process is suspicious. Compare against expected launcher, service, EDR, or anti-cheat job policy for the protected workload.

### 2.11 Named Pipes

Named pipes are the missing "obvious" surface in many covert-channel and malware-channel writeups because they are not exotic. That is exactly why they remain useful in the lower and middle market: Windows explicitly supports one-way or duplex named pipes, multiple pipe instances under the same name, client connection through `CreateFile` / `CallNamedPipe`, overlapped I/O, impersonation, and local or remote reachability. A commodity attacker can put the UM helper on the server side (`CreateNamedPipeW("\\\\.\\pipe\\...")`) and have the driver or a privileged service connect to the pipe path; a more cautious stack reverses the roles so the visible protected-workload-adjacent process is only a short-lived client.

The kernel-mode side does not need a custom device object to participate. It can open the pipe object through native file APIs, or the cheat can use a small service as a protocol translator between a driver-private mechanism and the pipe. The protocol usually has a fixed header, an opcode, a monotonic sequence number, and a variable payload; the payload can be encrypted, compressed, or padded to mimic normal management traffic. Bidirectional pipes are attractive for request/reply commands, while message-type pipes are attractive for low-volume command framing because message boundaries survive reads. Byte-type pipes are more common when the channel is disguised as a local telemetry stream.

**Why attackers use it.** Named pipes sit in a comfortable gray zone. They are common in launchers, updaters, browsers, anti-malware, debuggers, local web services, and overlay stacks. A suspicious pipe named `\\\\.\\pipe\\CheatPipe` is weak tradecraft, but a pipe that looks like a vendor updater, crash reporter, audio service, RGB controller, or browser broker can survive casual review. The surface also gives the attacker mature synchronization semantics, multiple clients, overlapped I/O, back-pressure, and a clean teardown story without writing any custom kernel IPC.

#### Anonymous Pipe and Standard-Handle Broker Variant

Black Hat USA 2020's Windows rootkit presentation highlights a related but easier-to-miss shape: a kernel component can create or broker a user-mode process and use unnamed pipe handles for command output or helper coordination. This is still a pipe channel, but it does not leave a stable `\\Device\\NamedPipe\\Name` artifact. The important objects are inherited or duplicated handles, standard-input / standard-output / standard-error bindings, and the process that owns the anonymous pipe endpoints.

**Presented case note.** In the Black Hat rootkit framing, the pipe is not necessarily a long-lived named IPC server. It can be a transient process-broker artifact: create helper, attach standard handles, collect output or feed input, then terminate. For defenders, the communication fields are inherited handle source, duplicated handle source, standard-handle object type, pipe file object, helper command line, parent/token/job lineage, byte count, exit status, and whether the pipe output contains the next-stage ALPC/section/WNF/firmware rendezvous.

For cheats, the anonymous-pipe form is attractive when the visible helper is supposed to look like a crash collector, updater, diagnostics subprocess, or command runner. The kernel or privileged service spawns a short-lived user-mode helper, redirects one or more standard handles to anonymous pipes, and treats the helper's output or exit timing as the reply path. The channel can be low frequency: run a helper, collect a small result blob, exit, repeat only on launch or configuration changes. It can also be used as a bridge from a kernel-only trigger into a normal-looking user-mode process that then writes to ALPC, COM, a section, or a named pipe.

The absence of a pipe name changes the defensive problem:

1. *Handle inheritance matters.* The suspicious event is a protected-workload-adjacent or service-spawned process inheriting pipe handles from a parent that should not be its broker.
2. *Standard handles matter.* A GUI helper with non-console standard handles bound to pipe file objects is worth explaining, especially if the process is hidden, windowless, or short-lived.
3. *Parentage can be misleading.* The creator process, logical parent, token source, job membership, and inherited-handle source can disagree when a service or driver-assisted broker creates the process.
4. *The payload may be stdout-shaped.* The data can look like logs, JSON, base64, or command output rather than a binary IOCTL protocol.
5. *The pipe can be only one stage.* Anonymous pipe output can carry the name of the real ALPC port, section, WNF state, or firmware-provider query to use next.

**Detection.** Inventory `\\Device\\NamedPipe\\` before launch, when the protected workload starts, and during runtime. Attribute every pipe endpoint to a process image, signer, command line, parent process, token, integrity level, and lifetime. Prioritize:

1. *Novel pipe names* created after anti-cheat start by unknown helper processes.
2. *Game-process clients* connecting to pipes owned by unrelated vendor-looking services.
3. *Remote-capable pipes* that should be local-only. Microsoft explicitly warns that named pipes can be reachable across the network when the Server service is running; a local game support component should deny `NT AUTHORITY\\NETWORK` or use local RPC instead.
4. *Protocol regularity* such as fixed-size packets, high-entropy payloads, opcode-like first bytes, or request/reply cadence that correlates with game memory reads.
5. *Handle duplication* from a helper or service into the protected process immediately before pipe traffic begins.

False positives are large but manageable. Discord, browsers, Unreal tooling, Steam, Xbox Game Bar, GPU vendors, anti-malware, crash reporters, and accessibility tools all create pipes. Pipe existence is noise; owner role, endpoint relationship, timing relative to driver load, and whether the owning binary can justify the vendor namespace decide the finding.

For anonymous pipes, add process-creation and handle-graph evidence. Record inherited handles, duplicated pipe handles, standard-handle object types, pipe file-object names when available, creator PID, parent PID, job object, token, image signer, command line, process lifetime, exit status, and read/write byte counts. A hidden helper launched during protected workload runtime with stdout/stderr redirected to pipe objects owned by an unrelated service is a stronger signal than any single pipe name. This also catches the case where a kernel driver uses unnamed pipes only as a one-shot command-output path and never exposes a named pipe endpoint.

### 2.12 Local RPC, COM, and Endpoint-Mapper Camouflage

Local RPC and COM are the grown-up version of named pipes. RPC gives a Windows-native client/server programming model with interface UUIDs, endpoints, authentication, impersonation, and the RPC endpoint mapper. COM adds activation, class registration, local servers, brokers, and apartments. Underneath, local RPC may ride over ALPC, named pipes, or other RPC transports, which makes it easy for an attacker to hide a command channel behind "normal Windows service architecture" instead of a raw pipe or socket.

RPC matters because it converts a suspicious binary protocol into an apparently normal method call. The client calls a local stub, the stub marshals parameters into Network Data Representation (NDR), the RPC runtime sends the request through a selected protocol sequence, the server runtime dispatches to a server stub, and the server stub calls the real method. To a caller, it looks like a local function. To telemetry, it may look like RPCSS, endpoint mapper, COM activation, a service-owned local endpoint, or ALPC traffic below the RPC runtime.

#### RPC Communication Model: Interface, Binding, Endpoint, Stub

A workable defensive model has five layers:

1. *Interface contract.* An RPC interface is identified by UUID and version. Method identity is usually an operation number / dispatch index within that interface. COM adds IIDs, CLSIDs, AppIDs, proxy/stub DLLs, and activation metadata.
2. *Stub and NDR layer.* MIDL-generated client/server stubs marshal `[in]`, `[out]`, and `[in, out]` parameters into NDR. Strings, conformant arrays, context handles, interface pointers, BSTRs, SAFEARRAYs, and opaque byte arrays all become structured byte streams. An attacker can hide a command record inside a legitimate-looking method argument.
3. *Binding layer.* A binding handle describes where and how the client calls the server. It may be fully bound with an endpoint already known, or partially bound so the runtime resolves the endpoint later.
4. *Endpoint layer.* The endpoint is transport-specific. For TCP it is a port, for named pipes it is a pipe name, and for `ncalrpc` it is a local interprocess endpoint string that maps into local RPC transport behavior, commonly visible as ALPC below the runtime. Microsoft documents `ncalrpc:[port-name]` as the local IPC endpoint form; the endpoint name is bounded and does not include a computer name.
5. *Security layer.* Authentication service, authentication level, impersonation level, interface flags, security callback, and COM launch/access permissions decide who can call and what identity the server can assume while processing the call.

The lifecycle is:

```text
Server:
    define interface UUID/version and methods
    register protocol sequence and endpoint
    register interface and optional security callback
    optionally register binding vector with endpoint mapper
    listen / dispatch calls

Client:
    discover endpoint directly, through COM activation, or through endpoint mapper
    create binding handle
    optionally set authentication and security QoS
    call interface method through client stub
    receive output parameters and return status
```

This makes RPC a *structured camouflage layer*. The protocol grammar is still there, but it is not visible as a raw `command_id` at offset zero. It may be method number 7, an NDR conformant-array length, an object UUID, a context handle value, a SAFEARRAY size, an HRESULT, an exception code, or a sequence of calls that only makes sense as a state machine.

#### Endpoint Mapper and Dynamic Endpoint Abuse

The endpoint mapper is the discovery broker. A server can use a well-known endpoint, or it can register dynamic endpoints and publish them through the endpoint map database. When a client uses a partially bound handle, the runtime can ask the endpoint mapper for a compatible endpoint. The matching logic includes interface UUID, major/minor version relationship, protocol sequence, and sometimes object UUID.

Attackers care about this because endpoint discovery gives them a legitimate rendezvous mechanism:

1. *Stable identity, rotating transport.* The interface UUID or CLSID stays stable while the actual local endpoint changes per launch. Static IOC matching on a pipe or ALPC name misses the channel.
2. *Endpoint-map camouflage.* The helper looks like a service registering a normal local RPC endpoint. The suspicious data is inside method payloads, not in the endpoint map entry.
3. *Late binding.* The protected-workload-adjacent module does not need a hard-coded endpoint. It can bind by interface identity and let the runtime resolve the current endpoint.
4. *Multi-transport fallback.* A server can expose `ncalrpc`, `ncacn_np`, and sometimes TCP-style endpoints. If ALPC inspection becomes risky, the same interface can move to a named pipe or loopback-style helper.
5. *Short-lived endpoint windows.* A dynamic endpoint can exist only during launch, license validation, operator activation, or protected-session runtime. After endpoint-map cleanup, only client-side traces, call cadence, and side effects remain.

For anti-cheat, endpoint mapper telemetry should not be treated as enterprise-only noise. A per-user helper registering a local RPC interface just before the game connects to it is exactly the kind of high-level cover a cheat wants.

#### RPC Security and Impersonation as Channel Surface

RPC security fields are not only access-control policy; they are observable protocol state. Microsoft documents authentication levels ranging from no authentication through packet integrity and packet privacy, and RPC server/client code can use impersonation so the server thread temporarily runs under the client's security context. Local `ncalrpc` also has special delegation behavior: a local server can impersonate a local client and make one outbound remote call on the client's behalf even when the client specified impersonation rather than full delegation.

For covert-channel analysis, this creates three important signals:

1. *Role mismatch.* A service-looking local endpoint that accepts anonymous, low-integrity, or unexpected per-user callers is suspicious. An attacker helper often chooses permissive settings because it wants the protected process, overlay, payload, or loader to connect without deployment friction.
2. *Impersonation boundary.* Some helper designs intentionally let the server impersonate the game/helper client to access files, registry keys, handles, or network resources under that identity. Others disable or mishandle impersonation because the server wants to keep a higher-privilege service identity. Both choices leave evidence in authentication level, impersonation level, token use, and post-call side effects.
3. *Security callback and interface flags.* Flags such as local-only, secure-only, callbacks-with-no-auth, autolisten, and security-callback caching influence who reaches the server method. A local-only endpoint is not automatically safe; it may be exactly how the channel avoids remote exposure while remaining useful to a local attacker stack.

Detection should therefore store not only "RPC endpoint exists" but also authentication service, authentication level, impersonation level, whether a security callback exists, interface registration flags, COM launch/access policy, and whether the server actually enforces the client identity it claims to require.

#### Attacker Mechanics: RPC as Structured Command Camouflage

The cheat pattern is usually not a full custom enterprise RPC stack. It is narrower:

1. A helper process registers a local RPC interface or COM local server with a plausible CLSID / AppID / interface UUID.
2. The protected-workload-adjacent module or injected overlay activates the COM class, binds to the local RPC endpoint, or asks the endpoint mapper for a dynamic endpoint.
3. Commands are encoded as method arguments, NDR-marshaled blobs, BSTRs, SAFEARRAYs, or custom binary payloads inside otherwise normal-looking calls.
4. The kernel driver either controls the helper, observes the helper through callbacks, or uses the helper as the UM half of a different kernel channel.

The operational advantage is attribution friction. A defender who looks only for `\\Device\\NamedPipe\\foo` or `127.0.0.1:port` misses the fact that the real protocol is "activate this local COM server, call method 7 with a 128-byte blob, receive a marshaled result." The names can be buried in registry class tables, endpoint mapper state, service registration, scheduled task repair logic, or per-user COM registration. The attacker can also separate discovery from traffic: the CLSID is stable and benign-looking, while the dynamic endpoint rotates per session.

The common attacker-side protocol shapes are:

1. *Opaque method blob.* One RPC method takes a byte array, string, BSTR, SAFEARRAY, or "configuration" structure that is really a command envelope. The method name may look like telemetry, diagnostics, crash upload, or device configuration.
2. *Method-number protocol.* The method/opnum is the command ID and arguments are small selectors. This is easy to hide inside a private interface because defenders rarely know the expected method distribution.
3. *Context-handle session.* The first call returns or establishes a context handle; later calls use that handle as the session key. From the outside, the endpoint looks like a normal stateful service.
4. *Endpoint-map rendezvous.* The endpoint mapper is used only to locate the current ALPC/pipe endpoint. After binding, the payload moves through RPC calls or a side channel disclosed by RPC.
5. *COM local-server disguise.* The visible action is CLSID activation and interface method invocation. The lower transport may be ALPC, but the object identity is hidden in COM registry and activation state.
6. *Privilege-broker helper.* A service-owned RPC server receives requests from a lower-privilege helper and performs file/registry/handle/network work. The cheat value is not bandwidth; it is brokered authority and clean-looking service architecture.

RPC is especially attractive in cheat ecosystems that already have a user-mode control module. It gives the helper a product-looking API surface, hides binary records inside NDR, and creates a natural place for license/config/state methods without exposing a custom device object. The kernel component may never call RPC directly; it can still rely on the RPC helper to deliver commands into ALPC, a section, registry trigger, WNF state, or WSK egress path.

#### Presented Case Notes: RPC as a Service-Looking Channel

1. *PacSec 2017 ALPC-RPC service examples.* The research used RPC interface identity, method numbers, and marshaled arguments to reason about reachable service behavior over ALPC. The communication lesson is that the channel can be "call method N on interface UUID X" rather than "send command byte Y to port Z." Detection therefore needs interface UUID/version, opnum distribution, NDR shape, authentication level, and server identity.
2. *RpcView-style endpoint inventory.* Multiple ALPC/RPC presentations and later detection writeups use endpoint/interface enumeration as the starting point. For this document, the case translation is clear: endpoint-map rows are first-class channel evidence. Store annotation, interface UUID, object UUID, protocol sequence, endpoint string, process owner, and registration lifetime.
3. *DEF CON 32 ALPC/RPC security-abuse framing.* Security metadata is not a side note. A local RPC endpoint that exposes a service-looking method set but accepts a broad local caller population, weak authentication, or unexpected impersonation semantics is a role mismatch even if its method payloads are opaque.
4. *COM local-server abuse pattern.* COM adds registry activation and proxy/stub metadata in front of the same local RPC idea. A cheat can hide discovery in CLSID/AppID registration and traffic in interface calls. The evidence is per-user COM registration, activation timing, local-server image path, interface IID, lower transport, and fixed-size/high-entropy method payloads.

**Detection.** Treat RPC/COM as an inventory problem:

1. Snapshot local RPC endpoints and COM local-server registrations under HKLM and HKCU before protected workload launch.
2. Track endpoint registrations and COM activations during the game session, especially from unsigned helpers or binaries that live outside expected install paths.
3. Validate CLSIDs, AppIDs, interface UUIDs, service names, and image paths against known vendor manifests.
4. Monitor protected-workload-adjacent processes that load COM/RPC runtime libraries and then perform high-frequency local calls to a new or obscure server.
5. Correlate with pipe/ALPC/socket telemetry because RPC often lowers into one of those transports.
6. Store endpoint-map rows: interface UUID, version, annotation, protocol sequence, endpoint string, object UUID, binding vector, registration time, owner process, service name, signer, and whether the endpoint disappears at match end.
7. Store call-shape evidence where available: opnum/method distribution, request and response sizes, HRESULT/exception status, call cadence, timeout/retry pattern, authentication level, impersonation level, and whether the method sequence creates or transfers side objects.
8. Correlate RPC calls with lower transports. `ncalrpc` should produce local IPC/ALPC evidence; `ncacn_np` should produce named-pipe evidence; TCP endpoints should produce socket evidence. A high-level RPC call with no plausible lower transport is a data-quality or evasion finding.
9. For COM, capture CLSID, AppID, LocalServer32/LocalService, TreatAs/AutoConvert-style redirections if present, proxy/stub CLSID, interface IID, elevation/launch permissions, per-user override under HKCU, and activation time. Per-user COM registration during protected workload activity is high-value.
10. Treat security downgrades and permissive policy as evidence. A vendor-looking endpoint using no authentication, accepting broad local callers, or enabling callbacks with no auth needs an owner explanation even if all traffic is local.

The false-positive population is huge: Windows shell, browsers, Office, audio, graphics control panels, launchers, accessibility tools, and EDR all rely on COM/RPC. Novelty plus role mismatch is what matters. A signed GPU control panel exposing a documented COM server is noise; a freshly dropped "audio enhancement" service that registers a COM server only while the protected workload is running and receives fixed-size opaque calls from the protected process is high-value investigation material.

### 2.13 IPC Deep-Dive Matrix: State, Lifetime, and Evidence

IPC namespace techniques are easy to list and hard to operationalize because the same primitive can be benign in one ownership graph and malicious in another. Model each channel as a five-stage state machine:

1. *Advertise.* A process, service, or driver-visible object creates a name, class, atom, window, pipe, port, key, or endpoint.
2. *Discover.* The peer probes the object by name, enumerates a table, resolves a symbolic link, queries the endpoint mapper, or watches a known parent object.
3. *Bind.* The peer opens a handle, connects a client endpoint, joins a job, activates a COM class, or registers for notification.
4. *Exchange.* State moves through bytes, messages, reference counts, handle values, completion-port packets, object metadata, registry values, or side effects.
5. *Retire or rotate.* The object is deleted, renamed, left orphaned, moved to a per-session namespace, or replaced by a new randomized name.

Detectors should store all five stages. A single snapshot answers "what exists now." A channel investigation asks "who advertised it, who discovered it, who bound to it, what changed while the game was live, and did the object disappear when the match ended?"

**Mailslots (§2.1).** Directionality and aging matter. A mailslot is a named message sink; the reader owns the slot, writers open it. For a KM->UM channel, the UM side usually creates the slot and the driver or a privileged broker writes messages. For UM->KM, a second primitive is needed. Detection should therefore track asymmetric pairs: a mailslot reader plus a second section, pipe, registry key, WNF state, or IOCTL path used for replies. Strong evidence is a newly created `\\Device\\Mailslot\\...` object whose owner process is protected-workload-adjacent, whose write cadence begins only after a driver loads, and whose name rotates across sessions while preserving a stable prefix or length pattern. A mailslot without a reply surface is usually a beacon or trigger, not a full control plane.

**ALPC/LPC (§2.2).** ALPC is normal service plumbing, so names alone are weak. The better view is endpoint role, handle topology, side objects, attributes, queues, and cross-view consistency. Capture connection ports, client communication ports, server communication ports, server/client PIDs, handle access, connection count, message queue behavior, message-size distribution, request/reply ratio, timeout/cancel/disconnect cadence, duplicated handle count, section/view correlation, completion-style behavior, security context, and whether the protected process or a suspicious helper owns a connected endpoint. Many legitimate ALPC ports are long-lived and service-owned. A channel-like ALPC port often has these shapes: a per-user helper registering a private port just before protected workload start; an injected module connecting to a helper-owned port but never using a documented service API; a section-view transport where ALPC carries only epochs; a handle shuttle that passes unnamed sections/events/completion ports; an RPC/COM broker that lowers into ALPC; a completion/direct-event path that wakes thread-pool code; or a driver-assisted endpoint insertion where the ALPC handle appears in the protected process without a plausible user-mode parent. Attribute families matter: view/data attributes imply a hidden shared-memory payload, handle attributes imply an unnamed-object broker, context attributes imply a sequence/correlation plane, security/QoS state exposes role mismatch, and completion state exposes wake-source laundering. The suspicious signal is not "ALPC present"; it is a short-lived or role-mismatched endpoint with stable binary cadence, side-object graph, attribute-driven object transfer, and a client/server graph that does not match namespace, ETW, VAD, and handle-table evidence.

**Custom symbolic links (§2.3).** Symbolic links are attractive because they decouple the visible name from the real target. A user-mode component may open `\\??\\VendorCache` while the link resolves to a custom device object, a named pipe, a section, or a per-session object. The defender needs to record both the link name and the resolved target at capture time; storing only the display name loses the evidence. Watch for links created under `\\GLOBAL??`, per-session `\\Sessions\\...\\DosDevices\\...`, and service-like aliases whose target owner is an unsigned or recently loaded driver. Link rotation is also meaningful: if the prefix is stable but the suffix changes every process launch, the randomization is itself part of the channel design.

**Anonymous named objects (§2.4).** This category is about handles more than names. Events, mutexes, semaphores, sections, timers, and completion ports can be unnamed but still shared through inheritance, duplication, broker handoff, or handle-value disclosure through another channel. Detection therefore needs a handle-graph pass, not just `\\BaseNamedObjects` enumeration. For the protected process, record object type, granted access, inheritability, source process, duplication time, and object basic information. A low-noise signal is a high-access handle to a section, event, or completion port that appears in the protected process after a helper starts, especially when the source process lacks a normal launcher/overlay/service relationship.

**Symlink farm rotation (§2.5).** Rotation trades static signature risk for lifecycle evidence. Instead of alerting on any one symlink, build a family fingerprint: target driver, target object type, name length, character set, creation interval, deletion interval, and whether old links remain dangling. Attackers often rotate the outer name but reuse the same target or same security descriptor. A production detector should collapse these into one "rotating namespace family" and score it higher than a single suspicious name because the rotation implies deliberate evasion.

**Hidden windows and message-only windows (§2.6).** The important distinction is GUI ownership. Message-only windows live under a process that must have a UI thread and a window procedure. A covert channel uses registered window messages, properties, `WM_COPYDATA`, timers, or posted messages as a low-volume mailbox. Inventory should map HWND -> owning thread -> owning module -> window class atom -> registered message names -> property names. Suspicion rises when a non-UI helper creates message-only windows, when a protected process receives registered messages from a helper without a normal overlay/service relationship, or when the window class name looks like a system or vendor class but the creating module is unrelated.

**Clipboard custom formats (§2.7).** Clipboard channels are low bandwidth but useful for cross-integrity and cross-process rendezvous because registered formats are shared by name. Track registered format names, owning process at write time, data size, HGLOBAL lifetime, and whether the clipboard is opened by headless helpers during protected workload activity. Normal users do not copy data dozens of times per minute during a ranked match or while a protected enterprise workload is idle. A suspicious pattern is a custom registered format with a vendor-looking name, fixed-size binary HGLOBAL payloads, and a producer/consumer pair that never has foreground focus.

**Global atom table (§2.8).** Atoms are name-to-integer rendezvous points. They are good for small commands, feature flags, sequence numbers encoded in strings, or discovery beacons. The defender should snapshot atom strings before launch and diff during runtime. Interesting features are high-entropy strings, timestamp-like names, repeated add/delete churn, and atoms that match clipboard/window-message names used by the same helper. The atom table becomes much stronger evidence when paired with hidden windows or registered clipboard formats because the same atom ecosystem underlies multiple GUI IPC primitives.

**Registry storage and trigger (§2.9).** Registry-backed channels have two planes: durable storage and callback-triggered signaling. Store the full normalized key path, resolved symbolic-link path, hive, value type, value size, security descriptor, virtualization state, transaction state, and last-write time. For trigger analysis, pair user-mode writes with `CmRegisterCallbackEx` registrations from loaded drivers. A strong package is a write by the game/helper to a key outside the title's configuration scope, immediately followed by activity in a driver that has a registry callback, with the written value showing opcode-like structure or monotonic counters.

**Job object notifications (§2.10).** Job channels are lifecycle and watchdog channels. Microsoft documents that job messages are delivered through an I/O completion port and that some message delivery is notification-grade rather than guaranteed. That makes the primitive poor for data but good for "process entered", "process exited", "limit crossed", and "watchdog heartbeat" signals. Detection should record job membership, nested-job parent chain, limit classes, completion-port handle owner, completion key, and whether non-launcher processes are grouped with the game. A job object that crosses launcher, helper, and game boundaries can be legitimate, but the completion-port owner should be explainable.

**Named pipes (§2.11).** Pipe telemetry needs endpoint pairing. Store server process, client process, pipe name, mode, instance count, security descriptor, remote access allowance, connection time, byte counts, message-size histogram, and disconnect time. Message-type pipes produce packet-shaped telemetry; byte-type pipes require framing inference. A strong channel signature is a pipe whose lifetime is exactly the game session, whose name resembles a trusted vendor namespace but whose binary owner is not that vendor, and whose packet sizes align with memory-read or aim-assist command cadence. Remote-capable ACLs are a separate risk: a local anti-cheat support component should almost never expose a remotely reachable pipe.

**Local RPC and COM (§2.12).** RPC/COM channels must be reduced to interface identity, binding, endpoint, activation, transport, and security. Store CLSID, AppID, LocalServer32/LocalService path, interface UUID/version, opnum/method distribution, endpoint strings, protocol sequence, endpoint-map annotation, service SID, launch command line, apartment model where visible, authentication level, impersonation level, security callback/registration flags where visible, and lower transport if it resolves to ALPC, named pipes, or sockets. An attacker can hide opaque blobs inside NDR method calls or COM method arguments; the defender does not need to decode every method to build evidence. It is enough to show that a new per-user COM local server or local RPC endpoint appears only during protected workload runtime, is called by the protected process or injected module, has fixed-size or high-entropy call payloads, registers a dynamic endpoint or broad local policy, and has no vendor-manifest justification.

---

## 3. System Information and Kernel Reflection Channels

The OS exposes a lot of itself to user mode. Firmware tables, system performance counters, big-pool metadata, kernel-shared data, ETW providers, WNF state, performance counter providers: all of these are *normal* surfaces that *normal* tools query constantly. A cheat that hides command and data inside these queries inherits both the volume of legitimate traffic and the OS's own implementation noise. This section walks the most useful of these surfaces.

### 3.1 Firmware Table Provider Hijacking

Windows lets user mode query firmware-backed data, including ACPI, SMBIOS, and raw firmware tables, through `EnumSystemFirmwareTables`, `GetSystemFirmwareTable`, and the native `NtQuerySystemInformation(SystemFirmwareTableInformation)` path. Internally the kernel maintains a list of firmware-table provider handlers, addressable by a 4-byte provider signature. A driver can register a new provider, replace an expected provider's handler, or simply hook the dispatch in `nt!NtSetSystemInformation` and use ordinary user-mode firmware-table queries as a command-dispatch path.

**Class numbers.** v6 hedged about whether the relevant `SYSTEM_INFORMATION_CLASS` values were 75, 76, or 77; the practical Windows 10/11 answer used by phnt/NtDoc-derived reverse-engineering views is concrete. `SystemFirmwareTableInformation` is the *query* class used with `NtQuerySystemInformation` / `ZwQuerySystemInformation` and is `76` (`0x4C`). `SystemRegisterFirmwareTableInformationHandler` is the *set* class used with `NtSetSystemInformation` / `ZwSetSystemInformation` and is `75` (`0x4B`). The WDK 19041 / 22621 / 26100 headers expose the associated `SYSTEM_FIRMWARE_TABLE_INFORMATION` and `SYSTEM_FIRMWARE_TABLE_HANDLER` structures, but the numeric enum entries are not a broadly documented user-mode ABI. Detectors should record both the numeric class and the decoded purpose, and should build-validate the `nt!NtSetSystemInformation` dispatch path rather than treating a header snapshot as the whole contract.

**Structures.** Two structures matter:

```cpp
typedef NTSTATUS (__cdecl *PFNFTH)(
    IN OUT PSYSTEM_FIRMWARE_TABLE_INFORMATION SystemFirmwareTableInfo);

typedef struct _SYSTEM_FIRMWARE_TABLE_HANDLER
{
    ULONG       ProviderSignature;
    BOOLEAN     Register;
    PFNFTH      FirmwareTableHandler;
    PVOID       DriverObject;
} SYSTEM_FIRMWARE_TABLE_HANDLER;

typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION
{
    ULONG       ProviderSignature;
    SYSTEM_FIRMWARE_TABLE_ACTION Action;
    ULONG       TableID;
    ULONG       TableBufferLength;
    UCHAR       TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION;
```

#### Registered Firmware-Table Provider Command Channel

The documented user-mode view exposes `EnumSystemFirmwareTables` and `GetSystemFirmwareTable`. Microsoft documents the normal provider signatures as `ACPI`, `FIRM`, and `RSMB`; callers pass a 4-byte provider signature and, for table retrieval, a 4-byte table ID. The abuse pattern relies on the private kernel registration path behind `SystemRegisterFirmwareTableInformationHandler`: a driver registers a new provider handler, then user mode queries that provider through the ordinary firmware-table API or through the native `SystemFirmwareTableInformation` path.

The registration side is the part that often gets missed. A driver does not need to patch `GetSystemFirmwareTable`, create a device object, or hook `NtQuerySystemInformation`. It can call `ZwSetSystemInformation` with the set class `SystemRegisterFirmwareTableInformationHandler` and pass a `SYSTEM_FIRMWARE_TABLE_HANDLER`-shaped registration record:

```text
SystemInformationClass = SystemRegisterFirmwareTableInformationHandler
SystemInformation      = SYSTEM_FIRMWARE_TABLE_HANDLER
    ProviderSignature  = attacker-chosen 4-byte provider namespace
    Register           = TRUE for registration, FALSE for removal
    FirmwareTableHandler = kernel callback that serves enum/query requests
    DriverObject       = owner-looking driver object
```

That makes the surface look like a normal firmware-table provider rather than a hook. The handler can be packaged inside the attacker driver, hidden behind a BYOVD-loaded component, or placed in a driver whose service name and signer are chosen to look like OEM platform support. From a shallow inspection view, the driver is "just registering a firmware table handler"; the command channel only appears later when the user-mode control module queries the provider.

**DriverObject-as-key weakness.** The `DriverObject` field is easy to overinterpret. In current Windows 10/11 observations, the registration path does not make `DriverObject` a strong proof that the handler belongs to a legitimate, live driver stack. The value is used internally more like an owner key for provider registration/removal and association than like a complete trust anchor. That means a registration can be made with a borrowed, stale-looking, spoofed, or otherwise non-authoritative `DriverObject` value even when the real communication logic lives in a different handler target.

This is one reason attackers like this surface: a shallow detector may log "firmware provider owned by driver object X" and stop there, while the actual handler pointer, provider signature, query cadence, and caller population tell a different story. A production detector must therefore treat the supplied `DriverObject` as attacker-controlled metadata until it has been independently validated. The handler pointer and its first-hop/chain target are the evidence; the `DriverObject` is only a claimed owner.

This behavior should also be version-guarded. Future Windows kernels may harden the registration path by validating that the supplied value is a real `DRIVER_OBJECT`, checking object type and reference state, enforcing image/handler ownership, restricting replacement/removal semantics, or changing how providers are keyed. Do not design either offensive assumptions or defensive parsers as if this weak owner-key behavior is a permanent ABI contract.

#### Attacker Mechanics: Firmware Query as Mini RPC

A firmware-table provider works like a small RPC endpoint hidden behind hardware-inventory vocabulary. The provider signature is the service name, `EnumSystemFirmwareTables` is discovery, `GetSystemFirmwareTable` is the request, the table ID is the method selector, the requested size is a negotiation field, and the returned blob is the reply. Nothing in that model requires a user-openable device object or a custom IOCTL path.

The registration phase gives the kernel component a durable advertised endpoint. The user-mode helper does not need to know where the handler lives; it only needs the four-byte provider signature and a convention for table IDs. A shallow user-mode trace then sees a normal process asking Windows for firmware data. The important attacker benefit is *semantic borrowing*: the call stack, API name, and object category all say "platform inventory," while the handler's private interpretation says "command bus."

The command grammar is compact but expressive:

1. *Provider signature as namespace.* A private signature selects the cheat channel and can be rotated per build, per customer, or per launch. Vendor-looking signatures reduce visual suspicion but increase the risk of collision with real platform tooling.
2. *Enumeration as handshake.* The enumerate action can return a synthetic list of table IDs that doubles as a capability mask, build compatibility indicator, or session nonce.
3. *Table ID as opcode.* A 32-bit ID is enough to encode command family, direction, feature flags, and a small sequence number. Attackers often prefer printable or firmware-looking values because they survive poor logging better than random integers.
4. *Buffer length as side channel.* The normal two-call "ask size, allocate buffer, ask again" pattern gives a request/response rhythm. A handler can vary required size, returned size, or status to encode readiness, error class, or result length.
5. *Output table as reply buffer.* The table blob can carry a fixed response header followed by encrypted or compressed bytes. For larger uploads from UM to KM, firmware queries usually become the trigger and reply path while a section, registry value, WNF state, or MDL-backed buffer carries the input payload.

The mature lifecycle is therefore: register the provider, wait for a protected-workload-adjacent helper to enumerate it, negotiate protocol version through table IDs and size probes, serve short request/reply commands during runtime, and unregister or swap the handler during teardown. The `DriverObject` value is useful camouflage because it can make provider ownership look local to a benign driver, but it is not the trust boundary. Handler provenance, registration timing, and query cadence are what reveal the channel.

The end-to-end flow is:

```text
KM setup:
    driver calls ZwSetSystemInformation(class 75, SYSTEM_FIRMWARE_TABLE_HANDLER)
        |
        v
    kernel adds / updates provider-signature -> handler mapping

UM command:
    EnumSystemFirmwareTables(provider)
    GetSystemFirmwareTable(provider, tableId, buffer, size)
        |
        v
KM callback:
    FirmwareTableHandler receives SYSTEM_FIRMWARE_TABLE_INFORMATION
    handler decodes TableID / Action / TableBufferLength / cadence
    handler writes reply bytes into TableBuffer
```

**Why this is a good disguise.** It is not an inline hook and it does not require a suspicious dispatch table patch. It uses a real kernel registration path and then a real user-mode firmware API. Many defenders baseline device objects, IOCTLs, ALPC ports, sections, and callbacks before they baseline firmware-table provider registrations. Even if a detector sees the later `GetSystemFirmwareTable` calls, the calls look like inventory behavior unless the detector also knows which provider signatures are expected on that machine.

**Registration evidence.** A production detector should capture the registration event, not only the later query:

1. Class `75` `NtSetSystemInformation` / `ZwSetSystemInformation` attempts, including caller module, previous mode where available, call stack, input size, provider signature, `Register` flag, handler pointer, and the supplied `DriverObject` value.
2. Provider signature deltas: new provider after boot, provider removed near anti-cheat shutdown, provider re-registered with a different handler, or provider using a vendor-looking four-character value with no OEM/platform provenance.
3. Handler pointer provenance: exact image, section, symbol/function-entry classification, chain walk, signer, load time, and whether the handler belongs to the same driver object supplied in the registration record.
4. Driver-object plausibility: whether the supplied value is a valid live `DRIVER_OBJECT` on this build, service name, device stack, INF/install record, signer chain, load order, and whether the claimed owner has any real firmware/platform role. A plausible-looking driver object is corroboration, not proof of ownership.
5. Registration-to-query correlation: a provider registered by a protected-runtime or role-mismatched driver and then queried only by the protected process/helper is far stronger than a provider that OEM tooling queries across normal desktop activity.

The resulting channel has a clean request/reply shape:

1. *Provider signature as channel ID.* The registered `ProviderSignature` is the namespace. A cheat usually chooses a vendor-looking 4-byte value rather than `ACPI`, `FIRM`, or `RSMB`, because colliding with real firmware providers is fragile.
2. *Table ID as opcode or selector.* `FirmwareTableID` is naturally a 32-bit selector. For ACPI, Microsoft documents that table signatures are passed little-endian; a covert provider can reuse that convention to make values look like table names.
3. *Action as enumerate-vs-query phase.* Enumeration can be used as discovery or handshake: user mode first asks which table IDs exist, then queries one of them. The query phase returns the actual reply bytes.
4. *Buffer length as negotiation.* `GetSystemFirmwareTable` supports the normal two-call pattern where a NULL or undersized output buffer returns the required size. A covert provider can use the size returned from the first call as an epoch, capability mask, or response-length negotiation.
5. *Output buffer as KM->UM payload.* The handler fills `TableBuffer` with arbitrary bytes from the driver's perspective. To a user-mode caller, it is simply a firmware table blob.

This gives KM->UM a natural data path and UM->KM a compact command path (`ProviderSignature`, `TableID`, requested buffer length, and call cadence). Larger UM->KM payloads usually require a companion channel such as registry, section, WNF, or a prior shared-memory rendezvous; firmware-table queries are best at request/response, not bulk upload.

**Operational profile.** The channel is stealthy because the user-mode API is common in inventory tools, anti-malware, virtualization utilities, OEM support agents, and hardware profilers. There is no device object to open, no IOCTL code to classify, and no custom pipe or ALPC port. The suspicious part is not a firmware query by itself. The suspicious part is a protected-workload-adjacent process querying an obscure provider signature with a repeated opcode-like table ID sequence shortly after an unknown driver registers a handler.

**Detection.** Treat firmware-table providers as a callback inventory:

1. Baseline provider signatures and handler pointers after boot and before protected workload launch. `ACPI`, `FIRM`, and `RSMB` are expected; additional providers need owner attribution.
2. Validate every handler pointer against loaded image ranges and expected firmware/platform modules. Do not trust the supplied `DriverObject` as the owner until object validity and image/handler relationship are independently confirmed. A provider handler inside an unknown role-mismatched driver is high signal even if the registration record names a plausible driver object.
3. Capture query telemetry: caller PID, provider signature, table ID, requested length, returned length, status, and call cadence. A two-call size probe followed by a fixed-size opaque response is normal for legitimate firmware reads, but repeated probes against a private provider during protected workload runtime are not.
4. Parse returned blobs enough to distinguish firmware-shaped data from command-shaped data. ACPI tables have headers and checksums; SMBIOS has a well-known raw format; a high-entropy 64-byte response under a fake provider is not firmware.
5. Correlate with driver load, BYOVD activity, system-information hooks, and other rendezvous artifacts. Provider registration plus game-process firmware queries plus a shared section or registry type trigger is a strong evidence package.

False positives come from OEM and virtualization stacks that may expose unusual firmware or platform data. The difference is provenance: legitimate providers have an install record, signer, platform role, and stable query population outside the game session. A provider that exists only after a suspicious driver loads, and only the game/helper queries it, should be treated as a covert channel candidate.

### 3.2 SystemFirmwareTable Handler Inline Hook

A close variant of §3.1: rather than registering a new provider, the cheat patches an existing legitimate firmware-table handler (a SMBIOS or ACPI handler) and forwards all but the magic requests. The UM side continues to call the standard firmware-table API, with a magic provider signature, table ID, or buffer pattern in the request.

The trade-off versus §3.1 is the usual one. Provider registration is a clean data-side modification visible to a provider-list inventory but not to code-integrity checks. Inline hooking is harder to enumerate from the provider list because the provider entry still looks normal, but it is detectable by code-integrity checks against the handler's prologue and is more likely to collide with PatchGuard or HVCI.

The hook can live at several depths:

1. *Entry prologue patch.* The handler entry branches to a wrapper, the wrapper checks `ProviderSignature`, `FirmwareTableID`, requested length, or caller process, and all non-magic requests are forwarded.
2. *Interior branch patch.* The entry bytes remain clean, but a later conditional branch or helper call is redirected. This defeats simple first-16-byte hashing.
3. *Data-side handler pointer swap.* The provider entry is left in place but its handler pointer is replaced with a trampoline in another trusted-looking module. This is closer to §3.1's registration inventory problem than a pure code hook.
4. *Table-data tamper.* The real handler runs, but the returned SMBIOS/ACPI blob is patched after generation. This leaves code clean but makes returned firmware data inconsistent.

The covert protocol is the same in all variants: UM sends a normal firmware query and hides its selector in provider signature, table ID, buffer length, or query cadence. KM decides whether the request is magic. If not magic, it forwards to the original handler. If magic, it returns command data, a descriptor for another channel, or a status code used as a one-bit reply.

**Detection.** Validate the code bytes and short control-flow chains of known firmware-table handlers against the on-disk image (handler entry points should reside in `ntoskrnl`, `WmiAcpi`, or platform firmware support modules). Monitor high-frequency firmware-table queries from the protected process. The correlation that closes the case is "handler bytes differ from clean image" plus "protected process queries this provider with command-like framing".

### 3.3 NtQuerySystemInformation Return-Value Manipulation

`NtQuerySystemInformation` returns dozens of structures with reserved fields, alignment padding, tag bytes, counters, and address-like metadata. A kernel component can intercept the path or modify the underlying data so that selected fields on selected classes carry command material. The signal-to-noise is favorable: these classes are queried by every system inventory tool, every launcher, every anti-cheat, and every EDR.

Abusable classes (from the v5/v6 catalog, confirmed against current builds):

- `SystemPerformanceInformation` (`0x02`): spare and reserved fields in `SYSTEM_PERFORMANCE_INFORMATION`.
- `SystemProcessInformation` (`0x05`): reserved fields inside `SYSTEM_PROCESS_INFORMATION`.
- `SystemPoolTagInformation` (`0x16`): 4-byte pool tags as direct payload.
- `SystemExtendedHandleInformation` (`0x40`): reserved or layout-dependent fields.
- `SystemBigPoolInformation` (`0x42`): tag and address metadata, expanded in §3.4.

The trick is choice of class. `SystemProcessInformation` and `SystemPerformanceInformation` are queried by everything; `SystemBigPoolInformation` is queried by far fewer tools and is therefore a louder positive signal if it appears in the protected process.

**Detection.** Three independent checks:

- *Direct hook integrity* on `nt!NtQuerySystemInformation` and its inner class dispatchers. A hook here is rare in legitimate software outside instrumentation tools and EDR.
- *Return-buffer consistency* against an independent kernel view. Compare returned `SYSTEM_PROCESS_INFORMATION` against `PsLookupProcessByProcessId` for each PID; mismatches in reserved fields are a direct signal.
- *Value plausibility*. Reserved fields should be zero in current build encodings; non-zero values, especially ones with high entropy or game-specific magic constants, are the channel payload.

False positives come from inventory tools that legitimately query these classes; the suspicious case is *manipulated data*, not API use.

### 3.4 SystemBigPoolInformation Metadata Channel

A specific application of §3.3 worth its own subsection. A driver allocates Big Pool memory with a distinctive tag (`XCHT`, `DvSc`, anything four bytes) and user mode calls `NtQuerySystemInformation(SystemBigPoolInformation)` to enumerate Big Pool allocations. The tag acts as a lookup key; the returned address-like metadata describes the rendezvous structure.

This is most commonly used to *announce* the endpoint of another channel ("here is the section", "here is the descriptor", "this is the current epoch") rather than to carry payload directly. The Big Pool table is large and noisy enough that a four-byte tag hides easily, but the channel can still encode more than the tag:

- *Tag as family ID.* Four bytes identify the cheat family, driver role, or current protocol generation.
- *Size as selector.* Allocation size can encode a small command or capability mask if rounded to plausible buffer sizes.
- *Presence as state.* Allocation exists = ready; allocation missing = sleep; allocation count = epoch.
- *Churn as clock.* Allocate/free cycles give UM a low-frequency timing signal without a handle.
- *Address-like metadata as descriptor.* Even when addresses are masked or canonicalized, relative changes can identify which allocation is current.

The most robust designs use Big Pool only for rendezvous. Once UM discovers the tag and size, it switches to a section, GPU resource, firmware-table provider, registry trigger, or driver dispatch path for actual payload transfer. This keeps Big Pool query frequency low and avoids pushing high-entropy data into a system-information buffer where defenders can diff it.

**Detection.** Baseline pool tags created by known drivers before protected workload launch. Alert on Big Pool entries with product-specific, random, or vendor-mimicking tags that did not exist in the baseline. Record tag, size, paged/nonpaged class, first-seen time, last-seen time, allocation count, apparent address range, and owning module evidence where available. Validate whether returned addresses map to allocation ranges owned by a known driver. Pool tags are short, so attribution by tag alone is weak; attribution by *owning module's allocation range plus tag plus allocation timing* is strong. A new tag that appears only when the helper runs and whose size changes like a command selector is much higher confidence than a static vendor-driver pool tag.

### 3.5 Windows Notification Facility (WNF)

WNF is a kernel-backed publish-subscribe state notification system. Components publish state changes; subscribers receive notifications without polling. It is used heavily inside Windows itself, including shell, networking, power, Store, and accessibility paths, and remains *the* hardest covert IPC surface for traditional anti-cheat to inventory because subscriptions and publishers do not live in the object namespace the same way named objects do.

The cheat can publish a state name and have UM subscribe, or it can subscribe to a state name and have the UM side publish, or it can use the *presence* and *version increments* of a state as a one-bit signal.

The Black Hat USA 2018 WNF research is the reason this surface deserves more than a footnote. WNF is not just "a notification bit." It is a kernel-backed state system with producer/consumer relationships, payload storage, security descriptors, per-state lifetime, and kernel/user boundary crossing. A published state can carry a payload up to the WNF implementation's small-blob limit, can be read by consumers after publication, and may be permanent depending on the state configuration. That gives attackers three useful dimensions: notification as trigger, state version as sequence number, and payload bytes as data.

**Presented case note.** The Black Hat WNF presentation explicitly framed WNF as a generalized internal communication, coordination, synchronization, and notification framework across user/kernel boundaries. The direct translation for this document is: treat a WNF state as a small named mailbox with access policy and versioning, not as a mere event. The communication fields are state name, scope/lifetime, security descriptor, subscriber identity, publisher identity, version counter, payload length, and payload shape. A cheat can use WNF only for wakeup, only for storage, or as a complete low-bandwidth mailbox.

The channel shapes are:

1. *Volatile state mailbox.* UM publishes a private state name; KM or another UM component subscribes and treats updates as commands. The state version is the epoch, and the payload is the command body.
2. *Kernel-consumer trigger.* KM registers or already owns a consumer path for a state name. UM publication wakes the kernel-side consumer without opening a custom device object.
3. *Persistent state rendezvous.* A permanent state stores configuration or rendezvous data across restarts. A cheat can use this as "last known section generation", "provider signature", or "arm/disarm" state.
4. *System-state mimicry.* The cheat chooses a name family that looks like shell, Store, power, network, or feature-management state. Windows feature flags and internal coordination already use WNF heavily, so defenders who baseline only object names miss it.
5. *Payload parser abuse.* Some legitimate consumers parse WNF payloads as structured data. For anti-cheat, the useful lesson is not to fuzz Windows consumers; it is to recognize that a 4 KB-ish opaque blob inside WNF can be a real payload, not just a notification.

**Obfuscation.** WNF state names are encoded rather than stored as obvious plain strings. Public reversing has documented XOR-style decoding with the historical key `0x41C64E6DA3BC0074` on older Windows 10 builds, but this is private implementation detail, not a stable contract. When parsing WNF subscription tables or published state inventories from kernel memory, use a build-validated decoder before string-matching against documented Windows state names. A defender that treats encoded state names as raw values will classify legitimate Windows states as "random" and bury the cheat in false positives.

**EDR visibility correction.** v6 claimed almost all EDR products are blind to WNF. That claim was already overstated when v6 shipped, and is more so now. Microsoft Defender for Endpoint and several commercial EDR products consume *some* WNF telemetry, typically for known Windows state names that are relevant to the security model. Arbitrary user-created state names remain the genuinely under-covered surface: that is where modern cheats hide.

**Detection.** Enumerate WNF subscriptions associated with the protected process when possible (the table is reachable through a kernel walker; documented APIs do not expose it). Look for random-looking state names, state names created around suspect driver load time, high-frequency state changes that do not match any documented Windows component, suspicious security descriptors, persistent states with protected-workload-coupled updates, and payload-size distributions that look like fixed command records. Correlate WNF activity with suspect driver load events and with a side channel such as a section, ALPC port, registry trigger, or firmware-table provider. Shell, network state, power state, Store, and feature-management components are the dominant legitimate signal; the discriminator is "state name not in the de-XOR'd inventory of known Windows names" plus "the publisher or subscriber is unsigned or protected-workload-adjacent".

### 3.6 KUSER_SHARED_DATA Field Manipulation

`KUSER_SHARED_DATA` is mapped read-only into user mode at `0x7FFE0000` (x64 and x86 alike) and is mapped writable in kernel mode at the system shared-data address. It carries time, version, mitigation, processor, and system state used by user-mode paths that want to avoid syscall overhead. Some fields are *spare* or *reserved* across builds and are not consistency-checked by anything observable to user mode.

A driver writes a selected field; user mode reads the shared page at `0x7FFE0000 + offset`. No object, no handle, no socket, no section. The user-mode read is an ordinary memory access that is indistinguishable from `KUSER_SHARED_DATA::SystemTime` polling.

**Limits.** Bandwidth is low and the surface is brittle. Microsoft can repurpose any field across builds, and any field that is consistency-checked by another OS path (tick count, version) will misbehave or trip diagnostics if written by something other than the OS. The viable write fields are a small subset that has historically remained spare.

The viable command shapes are tiny:

1. *One-bit gate.* A reserved field flips between zero and non-zero to tell UM whether another channel is armed.
2. *Epoch counter.* A small field increments when KM has updated a mailbox elsewhere.
3. *Selector nibble.* A few low bits select which provider, section, atom, or registry opcode UM should query next.
4. *Timing distortion.* The attacker perturbs a field that user mode reads often enough to create an observable cadence.

The attacker must avoid fields with strong invariants: time must be monotonic, build numbers must match the kernel, mitigation fields must agree with policy, and processor topology must agree with CPUID and scheduler state. That makes the usable field set build-specific and narrow.

**Detection.** Baseline fields that should remain stable on a given build. Monitor reserved or spare fields for non-zero or high-entropy values. Cross-check semantic fields against independent sources: time against system calls / ETW timestamps, processor data against CPUID and `KeQueryActiveProcessorCountEx`, mitigation state against process/system policy, and build data against loaded kernel image. Where instrumentation permits, detect kernel-mode writes to the shared-data page from anything other than `ntoskrnl`. Treat this as supporting evidence, not a standalone verdict, because Microsoft owns the field semantics and may change them between builds in ways that look identical to a covert channel to a naive scanner.

### 3.7 ETW Provider and Session Abuse

ETW is designed for high-throughput event delivery. The documented model is provider→session→consumer: user-mode and kernel-mode components register as providers, controllers configure sessions, and consumers receive events in real time or from trace files. That makes ETW a natural KM→UM or UM→UM data channel. It is not, by itself, a clean documented UM→KM command channel unless the driver is abusing an enable/control callback, hooking ETW internals, or using a separate kernel-observable trigger. Many defender pipelines consume ETW but few inspect every private provider, and the volume per-session is high enough that a cheat's payload can hide in the legitimate noise.

The trade-off versus other channels is bandwidth-for-attribution: ETW supports very high volume but requires the provider GUID, session name, provider owner, controller process, and event payload to be inspected for the cheat to be identified. If the defender does not pull provider GUIDs and session ownership from private sessions, the channel is easy to miss.

Abuse patterns split by direction:

1. *KM provider -> UM consumer.* The attacker driver registers or reuses a provider and emits events whose payloads are command replies or memory snapshots.
2. *UM provider -> UM/KM-aware helper.* A UM helper emits events to a private session; another process consumes them, while KM is triggered through a second path.
3. *Enable-callback trigger.* A controller enabling or disabling a provider causes a kernel provider callback to fire. The enable parameters, keywords, levels, and enable/disable cadence become the command selector.
4. *Trace-file persistence.* Events are written to an ETL file or private trace file that another component reads later, turning ETW into a durable queue rather than a live stream.

The stealth comes from role confusion. Security products, game engines, GPU profilers, crash reporters, and launchers all create sessions and providers. A cheat can name its session like telemetry, choose a vendor-like GUID, and emit plausible event sizes. The defender must therefore inventory controller/consumer/provider relationships, not just session names.

**Detection.** Inventory active ETW sessions during protected workload runtime. Store session name, logger mode, controller PID, consumer PID, provider GUIDs, provider image, keywords, level, stackwalk flags, buffer size, dropped-event count, private-vs-system session, and file destination. Watch for private sessions owned by untrusted processes, providers created or activated near suspect driver load, enable callbacks on suspicious providers, and event payloads with command-like fixed framing or high entropy. Performance tools, GPU profilers, crash reporters, anti-cheat, anti-malware, and engines all use ETW; the discriminator is "unknown provider GUID plus untrusted session owner plus suspiciously regular emission" and correlation with another channel.

### 3.8 PcwRegister Performance Counter Channel

`PcwRegister` registers a kernel-side performance counter provider. User mode reads counters through normal performance-query paths; the values returned are whatever the provider chooses to publish. A cheat can encode low-bandwidth state in counter values and have UM read it as if it were ordinary system telemetry.

This is a slow surface; performance counter queries are not high-frequency. It is still a *legitimate metric channel*, which makes attribution difficult. Anti-malware and hardware-monitoring tools query performance counters constantly.

A provider can expose countersets, instances, and fields. That gives the attacker several selectors: counterset GUID as family ID, instance name as endpoint name, field index as opcode, and counter value as reply. Values can be cumulative counters, raw values, rates, timestamps, or opaque-looking integers depending on how the provider defines them. The UM side can read through ordinary performance APIs or through tools that already know how to enumerate countersets.

The practical channel is low-frequency control state: enable flag, current epoch, target process ID, shared-section generation, last scan result, or license status. It is not appropriate for large payloads. A cheat that needs bulk data uses PCW as discovery and another channel as payload.

**Detection.** Inventory kernel performance counter providers, including those registered post-boot. Validate provider names, GUIDs, owner driver, manifests, counterset definitions, instance names, and registration timing. Record which process queries the counter and how often. Game-runtime-only providers from unknown drivers are the signal; established hardware-monitoring providers from known vendors are noise. Counter values that look like random 64-bit words, fixed-size command epochs, or process IDs unrelated to the provider's claimed metric role should be reviewed.

### 3.9 Process Mitigation Policy as Storage

Process mitigation policy structures contain reserved or weakly validated bit fields. The documented user-mode API is `SetProcessMitigationPolicy` / `GetProcessMitigationPolicy` with `PROCESS_MITIGATION_POLICY` values such as `ProcessDEPPolicy`, `ProcessPayloadRestrictionPolicy`, and `ProcessSideChannelIsolationPolicy`. A kernel component that wants to modify another process would have to use the native process-information path or write the backing process state directly; `SetProcessMitigationPolicy` only sets the calling process. Both sides can read the resulting policy bits, but using them as storage is brittle because unsupported or write-once policy bits can be rejected or become security-significant across builds.

The exact carrying capacity depends on the structure sizes (which v6 had wrong and v7 corrects):

```cpp
// PROCESS_MITIGATION_DEP_POLICY                    is 8 bytes
//   (DWORD Flags + BOOLEAN Permanent, with natural alignment padding).
// PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY    is 4 bytes
//   (single DWORD Flags union).
// PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY is 4 bytes
//   (single DWORD Flags union).
```

The reserved-bit surface for storage is the union bitfields of the 4-byte policies and the `BOOLEAN Permanent` tail of the 8-byte DEP policy.

**Detection.** Baseline the expected mitigation policy values for the game and its launchers. Alert on non-standard reserved bits, and watch for repeated set/query loops against mitigation classes. Anti-exploit tools, browsers, and anti-cheat may set mitigation policies, but the *cadence* of set/query loops against the *same* policy on the *same* process is rare in legitimate software.

### 3.10 Reflection Deep-Dive Matrix: Query Surfaces as Protocols

System-reflection channels are attractive because they invert the usual detector mindset. The user-mode side appears to be asking Windows ordinary questions: "what firmware table exists?", "what big pool allocations exist?", "what WNF state changed?", "what counters are available?" The covert protocol is hidden in the answer, in the side effects of asking, or in the kernel callback that the question triggers. Treat every technique in this section as a protocol with four fields: selector, caller identity, returned buffer, and kernel-side producer.

**Firmware provider hijack (§3.1) and inline handler hooks (§3.2).** The selector is the provider signature and table ID. The user-mode caller uses documented firmware-table APIs or the native system-information class; the kernel-side producer is either a legitimate firmware provider, a handler registered through `NtSetSystemInformation` / `ZwSetSystemInformation` class 75, or a hook on the registration/query path. A detailed detector should capture set-class registration attempts, provider signatures, handler pointers, supplied driver-object values, table IDs, enumerate-vs-query action, requested length, returned length, first bytes of returned data, caller process, and call frequency. The most useful anomaly is semantic mismatch: a provider signature that is not expected on the platform, a class-75 registration from a driver with no firmware role, a table ID that returns high-entropy non-firmware data, a size-probe pattern whose returned length behaves like a command epoch, a handler pointer / dispatch target outside a Microsoft/OEM firmware-driver image, or a claimed `DriverObject` whose validated owner does not match the handler. Do not rely only on class numbers or the registration record's owner field; validate the provider list and the code pointer chain that services the query.

**`NtQuerySystemInformation` manipulation (§3.3).** This is not one technique but a family. A driver can modify returned records for process, module, handle, pool, firmware, performance, or code-integrity classes; it can also use rare classes as a command demux. The defender should baseline returned structure invariants rather than simply compare byte arrays. Examples: list entry counts must match buffer length; kernel module ranges must map to loaded images; handle counts must be plausible against per-process handle snapshots; pool tags should have stable allocation-type relationships; firmware-table data should parse as the claimed table. Cross-view comparison is the key: if user mode sees one process/module/handle view while a kernel walker, ETW, or hypervisor view sees another, the channel or hide path becomes visible.

**Big-pool metadata (§3.4).** `SystemBigPoolInformation` is interesting because it leaks allocator metadata at scale. A cheat can use tag, size, allocation churn, or presence/absence as a mailbox. The channel is not the pool content; it is the allocation shape. For each sample, record tag, size, nonpaged/paged state, address redaction behavior, count, and first-seen/last-seen time. A suspicious pattern is a private tag whose allocation size encodes small commands, appears only when a helper process is alive, or changes in lockstep with game-state queries. False positives include drivers that allocate telemetry buffers, GPU stacks, network filters, and EDR. Score only when the tag owner and lifetime are unexplained.

**WNF (§3.5).** WNF has publication/subscription semantics, persistent and volatile state names, security descriptors, and private encoded state-name representation. For channel analysis, decode the state-name family where possible with a build-validated decoder, but also treat unknown state names as first-class objects. Store state name, lifetime, scope, creator, subscriber processes, payload size, update count, and subscription callback owner. The high-signal case is a private state name updated by a workload-adjacent helper and consumed by another related process, especially if the payload is fixed-size and high entropy. WNF alone is hard to block because Windows uses it heavily; it becomes powerful evidence when it is the trigger for a second channel such as section data or pipe traffic.

**`KUSER_SHARED_DATA` (§3.6).** This page is normally read-only to user mode and maintained by the kernel. It is not a practical high-bandwidth mailbox, but attackers may use time fields, feature flags, or tick-derived side effects as a low-bit signal if they already have kernel control. The defender should treat direct modification as an integrity issue, not just a covert-channel issue. Validate that fields with well-known semantics remain monotonic and consistent with independent time sources, CPU feature data, and kernel exports. Because some values naturally change at high frequency, the signal must be invariant violation or cross-view disagreement, not ordinary movement.

**ETW provider/session abuse (§3.7).** ETW can hide data in provider names, private provider payloads, enable callbacks, event fields, or session configuration. The important correction is direction: ETW is naturally provider -> session -> consumer, not a clean UM->KM command path unless the driver abuses enable/control callbacks or another trigger. Detection should inventory private providers, manifests, provider GUIDs, enabled keywords, controller process, consumer process, session flags, buffer size, and event rate. Look for providers created by workload-adjacent helpers with no manifest, sessions started only during protected workload runtime, high-entropy event payloads, and enable/disable flips that correlate with kernel behavior. The false-positive boundary is wide because EDR and performance tools use ETW constantly; focus on ownership and correlation.

**PCW performance counters (§3.8).** PCW turns kernel-maintained structures into queryable performance data. That makes it a subtle KM->UM channel: the UM side reads a counterset while the KM side updates fields. Detection should collect provider identity, counterset GUID, manifest path, application identity, instance names, field sizes, update cadence, and consumers. Suspicious cases include a kernel-mode provider with a vendor-like name but no installed manifest provenance, counters whose values look like sequence numbers or encrypted words rather than measurements, and provider instances that exist only while an unknown helper is present. PCW is not common for ordinary games or most endpoint utilities; a workload-adjacent kernel driver exposing custom counters deserves review.

**Process mitigation policy as storage (§3.9).** Mitigation policy structures are not a general communication bus, but they are compact, queryable state with plausible security-tool cover. Abuse usually encodes bits in seldom-used policy fields or uses repeated set/query cycles as a presence check. Detection should record which process changes policy, which policy class is changed, whether the change is legal for the process lifetime, and whether the resulting policy is coherent. For example, a browser enabling exploit mitigations at startup is normal; a game helper toggling a payload-restriction field every frame is not. Treat this as corroborating evidence, not a standalone ban reason.

---

## 4. Documented KM-UM Mediation Surfaces

The surfaces in §2 and §3 reuse OS primitives that were never intended as a driver's primary IPC. The surfaces in this section are the *official or contract-adjacent* KM-UM paths Microsoft documents and supports: Filter Manager communication ports, device-interface GUIDs, WMI providers, Winsock Kernel, WFP callouts, virtual HID / VHF, keyboard and mouse class-filter callback paths, eBPF-style maps, user-mode file-system provider callbacks, and the NLS file-section trick. Cheats favor them because the surface is legitimate by construction. Enterprise security, input, network, accessibility, cloud-file, source-control, and OEM products use one or more of them, so the question is never "should this exist" but "is *this particular* driver entitled to it."

### 4.1 Filter Manager Communication Ports

A file-system minifilter creates a communication port via `FltCreateCommunicationPort`. User mode connects through `FilterConnectCommunicationPort` and exchanges structured messages. Filter Manager handles serialization, security, and message-buffer lifetime: the driver gets a clean message API without having to ship its own IRP-level IPC.

The cheat plays the role of a minifilter without any plausible file-system function. The driver may register a callback for a frequently fired operation (open, create, query) so the surface looks busy, or it may register only the port and treat the port itself as the only artifact. In either case, the *appearance* is "I am a file-security or backup or monitoring component", which matches the population of legitimate filter drivers exactly.

The channel has two planes. The registration plane is the minifilter: filter name, altitude, instance attachment, operation callbacks, and communication port name/security descriptor. The data plane is the client connection: `FilterConnectCommunicationPort`, message buffers, replies, timeouts, and disconnects. A cheat can make the registration plane look plausible while the data plane is the real command bus. Common protocol shapes include fixed-size request/reply records, one-way heartbeat messages, and a section descriptor passed once over the port followed by shared-memory payload transfer.

Altitude matters. A file-security product at an expected altitude with matching service/INF/product footprint is normal. A driver choosing a security-like altitude but registering no meaningful file operation callbacks, or registering only a port with a vague name, is role-mismatched. Some cheats use an old or stolen signed minifilter shell precisely because defenders trust the "minifilter" category too broadly.

**Detection.** Enumerate loaded minifilters and their altitudes through supported Filter Manager surfaces (`FltEnumerateFilters` from kernel mode, or the user-mode Filter Manager APIs / `fltmc`-style inventory from a service). Check communication port names and their security descriptors. Validate the driver's signer and altitude against expected vendor roles: anti-malware, backup, encryption, DLP, and anti-cheat are the legitimate population. A signed driver with no obvious file-system role that creates a port and sees connections from the protected process or an unknown helper is the high-confidence pattern.

False positives are real and product-specific. Role matters: the driver should have a documented file-system function consistent with its altitude. A driver at altitude 360000 ("security" range) with no callbacks registered, no on-disk files corresponding to vendor product, and a single named communication port is suspicious regardless of signer.

### 4.2 IoRegisterDeviceInterface Custom GUID

A driver can register a device interface with `IoRegisterDeviceInterface` using a custom GUID, then expose it to user mode by enabling the returned symbolic-link name with `IoSetDeviceInterfaceState`. User mode discovers the enabled interface through SetupAPI (`SetupDiGetClassDevs`, `SetupDiEnumDeviceInterfaces`, `SetupDiGetDeviceInterfaceDetail`) and opens the resulting device path with `CreateFile`. This is still a device channel, but it is hidden behind interface discovery rather than a hand-written symbolic link, and the GUID can be chosen to resemble a vendor or OEM device class.

The advantage over a custom symbolic link (§2.3) is that interface discovery is a normal Windows pattern for HID, virtual audio, RGB, and storage drivers. The user-mode side does not need a hard-coded device path: it can scan for the GUID and locate the interface dynamically.

The stealth comes from PnP legitimacy. Device interfaces are supposed to be symbolic links, and user mode is supposed to discover them dynamically. An attacker can choose a class GUID that looks like a peripheral, sensor, RGB controller, anti-cheat helper, or vendor telemetry component. It can also keep the interface registered but disabled until protected-session runtime, then enable it only long enough for the helper to discover and open it, or expose multiple reference strings under one class GUID to encode generations. The actual payload still usually travels through `CreateFile` plus read/write/IOCTL on the returned path; the interface GUID hides how the path is found.

**Detection.** Enumerate device interfaces created after boot and around protected workload launch. Store class GUID, symbolic link, reference string, enabled state, parent PDO/FDO stack, service name, INF, hardware IDs, compatible IDs, container ID, signer, and opening process. Validate class GUIDs, the device stack ownership, and the driver signer. Compare interface names against known hardware inventory. A high-confidence pattern is "GUID belongs to no recognized vendor or class" plus "driver exposes user-openable interface to the protected process or helper" plus "no plausible hardware role for this driver". Legitimate populations are peripheral, RGB, virtual audio, virtual input, and anti-cheat drivers; mismatches against this population are actionable.

### 4.3 WMI Registration

Drivers register WMI providers via `IoWMIRegistrationControl` and `WmiSystemControl`, exposing one or more GUIDs and handling query, set, and event-notification requests. User mode queries through WQL or subscribes to provider events. An attacker hides a command channel inside provider queries, event notifications, or custom data blocks.

The trick is GUID selection. Provider GUIDs can be chosen to mimic OEM telemetry, hardware monitoring, or sensor providers, and the WMI namespace is large enough that a fresh provider in `root\\WMI` registered after protected workload launch is rarely investigated.

Microsoft's driver WMI model explicitly supports custom data, configuration through a standard interface, driver-defined events, and consumer-visible data/event blocks. That is exactly the cover an attacker wants. The UM side can query a data block as if it were hardware telemetry, set a block as if it were configuration, or subscribe to events as a wake channel. The KM side receives WMI IRP handling through `WmiSystemControl` and can decode method IDs, instance names, buffer sizes, and event enable/disable state as a protocol.

**Detection.** Inventory kernel-backed WMI providers, with timestamps and owner drivers. Store provider GUIDs, MOF/resource provenance where available, instance names, method IDs, data-block sizes, event GUIDs, enable state, consumer process, and query cadence. Validate GUIDs and signers; flag providers registered near protected workload launch from unknown drivers. Monitor WQL traffic from workload-adjacent helper processes. Enterprise tools, OEM utilities, sensor software, and EDR use WMI heavily: the discriminator is again "unknown owner driver plus registration timing plus suspiciously regular query activity from the protected process."

### 4.4 WSK Loopback and External Egress

Winsock Kernel lets kernel components use socket APIs. An attacker driver opens a WSK socket and connects to (or accepts from) `127.0.0.1` / `::1`; the user-mode side uses ordinary Winsock APIs against the same loopback endpoint. Compared to a custom device IOCTL path, this looks like network activity, supports reliable or datagram semantics, and can be proxied through helper processes for additional indirection.

It is one of the most operationally common L2 channels in commodity cheat ecosystems, and the same ownership problem applies to malware loaders and rootkits, because it is straightforward to implement and indistinguishable in casual inspection from any local-only network service. Voice chat, telemetry collectors, web UIs, and debugging tools all open loopback sockets.

There are several variants. In the simplest form, UM listens on loopback and KM connects through WSK; this lets the helper look like a local telemetry service. In the reverse form, KM listens and UM connects; this is noisier because kernel listeners are rare outside network/security products. Datagram mode can encode commands in packet size, source port, and timing even when payload is encrypted. Stream mode is easier for request/reply and bulk transfer. A helper can also proxy the loopback connection to a named pipe, section, or remote controller, leaving the kernel only responsible for a local socket.

**Detection.** This is one of the cheaper signals to acquire in production. The pipeline is:

1. Monitor loopback connections during protected workload runtime via ETW or socket telemetry.
2. Attribute each socket to a process and, where the connection is kernel-originated, to a kernel driver.
3. Flag local listeners created by unknown helper processes, and kernel-side WSK use by drivers with no documented network role.
4. Correlate with non-network drivers; a "system monitor", RGB, input, sensor, or overlay driver using WSK loopback without a network role is the canonical anomaly.
5. Baseline expected loopback endpoints for the title's launcher, voice chat, overlays, and telemetry: anything outside the baseline is investigation material.

The false-positive population is wide but mostly attributable: launchers, web-UI components of legitimate apps, voice chat, browser-based overlays, and local telemetry collectors. The strong signal is *kernel-side WSK use by an unsigned or freshly signed driver with no network role.*

#### Kernel-Resident License, REST-Like, and Configuration Fetch

Recent game-cheat stacks sometimes move licensing, subscription state, hardware-profile checks, and user configuration into the kernel side. Malware and rootkit families use the same shape for C2 policy, module retrieval, proxy state, and kill switches. Instead of asking a user-mode loader to fetch configuration and pass it down, the driver opens an outbound socket itself and talks to an external server. From the attacker's perspective, this keeps policy enforcement close to the privileged logic, makes user-mode reversal less useful, and lets the kernel decide whether to expose features before any obvious user-mode UI appears.

The wording "REST API from kernel" is usually imprecise. Windows gives kernel drivers WSK, a socket-style network programming interface. It does not give arbitrary kernel drivers the same high-level WinHTTP/WinINet/Schannel convenience stack that normal user-mode REST clients use. A kernel cheat therefore tends to choose one of these shapes:

1. *Raw TCP control plane.* The driver connects to a hard-coded IP/port or resolved endpoint and exchanges a compact binary protocol: license token, HWID hash, build ID, feature bitmask, and encrypted config blob.
2. *HTTP-shaped request over WSK.* The payload is a minimal `GET` or `POST` request built by the driver. It may look like REST in packet captures, but the driver owns the parsing, retries, headers, and response handling. In real samples, the static artifact can be very plain: code that appends header strings such as `Content-Type: application/json\r\n`, calculates their length with `strlen`-style helpers, then concatenates a JSON body containing license, HWID, product, build, or feature fields. That is strong evidence that the driver is not merely opening a socket; it is implementing a small HTTP client in kernel context.
3. *TLS-in-kernel or pseudo-TLS.* Higher-end stacks may embed a small TLS implementation or use custom encryption over TCP. Lower-end stacks often use plain HTTP, XOR/encrypted blobs, or certificate-pin-like magic without a real Windows TLS stack.
4. *UM resolver / KM connector split.* A user-mode helper performs DNS, proxy discovery, OAuth-like login, or TLS validation, then passes an IP, token, or session key to the driver. The kernel still owns the final license/config decision.
5. *Kernel egress as watchdog.* The driver periodically contacts a server to refresh feature flags, ban-state, watermark data, or anti-debug policy. If the server is unreachable or returns a revoked state, the kernel disables features or unloads.

The channel is not just C2. It is a *configuration authority* that changes how the kernel driver behaves. That makes it relevant even if the packet rate is low. A single outbound request can return offsets, encrypted strings, callback altitudes, provider signatures, WFP filter IDs, feature masks, or target process names. The driver then uses those values to arm other channels in this document.

Static reverse-engineering artifacts are useful here because kernel HTTP clients are unusual outside narrow network/security products. Record string and helper evidence such as:

1. HTTP method strings (`GET`, `POST`), request-line templates, `Host:`, `User-Agent:`, `Accept:`, `Content-Type: application/json\r\n`, `Content-Length:`, `Connection: close`, and CRLF-heavy format strings.
2. JSON field names tied to licensing or configuration: `license`, `token`, `hwid`, `user`, `product`, `build`, `version`, `config`, `features`, `expires`, `status`, or similar compact keys.
3. Manual buffer assembly routines: repeated append calls, `strlen` / length calculation, integer-to-string formatting for content length, fixed stack or pool buffers, and hand-rolled response parsing.
4. Network endpoint artifacts: hard-coded domains, IPs, URI paths, API route fragments, fallback host arrays, certificate or public-key blobs, and retry/backoff constants.
5. Parse-and-arm behavior: response fields that are immediately copied into global driver state, callback registration parameters, offsets, provider signatures, WFP IDs, or feature gates.

#### Related Case Studies and Research Signals

Public malware and rootkit research gives useful analogues for this cheat pattern. These families are not game cheats, but signed or kernel-resident Windows drivers have repeatedly used remote network authority for configuration, proxying, payload retrieval, certificate installation, or C2. Anti-cheat telemetry can reuse the same evidence model.

1. *Netfilter / Retliften.* G DATA's 2021 Netfilter analysis and Microsoft's Retliften description are directly relevant because the driver circulated in gaming environments, was Microsoft-signed, communicated with remote command infrastructure, received a root certificate over HTTP, wrote it into the machine root certificate store, and fetched proxy configuration. Defensive lesson: do not stop at "driver is signed" or "traffic is HTTP." Correlate driver egress with trust-store writes, `Internet Settings` proxy / AutoConfigURL changes, registry writes under certificate stores, and network stack interception.
2. *FiveSys and companion drivers.* Bitdefender's FiveSys research describes Microsoft-signed rootkit components used against online gamers, including traffic proxying, built-in proxy-domain lists, a component that served a PAC-style proxy autoconfiguration script, and another component that downloaded an executable and started it through kernel-assisted injection. Defensive lesson: kernel egress may not be a simple license check. It can be a proxy-control plane, downloader, updater, or module-reinstall path, all hidden behind a signed driver.
3. *Signed malicious driver ecosystem.* Group-IB's 2020-Q1 2025 signed-driver study found hundreds of signed malicious drivers and reported loader-style behavior including retrieval from C2, registry storage, local-disk staging, proxy behavior, memory injection, file access, and network tasks. Defensive lesson: a driver that fetches payload/config and then writes registry/local state is part of a broader signed-driver abuse economy, not a one-off curiosity.
4. *ToneShell / Mustang Panda style raw TCP over 443.* 2025 reporting on Mustang Panda's signed kernel-mode rootkit and TONESHELL backdoor describes TCP/443 C2, fake TLS-looking traffic, and rootkit protection around malicious files/processes/registry keys. Defensive lesson: port 443 or TLS-shaped bytes are not enough. Store TLS fingerprint, protocol compliance, server identity, owning driver/process, and post-response kernel side effects.
5. *Historical Rustock-style kernel networking.* Older Microsoft threat descriptions for Rustock note rootkit drivers communicating directly with TCP/IP-related devices. The modern implementation details changed; WSK/WFP replaced older TDI/device-hook patterns. The architecture is the same: kernel code owns network I/O and hides the user-mode control plane.

The highest-value translation is: "license server", "config API", "update endpoint", and "C2" are all remote policy inputs into a privileged component. A response can decide whether callbacks are registered, which offsets are trusted, what domain/IP to use next, which defender processes to shield against, whether to activate paid features, or whether to retrieve another module.

**Detection.** Treat kernel-originated internet egress as high-value telemetry:

1. Attribute outbound flows to drivers, not only to processes. WSK traffic may appear as System/tcpip activity unless the detector correlates socket creation context, call stack, WFP classify context, ETW network events, and driver load timeline.
2. Separate loopback from internet egress. A non-network driver using WSK loopback is suspicious; a non-network driver connecting to remote IPs or cloud-hosting ranges during protected workload runtime is stronger.
3. Record remote IP, port, SNI/ALPN if visible, TLS fingerprint if available, DNS source if any, hard-coded endpoint indicators, byte counts, request cadence, retry behavior, and whether traffic starts immediately after driver load.
4. Correlate egress with license/config side effects: new section mappings, registry writes, callback registrations, WFP filters, firmware-provider registration, or driver dispatch pointer changes after the response.
5. Baseline legitimate kernel egress. VPN, firewall, EDR, anti-malware, backup, storage sync, and network drivers can legitimately use kernel networking. GPU, input, RGB, sensor, overlay, or generic "system utility" drivers generally should not fetch remote config from the kernel during a protected session.
6. Watch for UM resolver / KM connector splits. A helper that performs DNS/TLS and then a driver-owned WSK connection to the resolved address is a stronger pattern than either half alone.
7. Preserve failed connection attempts. Cheats often fail open, retry at fixed intervals, or switch fallback hosts; failed SYNs and short-lived TLS failures can reveal the channel even when the server is down.
8. During static or memory analysis, search driver images and pool-backed decoded buffers for HTTP header fragments, JSON keys, URI paths, and CRLF request builders. A non-network driver containing `Content-Type: application/json\r\n` plus WSK imports/call paths and a license/config parser is a coherent evidence package.
9. After kernel egress, diff sensitive state: certificate stores, proxy/PAC settings, WFP filters, minifilter registration, driver service keys, callback slots, registry shield paths, and on-disk module staging directories. Netfilter/FiveSys-like cases show that remote config often changes local trust or proxy state, not only in-memory feature flags.

False positives require product context, not blanket allowlisting. Security products and VPNs have a reason to speak to remote services from kernel-networking paths; a freshly loaded role-mismatched driver using WSK to fetch a small opaque blob from a VPS shortly before registering callbacks is not normal platform behavior.

### 4.5 NLS File Page Sharing

National Language Support files under `C:\\Windows\\System32\\*.nls` are mapped by many processes for code-page and locale data. A driver can write into a reserved or rarely used mapped area; user mode maps the same NLS file with `CreateFileMappingW` and reads the chosen offset. The shared mapping carries the payload.

This works because (a) NLS mappings are commonplace, (b) section objects backing them are accessible without unusual API use, and (c) cross-process visibility is free: every process that touches the same NLS file sees the same backing pages.

**Limits.** NLS files are protected system files. The kernel write must avoid integrity-checked regions, and the underlying section object's backing on disk may be subject to verification at boot or at update time. The surface is *low-noise when it works*, but it can fail abruptly if Windows updates change the NLS file layout or activates additional integrity checks.

The protocol has two fragile assumptions: both sides agree on a stable offset, and the write is visible through the same section backing. Attackers choose offsets in rarely inspected tables, padding, or locale data they believe the game will not parse. The UM side may map the file directly, or it may rely on the game/runtime already having mapped it and read from the existing view. The KM side may write through a mapped system address or by reaching the section's physical pages. Either way, a protected language table becomes an implicit shared section.

**Detection.** Validate NLS file section integrity against disk and a known-good hash. Monitor writable mappings of NLS-backed pages, or write attempts that target NLS section objects. Store file path, section object, mapped processes, view protections, dirty-page state, offset, byte range, and writer attribution where possible. Check whether workload-adjacent processes map *unexpected* NLS files during runtime: most protected applications, games, overlays, and services touch the locale tables they need at startup and not again. Treat any kernel write into an NLS-backed page as high severity; the legitimate write population is essentially zero outside Windows Update.

### 4.6 Windows Filtering Platform Callout Channels

Windows Filtering Platform is the supported packet-filtering and stream-inspection framework that replaced older firewall hook, filter hook, TDI filter, NDIS filter, and LSP designs for most security-product use cases. It has both user-mode management APIs and kernel-mode callout drivers. User mode opens the filter engine with `FwpmEngineOpen0`, creates providers, sublayers, filters, and callouts, and can make them dynamic or persistent. Kernel mode registers callouts with `FwpsCalloutRegister*`; classify callbacks then receive traffic at layers such as ALE connect/listen, transport, stream, datagram, and packet paths. Microsoft explicitly positions callouts for deep inspection, packet modification, stream modification, and logging.

That makes WFP a strong hiding surface for command framing because a WFP callout is *supposed* to see local sockets and *supposed* to make decisions based on packet metadata. The cheat pattern has three useful forms:

1. *Loopback command packet.* UM sends a loopback TCP/UDP packet to an ordinary-looking local endpoint. The WFP callout at ALE or transport layers sees the flow, decodes a magic tuple, payload shape, or connection pattern, and either permits, blocks, or absorbs the packet after extracting the command.
2. *Filter-state channel.* UM adds, deletes, or modifies a dynamic WFP filter or provider context. KM observes the changed filter state or receives classify-time context, treating the management operation itself as the command. This avoids a custom device object and makes the UM side look like a firewall or VPN helper.
3. *Pend/complete signal.* At layers that support pended operations, the callout can suspend processing and resume it later. The timing of pend/complete operations becomes a signal path, useful for watchdogs or "anti-cheat reached phase X" synchronization.

The trade-off is privilege and visibility. Creating callouts and filters is not invisible; the Base Filtering Engine has a durable object model, providers, sublayers, filter IDs, weights, conditions, and security descriptors. But the false-positive population is large: Windows Firewall, VPNs, EDR, anti-malware, parental controls, network monitors, packet capture tools, and anti-cheat products all use WFP.

**Detection.** Build a WFP inventory at boot and at protected workload launch:

1. Enumerate WFP providers, sublayers, callouts, filters, provider contexts, and dynamic sessions. Track object GUIDs, display names, security descriptors, weights, conditions, and persistence.
2. Attribute every kernel callout target to a driver image and signer. A callout target outside a known network/security driver is a strong anomaly.
3. Correlate filter creation time with protected workload launch, driver load, and helper-process start. Dynamic filters that exist only during protected-session runtime deserve attention.
4. Watch loopback flows that are immediately absorbed, blocked, or classified by an unknown callout. A flow that never reaches the socket consumer but produces callout activity can be a command packet.
5. Compare sublayer and provider names against vendor manifests. Attackers often mimic "VPN", "monitor", "security", or "QoS" roles without shipping the rest of the product footprint.

False positives should be handled by role. A VPN callout that owns tunnel interfaces and has a service, driver, certificate, UI, and install record is normal. A freshly signed "system optimization" driver that registers ALE_AUTH_CONNECT callouts and only classifies traffic from the protected process is not.

### 4.7 Virtual HID, VHF, and Class-Input Callback Channels

Virtual HID is the software-input counterpart to external HID emulators. Starting with Windows 10, Virtual HID Framework lets a kernel-mode HID source driver create virtual HID devices without writing a full transport minidriver. The HID source driver calls `VhfCreate`, supplies a HID report descriptor, starts the virtual device, and submits input reports through VHF. VHF and HIDClass then expose normal top-level collections to user-mode HID clients just like a real keyboard, mouse, gamepad, sensor, or vendor-defined HID device.

As a cheat channel, VHF is attractive for two reasons. First, it blends into the legitimate input-device ecosystem: accessibility tools, remote input, Miracast UIBC, virtual gamepads, headset buttons, sensor bridges, and OEM utilities all have plausible reasons to produce HID reports. Second, HID is not only input. Feature reports, output reports, vendor-defined collections, report IDs, padding bits, logical ranges, collection topology, and descriptor strings can all carry state. A driver can send low-bandwidth KM→UM data as input reports, while a UM helper can send UM→KM data through feature/output reports if the source driver registered callbacks for those paths. Operationally, `VhfCreate` only creates the virtual HID device and reports it to PnP; VHF callbacks are not invoked until the HID source driver calls `VhfStart`, so detection should treat create/start/report-submit as separate phases.

The clean cheat layout is:

1. The driver exposes a virtual HID device with a plausible VID/PID/container ID and a descriptor that resembles a common device class.
2. The game, an overlay, or a helper process consumes raw input, HID APIs, XInput/DirectInput translations, or a vendor-defined collection.
3. The driver encodes state in report IDs, feature-report bytes, rare buttons, axis noise, wheel deltas, sensor values, or timing between reports.
4. The UM side returns acknowledgments through feature reports or a separate object channel.

The dangerous twist is that this surface can double as *input delivery*. The same report stream can move aim adjustments, recoil compensation, or trigger decisions while also carrying configuration and health checks. A software VHF device therefore bridges the software-cheat and hardware-HID threat models.

#### Class-Service Callback Hijack: MouClass / KbdClass

Cheat forums also discuss a lower-level input variant that does not create a new virtual HID device at all: hijack or directly call the keyboard / mouse class-service callback path. Windows class drivers use internal device-control requests such as `IOCTL_INTERNAL_KEYBOARD_CONNECT` and `IOCTL_INTERNAL_MOUSE_CONNECT` to pass a `CONNECT_DATA` structure down the stack. A legitimate upper filter can save the original class service callback, replace the callback pointer with its own filtering routine, and forward or modify input packets before they reach Kbdclass or Mouclass. Microsoft documents this pattern as the basis for keyboard and mouse filter callbacks.

The cheat version abuses the same shape in one of four ways:

1. *Install a fake class upper filter.* The driver attaches above the port/HID stack, receives the connect request, stores the original `ClassService` pointer, substitutes its own callback, and forwards normal input while injecting or suppressing packets.
2. *Patch cached `CONNECT_DATA` state.* Instead of being a real PnP filter, the cheat locates a cached callback pointer in an existing filter or device extension and swaps it after the legitimate connect sequence has completed. This avoids a visible new filter driver in `UpperFilters` but creates a raw pointer-integrity violation.
3. *Direct callback invocation.* The cheat resolves or steals the original `MouseClassServiceCallback` / `KeyboardClassServiceCallback` pointer and calls it with crafted input-data packets from its own driver. This simulates hardware-originated deltas below `SendInput`, user-mode hooks, and many raw-input monitors.
4. *Dual-use command stream.* The callback path is primarily an input-return path, but the same packet timing, unused button bits, wheel deltas, scan-code choices, or vendor-filter context can carry low-bandwidth KM->UM state to a cooperating user-mode raw-input consumer.

This is distinct from VHF. VHF creates a new virtual HID source and leaves PnP / descriptor evidence. A class-service callback hijack may leave only a modified callback pointer, an unexpected filter in the existing keyboard/mouse stack, or physically implausible packet cadence from a real-looking device. It is therefore a better fit for attackers who want the input to look like it came through the ordinary Mouclass/Kbdclass queue rather than from a newly enumerated virtual device.

**Detection.** Treat virtual HID as both device inventory and behavioral telemetry:

1. Enumerate HID devices and top-level collections before and during protected workload activity. Record VID, PID, version, serial number, container ID, bus type, parent device stack, INF, signer, install time, and driver image.
2. Parse report descriptors. Flag vendor-defined pages, unused padding with high entropy, role-inconsistent logical ranges, descriptor layouts that claim to be a mouse but include hidden feature reports, and report sizes far larger than the claimed device role requires.
3. Attribute the source stack. A VHF-backed device whose parent driver has no hardware or accessibility role is suspicious.
4. Monitor raw-input cadence and report entropy. Human input has natural variability but constrained semantics; a report stream with fixed-interval command fields, physically implausible axis transitions, or high-entropy vendor bytes is not normal input.
5. Correlate with server-side input dynamics. Client-side HID evidence alone is rarely ban-quality; paired with impossible reaction timing, aim curves, and target-selection behavior it becomes much stronger.

For the Mouclass/Kbdclass variant, add stack-level checks: enumerate keyboard and mouse device stacks, `UpperFilters`, attached filter device objects, device extensions that hold class `CONNECT_DATA`, callback targets, callback context objects, and packet-injection cadence. Validate callback targets against the expected Kbdclass/Mouclass/filter driver images and function entries. Record every non-Microsoft filter that handles `IOCTL_INTERNAL_*_CONNECT`, any post-connect callback pointer change, and any callback target that points into pool memory, a mapped manual driver, or a signed module interior that is not a function entry. Packet telemetry should include input source device, report-to-class latency, DPC/ISR context, packet count, delta distribution, and whether injected movement starts shortly after visual target exposure. A legitimate mouse filter transforms or passes device-originated packets; a cheat filter often produces command-shaped bursts or mathematically smooth deltas unrelated to physical-device jitter.

False positives include accessibility devices, virtual gamepads, remote-play software, Steam Input, vendor control panels, KVMs, and enterprise remote-control tools. The policy decision should be explicit: competitive modes may require a strict HID allowlist or force unknown virtual HID devices into a degraded-trust state, while casual modes can observe and score.

### 4.8 eBPF for Windows Maps and Ring Buffers

eBPF for Windows is not yet a universal gaming-client primitive, but it is worth tracking. It provides a verifier/runtime model, program attach points, maps, perf-event arrays, and ring-buffer style data paths that resemble the Linux eBPF ecosystem. The official Microsoft-hosted API surface exposes map objects, map lookup/update/query operations, ring-buffer mapping helpers, perf-event-array writes, and wait-handle signaling for new map data. From a channel perspective, that is a legitimate kernel-adjacent telemetry framework with explicit shared data structures.

Do not read this as "cheats are widely using eBPF on Windows today." The risk is that eBPF creates a normalized, policy-mediated way for user mode and kernel-resident execution to share state. Once a title's support matrix includes systems with an eBPF runtime, or once a vendor installs it as part of a security/networking product, the maps become a potential covert channel:

1. UM loads or controls an eBPF program through the eBPF service/runtime.
2. The program attaches to a network or socket-related hook and observes packet/process metadata.
3. UM and the program share state through maps, ring buffers, perf-event arrays, or pinned objects.
4. Commands are encoded in map values, while KM/eBPF-to-UM telemetry is emitted through ring/perf buffers or wait-handle notification.

The channel is low-friction because maps are *supposed* to be shared state. It is also easier to operationalize than raw kernel offsets because eBPF APIs expose object IDs, map info, program info, and link info. The attacker benefit is that the communication artifact can look like modern telemetry, firewalling, or network observability rather than a bespoke attacker driver.

**Detection.** If eBPF for Windows is present in the fleet, add it to the same inventory tier as WFP:

1. Enumerate loaded programs, attach types, links, maps, pinned objects, and map types. Ring buffers, perf-event arrays, queues, stacks, and hash maps with high-frequency updates from workload-adjacent processes deserve extra attention.
2. Attribute the loader and controller process. A browser, EDR, VPN, or network product may have a reason to control eBPF objects; a game overlay or unknown helper usually does not.
3. Validate program signatures, verifier logs where available, map names, object lifetime, and whether objects appear only during competitive sessions.
4. Monitor map update/query cadence. A small map updated at command cadence by a workload-adjacent process is a stronger signal than a long-lived security product map updated by a service.
5. Treat eBPF as a policy surface. If the game does not depend on it, competitive mode can require no third-party eBPF runtime or only allow known security products.

False positives will grow as eBPF adoption grows. Score ownership and attach role, not the existence of maps. A signed network monitor with documented attach points is normal; a per-match ring buffer controlled by an unknown helper is not.

### 4.9 Cloud Files, ProjFS, and User-Mode File-System Provider Callbacks

Cloud Files API and Projected File System are easy to overlook because they look like file-system features, not IPC. That is exactly why they belong in a KM-UM communication catalog. Microsoft documents `CfConnectSyncRoot` as initiating a bidirectional communication channel between a sync provider and the sync filter API, with a callback table and an opaque connection key. ProjFS has the same shape from a different angle: a user-mode provider starts a virtualization instance, supplies callbacks, and ProjFS invokes those callbacks in response to file-system operations under the virtualization root.

The channel value is not "file storage." It is *platform-mediated callback delivery*. A protected process, helper, scanner, anti-cheat, EDR, or service touches a path under a sync root or virtualization root. The Windows platform or ProjFS driver calls into a user-mode provider. The provider can return data, deny operations, observe the triggering process, or use the callback as a wake edge that leads into a section, ALPC port, named object, or ETW stream.

Useful cheat shapes include:

1. *Hydration-trigger mailbox.* A placeholder file is opened or read by a workload-adjacent process. The cloud-file provider receives a fetch-data style callback and treats the path, byte range, process image, or request timing as a command selector.
2. *Projected-file rendezvous.* A ProjFS provider exposes virtual files whose names encode epochs or selectors. Opening, enumerating, or reading those names triggers provider callbacks without a custom device object.
3. *Notification-only channel.* Create, delete, rename, hardlink, enumeration, or read notifications act as low-bandwidth events. The payload moves elsewhere.
4. *Process-identity oracle.* Cloud Files callbacks can include `CF_CALLBACK_INFO.ProcessInfo` when the provider connects with process-info requirements, and ProjFS `PRJ_CALLBACK_DATA` can carry `TriggeringProcessId` and `TriggeringProcessImageFileName` for callback types that supply them. That lets a provider distinguish game, launcher, scanner, and anti-cheat access patterns and respond differently.
5. *Canary inversion.* Defender research uses ProjFS-style canaries because callbacks reveal who touched the file. A cheat can invert the idea: create a provider-backed canary path and use anti-cheat access as a phase signal.
6. *Third-party user-mode file-system bridge.* WinFsp, Dokan, CBFS-style products, and vendor sync engines create the same evidence pattern: a user-mode process serves file data through a kernel driver or filter path. The implementation differs, but the defensive model is provider identity plus file-operation-triggered callbacks.

The operational cover is strong. OneDrive, cloud sync clients, enterprise document agents, source-control virtualization, backup tools, and security products all create provider-backed paths. An attacker can choose a vendor-looking sync root and never expose a named pipe or IOCTL; the only visible activity is file-system access to a path the system is designed to virtualize.

**Detection.** Add provider-backed file systems to the mediation inventory:

1. Enumerate registered Cloud Files sync roots, ProjFS virtualization roots, reparse tags, placeholder directories, provider processes, provider binaries, signers, service registrations, and start/stop times.
2. Record callback evidence where available: callback type, path, byte range, process image/PID that triggered the operation, connection key or virtualization context, status returned, and whether the provider returned data or denied the request.
3. Correlate provider callbacks with protected workload runtime. A provider path that is untouched before launch but receives fixed-size reads from the protected process, anti-cheat, EDR, or scanner during a protected session deserves attention.
4. Treat reparse-point identity as part of the path-identity model from §2.3. Store raw path, final path, file ID, reparse tag, sync-root identity, provider image, and handle-derived file object name.
5. Watch for provider roots under game, launcher, GPU-cache, crash-report, or vendor-looking directories created shortly before competitive sessions.
6. Separate legitimate cloud/source-control products from role-mismatched providers. A signed OneDrive or GVFS-style provider with stable roots is normal. A per-user provider launched by an unknown helper and serving only workload-adjacent callbacks is not.

False positives are broad but explainable. Cloud sync, VFS for Git, development tools, backup agents, DLP, EDR canaries, and enterprise document systems all use these mechanisms. Score role, root path, provider identity, callback timing, and whether the provider has a real user-facing sync or virtualization purpose.

### 4.10 Mediation Deep-Dive Matrix: Registered Surface, Owner, Consumer

Official KM-UM mediation surfaces are easier to defend than private hooks because they create registration artifacts. Do not stop at "the primitive exists." Store the tuple that explains the channel: registered surface, owner image, security descriptor, user-mode consumer, payload shape, and teardown behavior.

**Filter Manager communication ports (§4.1).** A minifilter port has a server side owned by a filter instance and a user-mode client connected through the Filter Manager API. Store filter name, altitude, instance volume, communication-port name, allowed SID set, connected client PID, message size, reply size, and disconnect timing. A clean anti-cheat, AV, DLP, or backup product has stable filter altitude and install provenance. A cheat-like port often has a random or vendor-mimicking name, exists only while the game runs, and carries fixed-size command messages unrelated to file-system operations.

**Device-interface GUIDs (§4.2).** `IoRegisterDeviceInterface` registers a PnP-discoverable interface instance, and `IoSetDeviceInterfaceState` controls whether the symbolic link is enabled for user-mode discovery. This is more subtle than a hand-made `\\Device\\Cheat` object because user mode can enumerate by GUID and open the returned symbolic link. Inventory should record interface class GUID, reference string, PDO stack, enabled/disabled state, symbolic link, device setup class, INF, service name, and consumer process. A suspicious pattern is a custom GUID with no public or product-manifest role, enabled only during protected workload activity, whose PDO stack belongs to a driver that is not hardware-backed.

**WMI registration (§4.3).** A WMI provider registered through a device object can expose data blocks, methods, and event notifications. Treat it like a structured RPC surface: provider GUID, MOF/registration data, data-block layout, method IDs, event GUIDs, and consumer identity all matter. Attacker use often creates a private provider with binary method payloads or uses WMI eventing as a low-frequency wake path. The false-positive boundary includes hardware telemetry, storage, network, and OEM utilities; the high-signal case is a workload-adjacent driver registering WMI blocks with no hardware or admin tooling role.

**WSK loopback and external egress (§4.4).** WSK is not suspicious by itself for network drivers, but it is suspicious for drivers with no network role. Capture socket family, local/remote tuple, owning driver, creating thread context, connect/listen timing, byte counts, and whether a corresponding user-mode socket exists. Game-cheat stacks favor loopback because the transport is mature and firewall-friendly; malware and rootkits use the same primitive for local brokers, C2, proxy state, and kernel-resident config fetch. The defender should separate user-mode loopback, kernel-originated loopback, and kernel-originated internet egress. A non-network kernel driver creating WSK sockets during protected-session runtime is a strong lead; a non-network driver contacting remote cloud/VPS infrastructure and then registering callbacks, sections, or WFP filters is stronger.

**NLS file page sharing (§4.5).** This surface is not an official IPC API, but it uses official file mapping behavior. Detailed detection needs section provenance: file path, section object, view protections, mapped process list, dirty-page state, write origin, and hash against disk. The suspicious event is not a game mapping an NLS file at startup; the suspicious event is a writable or modified view of a protected NLS-backed section, especially if the dirty page is later observed by the game or helper. Because legitimate writes are almost nonexistent, this can be escalated faster than noisy IPC surfaces.

**WFP callouts (§4.6).** WFP defense requires both management-plane and dataplane evidence. Management-plane inventory covers providers, sublayers, filters, conditions, weights, provider contexts, callout GUIDs, dynamic sessions, and persistence. Dataplane evidence covers classify layer, flow key, ALE endpoint, packet tuple, action, pend/complete behavior, injection/absorb behavior, and target driver. A WFP command channel usually has a management-plane artifact that looks like a security product and a dataplane pattern that only touches game or loopback traffic. If an unknown callout classifies only the game's loopback flow and never behaves like a firewall/VPN/EDR, the role mismatch is the evidence.

**Virtual HID, VHF, and class-input callbacks (§4.7).** The virtual-HID side has three identities: PnP device identity, HID descriptor identity, and behavioral identity. PnP identity is VID/PID/container/serial/INF/service/signer. Descriptor identity is usage page, usage, report IDs, feature/output/input report lengths, logical min/max, units, and vendor-defined collections. Behavioral identity is report cadence, axis/button plausibility, entropy in unused bits, feature-report traffic, and server-side input dynamics. A VHF-backed device that claims to be a simple mouse but exposes large vendor-defined feature reports should not be treated as normal input hardware.

The class-input side has a different evidence model: keyboard/mouse device stack, class upper filters, `IOCTL_INTERNAL_*_CONNECT` handling, cached `CONNECT_DATA`, callback target, callback context, packet cadence, and whether the target lands in Kbdclass/Mouclass or a documented filter function. A hidden callback swap in an existing stack may leave no new HID device at all, so virtual-device inventory and class-service callback validation must be separate checks.

**eBPF for Windows (§4.8).** The runtime should be inventoried only when present, but when present it deserves WFP-level treatment. Record loaded programs, attach types, links, maps, map types, key/value sizes, ring/perf buffers, pinned objects, controller process, service identity, verifier/log state, and driver/runtime version. A map is not a finding; a map with opaque fixed-size values updated by a workload-adjacent controller and consumed by a kernel-resident program is a channel. As adoption grows, the useful policy will be "known vendor eBPF programs allowed, unknown protected-session programs observed or blocked," not blanket distrust of eBPF.

**Cloud Files / ProjFS providers (§4.9).** Treat provider-backed file paths as callback endpoints. Record sync root or virtualization root, provider image, callback table registration time, reparse tag, placeholder state, triggering process, callback type, byte range, status, and returned-data shape. A path read is not just a file read if it crosses into a provider callback. Suspicious cases are provider roots created near protected workload launch, callbacks triggered only by the protected process or defender scanner, opaque fixed-size returned data, and provider binaries with no real cloud/source-control/backup role.

---

## 5. Kernel Callback Infrastructure

Windows exposes a rich set of kernel callback APIs for security products, anti-malware, debuggers, and instrumentation tools. Each of them is a *signal channel*: a UM operation reaches a kernel code path that calls a registered callback. An attacker registers in the same slot, treats the event as a command trigger, and either takes action in kernel mode or returns a value that influences the operation. The defender's problem is that *legitimate registrations look identical to malicious ones at the API level*; what changes is the owner driver, the callback target, and the response behavior.

### 5.1 PsSetCreate Process/Thread/LoadImage Notify Arrays

Windows maintains arrays of registered notify routines for process creation (`PsSetCreateProcessNotifyRoutineEx`), thread creation (`PsSetCreateThreadNotifyRoutine`), and image-load events (`PsSetLoadImageNotifyRoutine`). Each is an array of slots; each slot is an `EX_FAST_REF`-wrapped pointer to a callback block.

**Slot counts (corrected from v6).** The expansion from 8 slots to 64 slots landed in *Windows 8* (NT 6.2, build 9200), not in Windows 10 1507 (build 10240). v6 had this boundary off by one major version, and detection code that uses 10240 as the cutoff *will undercount callbacks on Windows 8 and 8.1*. The correct cutoff:

```cpp
ULONG max = (osBuildNumber >= 9200) ? 64 : 8;  // 9200 = Windows 8 RTM
```

The `EX_FAST_REF` mask is `~15` on x64 and `~7` on x86; the lower bits are reference counts. A clean walker looks like:

```cpp
ULONG max = (osBuildNumber >= 9200) ? 64 : 8;

for (ULONG i = 0; i < max; i++)
{
    ULONG_PTR raw = (ULONG_PTR)NotifyArray[i];
    if (raw == 0)
    {
        continue;
    }

    PVOID block = (PVOID)(raw & ~MAX_FAST_REF);
    PVOID func  = *(PVOID*)block;

    // Validate func target against loaded modules.
}
```

**Why attackers register here.** Lifecycle events are *natural* during workload startup. In anti-cheat cases, image-load callbacks observe module load order and let the cheat time its actions relative to anti-cheat initialization. In malware cases, the same callbacks expose process creation, injected module load, service startup, and security-tool activity. Process and thread creation callbacks give a UM->KM signal whose UM side is just `CreateProcess` or `CreateThread`.

The same arrays are also the surface for *tamper*: an attacker may not register its own callback but may instead overwrite a legitimate slot's pointer with its own trampoline, forwarding the original on the way out.

**Detection.** Enumerate callbacks with symbol-aware parsing and `EX_FAST_REF` handling. Validate callback target addresses against the loaded module ranges and the on-disk image bytes of the owning driver. Track callback registration time relative to boot and protected workload launch. The strong signal is "callback target outside any signed module" or "callback target inside a signed module but at an address that does not match the on-disk function bytes": the second pattern catches in-place hot-patching of a legitimate callback.

### 5.2 CmRegisterCallback Registry Callbacks

`CmRegisterCallback` and `CmRegisterCallbackEx` give drivers a registry-operation notification path. The attacker uses it as a command-trigger surface (UM writes a value, KM receives a callback and decodes the path or data), as a defensive shield (KM denies access to registry keys that defenders inspect), or both.

#### Attacker Mechanics: Registry Operation as Syscall-Like ABI

A registry callback channel is easiest to understand as a private syscall ABI built out of a normal configuration write. The key path is the service selector, the value name is the stream selector, the value type is an opcode field, the data buffer is the argument block, and the callback return path is the status. The registry hive is not necessarily the storage layer; it can be only the dispatch surface.

Attackers like this because the UM side can use ordinary registry APIs that are already common in launchers, services, installers, graphics utilities, and game settings tools. The kernel callback sees richer state than most post-factum registry scanners: operation class, raw type, value name, data pointer, data size, caller context, and whether the operation is still in the pre-notification stage. That pre-operation timing is important. The driver can consume the command, alter the status, or rewrite the attempt before any durable value is committed to disk.

The protocol usually splits into four layers:

1. *Path gate.* The callback ignores almost all registry traffic and activates only for one normalized key path, path prefix, object pointer, hive, or transaction state. This keeps CPU cost and noise low.
2. *Selector fields.* Value name, raw type, data size, transaction state, and sometimes the desired final status form the command selector. The type field is attractive because many tools assume it is one of the documented `REG_*` constants and lose fidelity for out-of-range values.
3. *Argument block.* The data buffer carries either inline arguments or a pointer/handle/nonce that identifies a companion payload channel. In more careful designs, the registry write only transfers a mailbox descriptor and all high-volume traffic moves elsewhere.
4. *Reply and acknowledgement.* The reply can be the callback's returned status, a modified value, a second registry read, a size mismatch, an event signal, or a later write to a paired value. Some channels intentionally leave no persistent reply in the hive.

This is why registry channels often look underwhelming in static artifacts: one odd value write, one weird type, or one denied operation. The real value is that a registry write gives UM a legitimate transition into a kernel callback at a predictable point in the configuration manager pipeline.

#### Undocumented Registry Value-Type Command Channel

One particularly quiet variant uses the registry value *type* as part of the protocol. `RegSetValueExW` and `ZwSetValueKey` both take a caller-supplied type field (`dwType` / `Type`). Microsoft documents the normal `REG_*` values in `winnt.h`, but the registry callback path passes the attempted write to the filter as a raw `ULONG Type` inside `REG_SET_VALUE_KEY_INFORMATION`, along with `ValueName`, `Data`, and `DataSize`. A filter registered with `CmRegisterCallbackEx` can therefore treat a write that uses a non-standard or undocumented type value as a command, even if the value name and data look boring.

The usual layout is:

1. *Key path selects the channel.* The key lives under a plausible vendor, cache, telemetry, service, or per-user configuration path. The path is not enough to identify the command because ordinary software writes nearby keys too.
2. *Value name selects the stream.* The value name may be stable (`State`, `Config`, `LastError`) or rotated. A stable value name keeps the artifact looking like configuration; a rotated name defeats simple IOC matching.
3. *Type carries opcode and flags.* Values outside the documented `REG_*` set, or values in a private high-bit range, encode command family, operation, version, or direction. For example, the high word can identify the protocol family while the low word identifies the command. The exact numbers are attacker-defined; defenders should not hard-code one magic value.
4. *Data/DataSize carries payload.* The data can be empty for one-bit triggers, small for command arguments, or fixed-size/high-entropy for encrypted payloads. `DataSize` itself can also be part of the selector.
5. *Pre-operation callback consumes the attempt.* The driver can observe the write before it is committed. Some variants only need the pre-set notification and do not care whether the unusual value is later visible in the hive. This is why scanning the registry after the fact can miss the channel.

This is different from ordinary registry storage. In a storage pattern, the data bytes are the payload and the type is a normal `REG_BINARY`, `REG_DWORD`, or `REG_SZ`. In the undocumented-type pattern, the *type field is the stealthy discriminator*. Many tools display unknown types poorly, ignore them, normalize them in exports, or focus on value data and path names. A defender that records only key path, value name, and data bytes loses the opcode.

**Why attackers use it.** It gives UM->KM signaling without a device object, IOCTL, named pipe, ALPC port, event object, or custom section. The user-mode side performs a normal registry write. The kernel side receives `RegNtPreSetValueKey` / `RegNtSetValueKey` callback context and decodes the raw type before ordinary registry tooling has a chance to interpret it. If the callback blocks, rewrites, or consumes the operation, the durable artifact may be absent or may appear only as a harmless normal value.

#### Callback-Context Gadget Masking

The more sophisticated version hides the callback source itself. A registry callback routine has the generic `EX_CALLBACK_FUNCTION` shape: the first argument is the callback context supplied at registration time, the second argument identifies the registry operation, and the third argument points to the operation-specific structure. On x64 Windows, the first argument is delivered in `RCX`. If a cheat registers a callback routine pointer that lands on a tiny kernel-resident gadget such as `jmp rcx`, the callback list appears to point into `ntoskrnl` or another trusted kernel image. At invocation time, the gadget transfers execution to the callback context value, which can point at the cheat's real handler or at a dispatcher structure controlled by the cheat.

That breaks a common detector shortcut:

```text
callback function pointer inside ntoskrnl == safe
```

For this pattern the registered function pointer is intentionally safe-looking. The suspicious object is the *pair*:

```text
registered callback function -> trusted-image gadget
callback context             -> untrusted executable target / dispatcher
```

The same idea can apply to other callback families whose first argument is a registration context, including object-filter callbacks. Registry callbacks are especially useful because the same invocation also exposes `REG_SET_VALUE_KEY_INFORMATION.Type`, so the attacker gets both a hidden dispatch target and a compact UM->KM command ID in one path.

**Detection.** Registry callback validation must inspect more than the callback routine address:

1. Disassemble the registered callback routine target even when it is inside `ntoskrnl`, HAL, or another trusted image. Flag one-instruction or short gadget targets such as register-indirect jumps/calls, especially `jmp rcx`, `call rcx`, or equivalent dispatch-through-first-argument patterns.
2. Record the callback context pointer and classify it. A context pointer into the registering driver's non-executable data is normal. A context pointer that is executable, points into an unknown driver, points into pool code, or points to a structure whose first field is executable is suspicious.
3. Pair gadget detection with altitude and owner attribution. A legitimate registry filter should register an actual function entry in its own driver image, not a generic kernel gadget plus an opaque executable context.
4. Preserve the invocation evidence: `Argument1` / `REG_NOTIFY_CLASS`, `REG_SET_VALUE_KEY_INFORMATION.Type`, value name, data size, caller PID, and whether the callback consumed or modified the operation.
5. Do not rely on module-range validation alone. A callback target inside a clean Microsoft image can still be a gadget trampoline when the callback context is attacker-controlled.

This pattern is particularly good at defeating shallow callback inventories because the visible function pointer passes "inside trusted module" checks. The durable fix is semantic validation: function-entry validation, gadget classification, callback-context classification, and correlation with unusual registry value types.

**Detection.** Add raw value-type telemetry to registry monitoring:

1. Record every workload-adjacent `RegSetValueExW`, `NtSetValueKey`, and driver-originated `ZwSetValueKey` attempt with key path, resolved symbolic-link target, value name bytes, type value, data size, caller PID/TID, image, signer, and transaction/virtualization state.
2. Maintain a known type set from the documented `REG_*` values and separately track rare but legitimate resource types. Values outside that set are not automatically malicious, but they are high-quality hunting leads when written by the game, launcher, overlay, unknown helper, or freshly loaded service.
3. Correlate non-standard type writes with registry callbacks from unknown drivers. The evidence package is strong when a driver registers a callback, a workload-adjacent process writes an unusual type under a watched path, and the driver performs work immediately afterward.
4. Compare pre-operation telemetry against post-operation hive state. If a suspicious type appears in pre-set telemetry but never persists, the callback may be consuming or blocking the command.
5. Inspect cadence. Repeated writes to the same value with changing undocumented type values look like opcodes; repeated writes with stable type but changing fixed-size high-entropy data look like encrypted payloads.

False positives exist. Legacy applications, installers, driver packages, resource-map data, broken registry writers, and migration tools can create unusual types. The signal becomes useful when four things align: non-standard type, game-session timing, unknown registry callback owner, and command-like cadence.

**Detection.** Enumerate registry callbacks and their altitudes (Windows exposes both internally; a defender driver walks `nt!CallbackListHead` or equivalent build-aware state). Validate callback target addresses against signed modules, but do not stop there: confirm the target is a plausible function entry, classify short register-indirect gadgets, and classify the callback context pointer. Check suspicious altitude strings, duplicate vendor naming, unknown drivers in the chain, and trusted-image gadgets that dispatch through attacker-controlled context. Correlate with unusual registry paths touched by the protected process: a callback from an unknown driver, or a trusted-looking gadget callback with untrusted context, plus protected-process writes to high-entropy paths or non-standard value types is the high-confidence pattern.

Security products, virtualization tools, and configuration managers legitimately register registry callbacks; the discriminator is owner image, altitude appropriateness, and behavior on inspection (callbacks that *deny* access to specific paths from specific PIDs are the defensive-shield pattern and look distinctive in telemetry).

### 5.3 ObRegisterCallbacks

`ObRegisterCallbacks` registers pre-operation and post-operation filters on handle creation and duplication for specific object types. Cheats use it three ways:

1. *Defensive.* Strip `PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION`, or `THREAD_GET_CONTEXT` when anti-cheat opens the cheat process.
2. *Offensive.* Enumerate existing callbacks and re-register so the cheat's callback runs first, allowing it to override a legitimate filter.
3. *Communication.* Intercept handle requests that match a magic shape (target PID, desired access, duplication pattern, object type) and decode as a command.

**Supported object types (correction).** v5 listed many object types as supported; the correct supported set is narrower. On Windows 7 and later, `ObRegisterCallbacks` supports `PsProcessType` and `PsThreadType`. Windows 10 1607 and later add `ExDesktopObjectType`. File, Section, Event, and most other object types are *not* supported and the registration fails outright. Detection code that walks "all Ob callbacks across all object types" is searching in the wrong places: only these three matter for the cheat surface.

**Detection.** Enumerate Ob callbacks and altitudes for the three supported types. Validate callback target addresses and owning drivers. Check for suspicious altitude strings (callbacks that pick altitudes designed to run before known security-product altitudes), callback-order manipulation, and access-stripping behavior on opens of anti-cheat, EDR, protected-service, or protected-game processes. EDR, anti-malware, DLP, anti-cheat, and sandboxing products legitimately register here: ownership and behavior matter more than presence.

### 5.4 Minifilter Callback Registration

A minifilter registers pre- and post-operation callbacks via `FltRegisterFilter`. The cheat can use a fake or low-altitude minifilter and treat a magic file path, extension, operation type, or buffer length as a command trigger. When the magic operation appears, the callback handles the command and returns `FLT_PREOP_COMPLETE_REQUEST` so that the underlying file I/O never happens: the file path is purely a *trigger string*, not a real file.

This is closely related to §4.1 (Filter Manager communication port) but uses the *callback* path rather than the *port* path. A driver may use either or both.

The trigger can be surprisingly rich: normalized file name, stream name, create disposition, desired access, share mask, file attributes, EA length, reparse point behavior, read/write length, or final status. A UM helper can issue a create against `C:\ProgramData\Vendor\cache\{opcode}` and the file never needs to exist. The callback sees the path and metadata, decodes the command, completes the operation with a synthetic status, and the helper interprets that status as the reply.

The minifilter can also carry state through contexts: volume context, instance context, stream context, stream-handle context, or transaction context. A suspicious filter with no real file-security role but with context allocation on game-touched paths deserves attention.

**Detection.** Enumerate minifilter drivers, altitudes, operation callbacks, volume attachments, and contexts. Validate signer and plausible vendor role. Record major function, pre/post choice, normalized file name, final status, completion behavior, context allocation, and whether the same driver exposes a Filter Manager communication port (§4.1). Watch for minifilters that register callbacks but perform no plausible file-system function; a security minifilter that handles `IRP_MJ_CREATE` should be doing *something* observable in file telemetry. Correlate magic-path file operations from the protected process with callback firing on the unknown driver.

### 5.5 PoRegisterPowerSetting and PnP Notifications

Power-setting callbacks (`PoRegisterPowerSettingCallback`) and PnP notifications (`IoRegisterPlugPlayNotification`) deliver system lifecycle, device arrival/removal, and power-state changes. A cheat uses these as low-frequency signals or to coordinate initialization and teardown around anti-cheat startup.

Low frequency is the attraction. An IOCTL loop is loud; a power-state notification fires once when the system enters or leaves a state, which is plenty for "anti-cheat is starting" or "the DMA device just arrived."

The cheat pattern here is orchestration rather than payload transfer. A driver watches for display state, power profile changes, monitor on/off, docking events, USB/PCI arrival, interface registration, or surprise removal. The UM side causes or waits for one of these transitions and the KM side treats the callback as a phase gate. Hardware-assisted stacks use this to coordinate DMA device arrival, virtual HID readiness, or capture-card setup without maintaining a loud polling loop.

This channel is often invisible if defenders only look for continuous IPC. It fires at launch, device plug, display wake, lid/power events, docking transitions, or interface arrival and then goes quiet. That makes it ideal for "arm the DMA reader", "switch HID profile", "start capture pipeline", or "disable noisy telemetry while anti-cheat scans".

**Detection.** Inventory callback registrations where feasible. Store notification type, GUID/interface class, target callback pointer, owner driver, registration time, and actual notification sequence. Correlate unknown driver callbacks with device arrival/removal events near protected workload runtime, especially high-risk PCIe, USB HID, display, capture, and virtual device classes. Watch for power-setting GUIDs registered by drivers with no power-management role. Hardware drivers, OEM utilities, virtual input devices, and security products legitimately register here, so the signal must lean on owner role, callback target integrity, and pairing with device topology changes.

### 5.6 KeRegisterBugCheckCallback

Bugcheck callbacks run during crash processing. They are not a viable runtime channel; by the time the bugcheck callback runs, normal kernel services are gone. They are still useful for *cleanup*, *anti-forensics*, and *persistence hints*. A driver may register a bugcheck callback that wipes evidence, marks a state file, or alters crash-time artifacts before the dump is written.

`KeRegisterBugCheckReasonCallback` is more operationally interesting than the older raw callback form because it carries a reason and component string and can add secondary dump data. Legitimate drivers use this to preserve crash-relevant device state. A cheat can use the same path to leave a reboot marker, erase or distort its own diagnostic footprint, write misleading tagged data, or signal a loader after the next boot that the previous session ended under detection pressure.

The callback record itself becomes evidence: callback routine pointer, reason, component string, registration time, owner driver, and whether the driver deregisters on unload. Unknown runtime drivers should rarely need crash-dump enrichment. A driver that combines bugcheck callbacks with registry shielding, dispatch patching, or large-page shellcode is building an anti-forensics package rather than a normal telemetry feature.

Abuse markers include misleading component strings, dump data that looks encrypted or command-like rather than diagnostic, callbacks that survive driver unload attempts, and callbacks registered by drivers with no hardware or crash-diagnostics role. The interesting signal is not that the callback runs; it is that the driver prepared an anti-forensics path before a crash ever happened.

**Detection.** Enumerate bugcheck callbacks. Validate callback targets and owner drivers. Store reason type, component string, callback record address, owner module, dump-data size, and whether the same module registers other runtime surfaces. Storage, crash-dump, security, and platform drivers may register legitimately; unknown role-mismatched drivers in the bugcheck callback chain are suspicious, especially if the same driver has no other apparent legitimate function.

### 5.7 KeRegisterBoundCallback

Bound callbacks are an obscure, undocumented callback path used by the kernel to deliver `#BR` (Bound Range Exceeded) exceptions. They are legacy, rarely used by legitimate software, and useful to cheats as a *fallback trigger* surface: a place to put a callback that is unlikely to collide with any well-known security product's monitoring.

The channel value is scarcity. Because almost no modern software intentionally relies on x86 bound-range exceptions, a registered handler has a much smaller legitimate population than process, image-load, registry, or object callbacks. A cheat can use it as an emergency wake path: user mode or a controlled thread triggers the exception pattern, the kernel callback observes it, and the real payload moves elsewhere.

The risk is stability. This is not a mainstream, well-supported extension point, and build differences matter. That makes it unattractive for broad commodity deployment but attractive for bespoke, version-pinned stacks that want a callback list most defenders do not enumerate.

The channel is usually one-bit or event-only. The callback does not carry a large payload; it tells the real kernel component that a rare exception path was reached, then a section, registry value, or APC path does the actual work. That is why a bound callback should be scored as a hidden trigger, not as an isolated payload bus.

**Detection.** Inventory registered bound callbacks if the build exposes enough metadata. Validate callback target addresses, target function-entry status, owner driver, and registration timing. Correlate with unknown driver load time and exception telemetry. The legitimate population is essentially empty on modern Windows; any registration during protected workload runtime should be treated as high-confidence malicious or unauthorized activity until proven otherwise.

### 5.8 Callback Deep-Dive Matrix: Registration, Order, and Intent

Callbacks are powerful because they make the cheat look event-driven instead of polling. A detector needs to preserve three things for every callback: where the callback is registered, what order it runs in, and what user-mode action can trigger it.

**Ps process/thread/image callbacks (§5.1).** These callbacks form the startup timeline. A cheat uses them to learn when the launcher, game, anti-cheat service, protected process, overlay, or target DLL appears. For each callback slot, record decoded function pointer, callback block address, owner driver, registration generation if available, and whether the target bytes match the owning image on disk. For behavior, correlate callback firing with process/thread/image events and downstream actions such as mapping a section, opening a pipe, registering WFP state, or patching a dispatch table. A callback that does nothing visible until a specific anti-cheat DLL maps is much more suspicious than a generic EDR callback that observes all process events.

**Registry callbacks (§5.2).** Registry callbacks carry an altitude string and can filter before or after operations. Store altitude, owner, target function, target function-entry classification, gadget classification, callback context pointer, operation classes observed, raw value type, value data size, blocked paths, modified output parameters, and per-process deny behavior. A cheat trigger often watches one high-entropy path or one vendor-looking path and ignores the rest of the registry. The quieter variant watches for non-standard value types in `REG_SET_VALUE_KEY_INFORMATION` and treats the type field as an opcode. The stealthier variant registers a trusted-image gadget such as `jmp rcx` and places the real dispatcher behind the callback context. A defensive-shield callback often allows ordinary tools but denies anti-cheat PIDs, or returns inconsistent status depending on caller identity. These patterns require call-result telemetry, callback-context validation, and pre-operation telemetry, not just callback enumeration or after-the-fact hive scans.

**Object callbacks (§5.3).** Ob callbacks are about handle policy. Record object type, altitude, pre/post operation pointers, desired-access mask before and after callback, caller PID, target PID, and duplication source/target. A communication pattern is "open this target with magic access bits to signal a command"; a protection pattern is "strip access when the anti-cheat opens the protected process." The two patterns can coexist. The best test is controlled handle-open probing from a trusted anti-cheat process and a neutral process, then comparing how access masks are rewritten.

**Minifilter callbacks (§5.4).** Minifilter callbacks have rich context: altitude, volume instance, major function, pre/post operation choice, file name, normalized name, stream context, transaction state, and final status. A magic-path channel often completes the request early or returns a synthetic status so the underlying file never matters. Capture the file path and final status when workload-adjacent processes touch unusual names. If the same minifilter also exposes a communication port (§4.1), correlate the port messages with file-operation triggers.

**Power/PnP callbacks (§5.5).** These callbacks are low frequency but useful for hardware-assisted cheat orchestration. Record registered GUIDs, device-interface classes watched, owner driver, and actual notification sequence. A DMA or virtual HID cheat may use arrival/removal notification as a clean initialization trigger. The detection value is in pairing: unknown driver registers PnP notification, high-risk PCIe/HID device arrives, then a section/pipe/WFP channel appears.

**Bugcheck callbacks (§5.6).** Runtime channel value is low, but forensic value is high. Capture callback list, owner, reason type, callback buffer, and whether the driver also registers other suspicious runtime surfaces. Unknown bugcheck callbacks are not automatically malicious, but an unknown role-mismatched driver with a bugcheck callback, registry shield, and dispatch patch is a coherent anti-forensics package.

**Bound callbacks (§5.7).** The legitimate population is tiny, so treat registration itself as evidence. If present, validate target pointer and inspect whether the owner driver has any compiler/runtime feature that could plausibly use bound exceptions. Modern code almost never needs this path. Correlate registration with exception telemetry if available; a deliberate `#BR` trigger is a low-frequency command signal.

---

## 6. Driver Object and Dispatch Surface

A `DRIVER_OBJECT` is a small struct with very specific abuse value: it carries the `MajorFunction` dispatch table, the `FastIoDispatch` pointer, the device-object list, and a few other fields that influence how every I/O request reaches the driver. Patching any of them gives an attacker the ability to redirect entire categories of user-mode operations into its own code.

### 6.1 IRP MajorFunction Patch

Every `DRIVER_OBJECT` carries a 28-entry `MajorFunction` table. An attacker patches one or more entries in an *existing* legitimate driver object so that file operations or IOCTLs against that driver are diverted into attacker-controlled code. The user-mode side opens the legitimate device and sends what looks like an ordinary file or IOCTL request.

Common targets are `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL`, `IRP_MJ_READ`, and `IRP_MJ_WRITE`. The traffic appears to target a legitimate driver; no new suspicious device object is required. Implementation is easy, reliability is high, and the surface has been the workhorse of mid-tier game cheats and commodity signed-driver abuse for years.

#### Attacker Mechanics: Borrowed Dispatch as a Front Door

An IRP dispatch channel has three actors: the visible user-mode opener, the borrowed driver object or device stack, and the hidden handler that actually interprets selected requests. The user-mode operation does not have to look malicious. It can be an open, close, read, write, query, or device-control request against a path that already exists on the system. The patched dispatch entry or swapped routing object turns that ordinary operation into a private front door.

The reason this pattern remains common is that it solves two practical attacker problems at once. First, it avoids creating a new `\Device\Cheat`-style object whose name, ACL, and IOCTL set are easy to inventory. Second, it borrows legitimacy from a driver that already receives traffic from user mode. A detector that only asks "which device did the protected process open?" sees a known device. The real question is "where did the request go after the I/O manager reached the driver object or file object?"

The protocol fields can be spread across normal IRP metadata:

1. *Create path and options.* `IRP_MJ_CREATE` can use file name suffix, create disposition, share mask, desired access, or extended attributes as a selector. A failed open can still be a successful command if the hidden handler returns a chosen status.
2. *IOCTL code and transfer shape.* `IRP_MJ_DEVICE_CONTROL` naturally exposes an IOCTL code, input length, output length, transfer method, and output status. Even when the visible IOCTL looks unsupported, the hidden handler can treat those fields as command grammar.
3. *Read/write length and offset.* Reads and writes against a borrowed device can encode command IDs through length, offset, alignment, or repeated size patterns while the actual payload lives in a shared buffer.
4. *MDL and buffer provenance.* Direct I/O or internal I/O paths give the hidden handler an MDL or system buffer that can become a one-time bootstrap for a longer-lived mailbox.
5. *Completion status as reply.* `IoStatus.Status`, `IoStatus.Information`, completion routine timing, and output-buffer length form a compact reply plane. This is especially useful when user mode expects device-specific failure codes.

Higher-skill variants reduce global blast radius. Instead of patching a whole driver's dispatch table, they redirect only one file object, one socket, one device instance, or one completion path. This makes the channel harder to catch with simple driver-object baselines, but it also creates a more specific object-relationship anomaly: one handle or one file object no longer routes through the stack it claims to represent.

#### Existing-Driver Stack Proxy and `IRP_MJ_INTERNAL_DEVICE_CONTROL`

UnknownCheats-style discussions often frame this as "do not expose your own IOCTL device; proxy through something that already exists." The deeper pattern is not limited to `IRP_MJ_DEVICE_CONTROL`. Windows uses `IRP_MJ_INTERNAL_DEVICE_CONTROL` for communication between paired or layered kernel-mode drivers, especially class/port stacks such as keyboard, mouse, storage, video, and bus drivers. User mode does not normally send internal IOCTLs directly, but a cooperating or hijacked kernel component can build an internal-device-control IRP to a legitimate lower driver and encode state in the IOCTL code, input buffer shape, MDL, completion timing, or output status.

That gives the attacker three camouflage options:

1. *External-looking user-mode trigger, internal kernel path.* UM opens a benign device or performs a normal operation. A patched `IRP_MJ_CREATE`, `IRP_MJ_DEVICE_CONTROL`, fast I/O entry, callback, or `.data` pointer sees the trigger and then sends an internal IOCTL down an existing stack. The durable command path is no longer the user-mode IOCTL; it is a driver-to-driver IRP.
2. *Class/port stack piggybacking.* HID, Mouclass/Kbdclass, storage, ACPI, display, and bus stacks already exchange internal IOCTLs. An attacker-controlled filter can hide command state in otherwise plausible internal requests, especially if defenders inventory only user-mode `DeviceIoControl` calls.
3. *Completion-status mailbox.* The lower stack does not need to understand the command. The attacker-owned filter can complete an internal request early, rewrite `IoStatus.Status`, `Information`, or an output buffer, and use the completion as a small reply path. This is especially quiet when the triggering user-mode operation expects occasional `STATUS_NOT_SUPPORTED`, `STATUS_BUFFER_TOO_SMALL`, or device-specific failures.

This matters because "no suspicious device handle" is not proof that driver communication is absent. A UM event can be only the front door. The real protocol may run between drivers after the first hook fires.

**Detection.** This is one of the cheapest and highest-yield checks a kernel detector can run:

1. Enumerate every loaded `DRIVER_OBJECT`.
2. For each `MajorFunction` pointer, validate that the target belongs to the owning driver's image (`SECTION_IMAGE` range) or an allowlisted filter path.
3. Alert if the target lands in an unknown module, pool memory, executable heap, or another unrelated driver.
4. Capture a baseline at boot and compare at protected workload launch.

Legitimate filter stacks attach devices rather than patching dispatch tables directly. Historically a few old security products patched dispatch tables, so a small allowlist may be necessary, but the legitimate population is very small.

For the internal-IOCTL proxy case, add device-stack provenance rather than only dispatch-pointer provenance. Record `IRP_MJ_INTERNAL_DEVICE_CONTROL` handlers, internal IOCTL codes observed during protected workload runtime, source and target device objects, top-of-stack driver, completion routine address, MDL presence, input/output lengths, status codes, and whether the request was built by an expected class/filter driver. A mouse filter issuing internal keyboard requests, a storage filter issuing video-stack internal requests, or an unknown role-mismatched driver building internal IRPs into a stack it does not own is a strong anomaly. Legitimate class and port drivers are chatty during PnP/startup; command channels tend to be sparse, workload-coupled, fixed-size, and paired with a separate user-mode trigger.

#### File-Object DeviceObject Swap and AFD Socket Channels

Black Hat USA 2020's "Demystifying Modern Windows Rootkits" describes a more selective alternative to patching a global dispatch table: redirect the `DeviceObject` pointer inside a specific `FILE_OBJECT`. The rootkit-focused example targets socket handles backed by AFD, the Ancillary Function Driver for Winsock. Instead of changing `\Driver\Afd`'s `MajorFunction` table or placing a code hook in AFD, the attacker changes the per-file-object routing so I/O for one chosen socket reaches attacker-controlled device/driver state first.

**Presented case note.** The communication technique in the Black Hat example is not "open a hidden socket" or "patch AFD globally." It is per-handle route substitution. A normal-looking socket handle becomes the rendezvous object, the `FILE_OBJECT->DeviceObject` relationship becomes the control edge, and ordinary socket IRPs, completion status, packet timing, or stream bytes become the selector/reply plane. The evidence fields are therefore socket handle, file object, observed device object, expected AFD stack, endpoint tuple, owning process, creation time, and whether only one workload-adjacent socket diverges from the normal AFD route.

This is highly relevant to game cheats because it removes the obvious artifacts defenders usually hunt:

1. *No custom device handle.* User mode can hold what appears to be an ordinary socket handle.
2. *No global AFD dispatch patch.* `\Driver\Afd->MajorFunction` can remain clean.
3. *No suspicious listening port is required.* The channel can ride loopback traffic, a legitimate service connection, a launcher/updater connection, or a BITS-like background transfer pattern.
4. *Per-socket selectivity.* Only the chosen socket file object is redirected. Other sockets and system-wide network behavior remain normal.
5. *Protocol camouflage.* The packet stream can look like ordinary TCP or loopback traffic while a magic constant, header shape, timing pattern, or completion status acts as the command selector.

The effective channel is therefore not "network C2" in the usual sense. It is a file-object routing channel. The UM side creates or receives a normal socket. The kernel-side component identifies the target socket file object, redirects its `DeviceObject` relationship to an attacker-controlled device object, and handles selected IRPs or IOCTLs before forwarding ordinary traffic to the original AFD path. The packet bytes, receive completion, socket status, or read/write timing become the command bus. An attacker can use this to receive commands through a legitimate local service port, to exfiltrate results through normal application traffic, or to hide a loopback control plane behind ordinary Winsock activity.

The detection mistake is to validate only driver-object dispatch pointers. That misses this class because the corrupted pointer is in a `FILE_OBJECT`, not the global `DRIVER_OBJECT`.

**Detection.** For high-risk processes, inspect socket handles as objects, not only as network endpoints. Resolve each socket handle to its `FILE_OBJECT`, record the `FILE_OBJECT->DeviceObject`, device stack, driver object, dispatch target, endpoint tuple, owning process, handle source, and creation time. For AFD sockets, the related device object should belong to the expected AFD device stack or to an explainable, loaded, signed network filter path. Flag socket file objects whose `DeviceObject` points to an unrelated driver, pool-created object, fake driver object, or device object that does not appear in the normal AFD stack. Correlate with ETW TCP/IP, handle-table telemetry, and driver-object validation: "AFD dispatch table clean" plus "one protected-process or helper-owned socket file object routes to an unknown device object" is exactly the interesting case. Store the original and observed device-object chain when possible, because an attacker may restore the pointer on cleanup or scan windows.

### 6.2 FastIoDispatch Pointer Patch

File-system and storage-related drivers expose a `FastIoDispatch` table: a parallel dispatch path for high-frequency operations that bypass the IRP dispatch. An attacker patches entries (fast read, fast write, fast query, fast device control) to divert operations through attacker-controlled code without going through `IRP_MJ_*`.

This is checked less often than `MajorFunction`. The same logic applies: every entry must target the owning module or a legitimate stack, and any cross-module or pool-pointed target is a strong signal.

The reason this matters is coverage asymmetry. Many anti-cheat drivers validate `MajorFunction` entries but skip `FastIoDispatch`, while the I/O manager and file systems may consult fast I/O paths for cache-friendly operations. A patched fast I/O routine gives the attacker a less-watched trigger tied to ordinary file activity. The user-mode side can open/read/query a legitimate file or device path and reach the patched table entry without a custom IOCTL.

**Detection.** Enumerate drivers with non-null `FastIoDispatch`. Store table address, populated entries, entry target module, section, symbol/function-entry status, and owning driver class. Verify each entry address belongs to the owning module or expected file-system stack. Flag unexpected cross-module pointers or pointers into pool memory and private executable mappings. Also flag table pointers that live outside the owning driver's static image when the driver has no documented reason to allocate a dynamic fast I/O table. The false-positive population is filesystem and security-product specific, and is small.

### 6.3 Driver Object Extension

`IoAllocateDriverObjectExtension` attaches extension data to a `DRIVER_OBJECT` under a client identification address. An attacker attaches data to a legitimate-looking driver object and later retrieves it using the same client ID. The data can hold keys, pointers, state flags, or a rendezvous descriptor: anything the attacker wants to keep associated with an existing kernel object rather than in its own driver's globals.

The user-mode side does not read driver-object extensions directly; instead, a companion kernel path retrieves the extension or observes behavior that depends on it. The surface is therefore a *KM state hiding* primitive more than a UM-facing channel: but it routinely bootstraps other channels by serving as the rendezvous descriptor.

Microsoft documents that the extension is resident storage, accessible from any IRQL, keyed by `ClientIdentificationAddress`, and automatically freed when the driver object is deleted. Those properties are attractive for covert state: no named object, no pool tag that clearly belongs to the attacker, no user-mode handle, and automatic cleanup tied to a trusted-looking driver object. An attacker can store the original dispatch pointers it patched, the current shared-section descriptor, encryption keys, callback cookies, or the address of the real handler hidden behind a trusted gadget.

The abuse becomes stronger when the target driver object is not the attacker's own object. Attaching state to a system, storage, GPU, null, ACPI, or vendor driver creates misleading locality: a memory walker sees data reachable from a legitimate driver object and may not attribute it to the driver that allocated it.

**Detection.** Enumerate driver-object extensions where practical (the structures are reachable from a kernel walker but not exposed through documented APIs). Validate extension owner identity and the relationship between owning driver and target driver. Store target driver object, client identification address, extension size, allocation time if available, and data-shape hints such as embedded kernel pointers or section descriptors. Alert when unknown drivers attach data to unrelated system drivers: that pattern is rare in legitimate driver development.

### 6.4 ntoskrnl Multi-Stage Chain Hook

Naive `MajorFunction` and `.data` pointer validation checks ask "is the target inside `ntoskrnl`?". A multi-stage chain hook satisfies that check on the first hop while ultimately branching to attacker-owned code. The intermediate stages stay within legitimate-looking kernel ranges; the final stage branches out.

```text
   patched dispatch entry
            |
            v
   trampoline 1   <- inside ntoskrnl .text alignment slack
            |
            v
   trampoline 2   <- inside hal .text or a signed driver
            |
            v
   attacker code  <- outside any signed module
```

**Detection.** Do not stop at first-level range validation. For high-risk pointers, disassemble the target's first few instructions and chase short branch chains. Compare target bytes and short-range control-flow against a clean build. Randomize scan timing: an attacker that restores the chain between scans can be caught when the scan windows are not predictable.

HVCI plus Memory Integrity reduce the available alignment slack and constrain the attacker to using legitimate function ranges as trampoline anchors. The signature shifts from "target outside any signed module" to "target inside a signed module but not at any function entry point that the on-disk image declares." The latter check is more expensive but is the durable detection.

### 6.5 Dispatch Deep-Dive Matrix: Pointer Ownership and Call-Chain Reality

Driver-object abuse is the most production-relevant kernel channel family because it converts ordinary user-mode opens, reads, writes, and IOCTLs into attacker-controlled execution. The defender must answer four questions for every dispatch-like pointer: who owns the object, where does the pointer land, is that address a valid entry point, and what does the first control-flow chain do.

**IRP `MajorFunction` patches (§6.1).** Each entry should normally point into the owning driver image and usually to a small set of stable dispatch routines. A detector should store driver object address, driver name, service key, image path, image base/size, dispatch index, target address, target module, target section, and whether target bytes match disk. Also store the device object path that user mode opens. The high-confidence pattern is a legitimate device path whose `IRP_MJ_DEVICE_CONTROL` or `IRP_MJ_CREATE` entry points into unrelated driver code, executable pool, or an address that is inside the owning image but not at a known function boundary.

**Internal-device-control stack proxies (§6.1).** Treat `IRP_MJ_INTERNAL_DEVICE_CONTROL` as a driver-to-driver command surface, not just implementation detail. Record IOCTL code, source driver, target device stack, top and lower device objects, completion routine, MDL, buffer sizes, caller thread/process context, and final status. Legitimate internal IOCTLs usually follow PnP/start/connect flows and stay within a class/port stack. Suspicious ones appear after a workload-adjacent trigger, repeat with fixed-size opaque buffers, traverse unrelated stacks, or complete in an unknown filter before the lower device sees the request.

**Fast I/O patches (§6.2).** `FastIoDispatch` is lower-noise than IRP dispatch because many drivers never use it. If non-null, validate every populated routine pointer, not just the table pointer. Record table address, table size, populated entries, owning module, and whether the driver class plausibly uses fast I/O. A random non-file-system driver with a populated fast I/O table is suspicious. A file-system/security driver with one entry redirected to pool memory is stronger evidence than a noisy IOCTL trace because fast I/O paths are not normally patched by third-party filters.

**File-object device swaps / AFD socket channels (§6.1).** Add per-handle object validation to the dispatch program. For socket handles, record `FILE_OBJECT`, `DeviceObject`, owning driver, endpoint tuple, process, handle source, and whether the device object belongs to the expected AFD stack. A swapped file object's global driver table may be clean; the anomaly lives in the relationship between one file object and one device object. This check should be sampled for game, helper, launcher, overlay, browser, updater, and suspicious service processes, because the socket can be owned by a broker rather than by the game itself.

**Driver-object extensions (§6.3).** Extensions are not usually a direct UM channel, but they are excellent hidden state. Treat them as rendezvous descriptors: stored keys, original pointer backups, target object addresses, or channel metadata. Record extension client ID, target driver object, extension size, allocating driver, and whether the target driver has any legitimate relationship with the allocator. The suspicious shape is an unknown driver attaching extension data to `\Driver\ACPI`, `\Driver\Disk`, `\Driver\Null`, a GPU driver, or a security-product-adjacent driver without owning that stack.

**Multi-stage chains (§6.4).** Range checks are necessary but insufficient. The scanning algorithm should classify each pointer as: outside loaded images; inside image but not executable; inside executable section but not at a symbol/function entry; inside function entry with bytes matching disk; or inside executable section with modified bytes / short branch chain. For high-risk pointers, disassemble through unconditional branches, import thunks, hotpatch prologues, and short trampolines until the chain reaches a stable function body or leaves the trusted set. Store the full chain in evidence. "Pointer inside ntoskrnl" is not clean if instruction 2 is a jump into a non-image allocation.

---

## 7. Kernel `.data` Pointer Surface

PatchGuard's classic coverage is over kernel `.text` (code) and a specific list of structures: the SSDT, KdpStub, the IDT, the GDT, and selected critical pointers. A great deal of the kernel's behavior is *also* controlled by writable function pointers in `.data` sections, and most of those pointers are *not* on PatchGuard's coverage list. Replacing one of them with a trampoline gives an attacker a normal-looking OS path that ends in attacker-controlled code, with no code modification and no SSDT trace.

This section walks the pointers that matter, in roughly increasing order of subtlety.

### 7.1 Generic `.data` Function Pointer Hooks

Many kernel and driver structures hold function pointers in writable data sections. The pattern is identical regardless of which structure: the cheat replaces a pointer with a trampoline, stores the original, and forwards normal calls. The choice of pointer determines what user-mode operation acts as the trigger.

The important distinction is *registration semantics*:

1. *Static pointer.* Initialized during boot or driver load and should never change after initialization. Post-boot change is high severity.
2. *Registration-backed pointer.* May change, but only through a documented API that produces a visible registration record, cookie, object, altitude, GUID, or provider entry.
3. *Cache pointer.* May change as part of normal OS operation but must still point into a narrow set of expected modules and object lifetimes.
4. *Callback array entry.* Looks like arbitrary data but is conceptually a callback list; the right evidence is owner, order, context pointer, and unregister path.

The attacker prefers category confusion. A pointer that looks like a cache pointer but is actually a control pointer is less likely to be baselined. A registration-backed pointer changed by raw memory write creates no cookie, no registration event, and no owner. A static pointer redirected to a branch gadget inside a trusted image passes naive range validation.

**Detection.** Baseline high-risk `.data` function pointer tables under known-clean conditions. Validate pointer targets against expected module ranges and, where possible, against expected per-function entry points from the on-disk image. Monitor writable data sections for unexpected executable-looking pointer values. Use symbol-guided checks where symbols are available. For every pointer, store old value, new value, owning section, expected writer, observed writer if telemetry exists, target module, target symbol, and first-hop disassembly. A pointer that changes without a corresponding documented registration event should be investigated even if the new target lands inside a signed module.

#### Field-Observed: "Data Ptr Called Function" Channels

UnknownCheats threads and related public repositories repeatedly describe this family as "driver communication using a data pointer called function." The important defensive lesson is the naming: the attacker is not trying to hook a famous exported routine. They are looking for any writable pointer that is *indirectly called by a user-triggerable kernel path*. The UM side then calls a normal syscall or Win32k/D3DKMT wrapper whose kernel path eventually dereferences that pointer. The pointer target becomes a dispatcher, and one of the syscall arguments carries a pointer to a command structure, a magic value, or a shared-memory descriptor.

The common trigger families are:

1. *Ntoskrnl/HAL data-pointer calls.* `NtConvertBetweenAuxiliaryCounterAndPerformanceCounter` reaching a HAL dispatch slot is the canonical public example (§7.2), but the same search strategy applies to other writable indirection cells reached from native syscalls.
2. *Win32k / session-state pointer calls.* GUI and graphics syscalls in `win32u.dll` route into `win32kbase`, `win32kfull`, and session-specific state. Older public material focused on fixed `.data` cells; newer Windows 11 chatter increasingly targets nested session-state pointer chains because fixed offsets move or become guarded. From the defender's perspective both are the same artifact: a writable control pointer inside the GUI subsystem is changed without a documented registration path.
3. *Dxgkrnl / graphics dispatch tables.* D3DKMT wrappers reach Win32k and dxgkrnl indirection tables. A single graphics syscall can therefore act as a trigger into a KMD or cheat trampoline while looking like ordinary render traffic (§9.6).
4. *Existing-driver data pointers.* Vendor and system drivers often hold callback, operation, or interface pointers in writable sections. If user mode can trigger the operation through a normal device path, the pointer becomes a no-new-device communication channel.

The protocol usually has the same compact shape: first argument or one pointer-sized argument points at a command block; one integer argument carries a magic or opcode; the hook validates `PreviousMode == UserMode` or validates the caller process; the hook copies a small amount of user memory; the original target is called for non-matching traffic. A detector should not rely on the exact magic, target symbol, or forum-released slot. Those change quickly. The stable signal is a post-boot writable control-pointer change plus a user-mode trigger path whose arguments suddenly look like a private ABI.

**Detection.** Build a "callable writable pointer" manifest rather than a "known bad slot" list. For each candidate pointer, store section, symbol/RVA, expected target, expected mutability class, user-mode trigger path if known, and whether the target is a function entry. At runtime, record pointer diffs, first-hop disassembly, branch-chain target, caller syscall or Win32k/D3DKMT operation, argument sizes, and caller process. A pointer that changes to an address inside a signed module but not to a valid entry point should be treated like a trampoline, not as clean. A pointer that remains inside the expected module but is paired with a `jmp rcx` / `call rcx`-style gadget and attacker-controlled context should be classified with the callback-context gadget pattern (§5.2).

Some legitimate drivers register callbacks at documented extension points; the discriminator is "is this pointer documented, owned by the correct module, and changed through an expected registration path." A pointer that is documented as registration-only but changed via an arbitrary write is high severity.

### 7.2 HalPrivateDispatchTable

`HalPrivateDispatchTable` is a kernel data structure containing HAL-related function pointers. One historically named slot, `xKdEnumerateDebuggingDevices`, is reachable from user mode via `NtConvertBetweenAuxiliaryCounterAndPerformanceCounter`, which makes it a particularly clean trigger surface: UM issues an ordinary syscall, KM walks `nt!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter`, the dispatch lands on a `HalPrivateDispatchTable` slot, and the slot dereference reaches the cheat trampoline.

**Slot name vs. actual function.** The slot name is historical. On modern Windows, the function stored in that slot is commonly related to auxiliary counter conversion (something like `HalpTimerConvertAuxiliaryCounterToPerformanceCounter`). The mismatch between the old slot name and the actual function is one reason cheat developers identified this slot as an interesting target: it is documented in pdb metadata under a name that no defender naturally associates with the syscall path that reaches it.

**Call flow.**

```text
UM:
    NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(...)
        |
        v
KM:
    nt!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter
        |
        v
    HalPrivateDispatchTable[slot] dereference
        |
        v
    original HAL routine, or cheat trampoline
```

**Detection.** Resolve `HalPrivateDispatchTable` via symbols or verified build metadata. Validate known high-risk slots against expected HAL/kernel module ranges. Compare boot baseline to protected-runtime values; treat any pointer landing in unknown driver memory as P0. Then *do not stop at the first hop*: apply the chain check from §6.4. A multi-stage chain that lands at `hal!HalpFoo` on the first dereference but reaches attacker-controlled code two trampolines later is the modern presentation.

### 7.3 SeSiCallback and Security Callback Pointers

Security-related internal callback pointers are attractive as `.data` control points because they are not part of any ordinary driver IOCTL surface and they fire on token, logon, or security-descriptor operations rather than on high-frequency I/O. `SeSiCallback`-style paths can be triggered through normal user-mode security operations.

The value is trigger camouflage. User mode can perform ordinary operations such as opening tokens, querying security descriptors, impersonation setup, logon/session queries, or access checks. If a writable security callback pointer has been redirected, those normal operations become a kernel dispatch path. The attacker gets a trigger that looks like security bookkeeping, not file/device I/O.

The fragility is build knowledge. These are not broad public registration APIs; private layout, symbol quality, PatchGuard coverage, and call graph changes matter. A robust cheat pins the technique to specific builds and falls back to other channels when the pointer is protected or moved.

The protocol shapes are narrow but useful:

1. *Token query trigger.* UM opens or queries a token with a magic access mask.
2. *Security descriptor trigger.* UM asks for a descriptor on a chosen object and the redirected path sees the object type and access request.
3. *Impersonation trigger.* UM toggles impersonation state; KM observes the security transition.
4. *Access-check trigger.* UM causes a predictable access check whose subject/context encodes a selector.

The channel is not high-bandwidth. It is a stealth trigger that routes execution through security bookkeeping and then dispatches to another payload surface. This matters for detection because the anti-cheat should correlate pointer integrity with the initiating security operation rather than looking for file, socket, or IOCTL activity.

**Detection.** Build a list of internal security callback pointers that are stable enough to inspect per build. Validate target addresses against expected modules and function entries. Monitor for post-boot changes and chain-walk suspicious targets. Record token operations, security-descriptor queries, impersonation transitions, access-check cadence, caller PID/TID, target object, desired access, and resulting status. Correlate with token or security-descriptor operations issued by the protected process; an attacker that wants to drive the surface from UM has to perform *some* security operation, and the operation pattern is often distinctive.

### 7.4 ObTypeIndexTable Method Hijack

On Windows 7 and later, `_OBJECT_HEADER->TypeIndex` indexes `nt!ObTypeIndexTable`. Each entry is an `_OBJECT_TYPE` whose initializer contains procedure pointers: open, close, parse, delete, query-name, okay-to-close, security, dump:

```cpp
typedef struct _OBJECT_TYPE_INITIALIZER
{
    // ...
    POBJECT_DUMP_PROCEDURE          DumpProcedure;
    POBJECT_OPEN_PROCEDURE          OpenProcedure;
    POBJECT_CLOSE_PROCEDURE         CloseProcedure;
    POBJECT_DELETE_PROCEDURE        DeleteProcedure;
    POBJECT_PARSE_PROCEDURE         ParseProcedure;
    POBJECT_SECURITY_PROCEDURE      SecurityProcedure;
    POBJECT_QUERY_NAME_PROCEDURE    QueryNameProcedure;
    POBJECT_OKAY_TO_CLOSE_PROCEDURE OkayToCloseProcedure;
    // ...
} OBJECT_TYPE_INITIALIZER;
```

Most object types use only a subset of these procedures. The unused slots are a broad, weakly monitored `.data` hook surface. A cheat replaces a procedure pointer on a *rare* object type, forwards normal behavior where needed, and triggers the hook through ordinary object-manager operations.

**TypeIndex obfuscation (correction).** The raw `TypeIndex` byte in `_OBJECT_HEADER` is *obfuscated* on Windows 10 and later. To recover the real type index, XOR with `nt!ObHeaderCookie` (a random per-boot byte) and with the second byte of the object header address:

```cpp
UCHAR RealIndex = (UCHAR)(
    ObjectHeader->TypeIndex
    ^ ObHeaderCookie
    ^ (UCHAR)(((ULONG_PTR)ObjectHeader >> 8) & 0xFF)
);
POBJECT_TYPE Type = ObTypeIndexTable[RealIndex];
```

Detection code that parses object types directly must apply this decoding before indexing `ObTypeIndexTable`. On Windows 7 and 8 the raw byte is the index and no XOR applies; on Windows 10 and later, skipping the XOR step lands on the wrong slot and the result is either a bugcheck, garbage, or a silent false negative. v6 omitted this entirely, which is the omission v7 corrected.

**PatchGuard.** Windows 22H2 and later protect some high-value object-type paths more strongly. `PsProcessType` and `PsThreadType` are higher risk for the attacker; rare types (Profile, Transaction Manager, low-frequency types) remain the more practical surface: but coverage shifts by build, and attacker communities track those shifts more closely than most defenders.

**Detection.** Capture a boot baseline of object-type procedure pointers (after applying the cookie correction). Validate each pointer target against expected kernel module ranges. Compare at protected workload launch and periodically. Treat unexpected procedure changes as high severity unless an allowlisted security product accounts for them.

### 7.5 ApiSetSchema Redirection

The ApiSet schema maps `api-ms-*` and `ext-ms-*` logical DLL names to concrete host DLLs. `PEB->ApiSetMap` points to the schema; the loader consults it during import resolution and `LoadLibrary`. A cheat redirects resolution by replacing or modifying the schema pointer or content, so that a selected ApiSet name resolves to a cheat-controlled DLL or path.

This is a UM-targeted surface that KM commonly helps set up: the KM driver does the write into the protected process's PEB or schema region, and the UM loader does the rest. It is useful for delaying code load until a later import event and for swapping a normal-looking DLL for attacker-controlled code.

There are two common shapes:

1. *Pointer replacement.* `PEB->ApiSetMap` is changed to point at a copied schema in private memory. Only one or a few namespace entries are modified.
2. *In-place schema tamper.* The pointer remains normal but backing memory is made writable, patched, and restored. This is less visible to pointer checks but visible to protection-change and content-hash checks.

The command-channel angle is delayed execution. UM does not need to open a device or pipe. It loads a logical DLL name, the loader consults the schema, and the modified host mapping decides whether to land in a clean DLL or cheat-controlled code. KM can use this as a one-time activation path after anti-cheat initialization has already passed.

**Limits.** `PEB->ApiSetMap` usually points to read-only mapped memory. Writable modification is visible if memory-protection changes are monitored. Some anti-cheat products already validate this pointer. Loader behavior is also fragile: a malformed schema can crash process startup or break unrelated imports.

**Detection.** Compare `PEB->ApiSetMap` against the normal system mapping. Validate that ApiSet host DLLs resolve to expected system DLLs. Store pointer address, VAD backing, memory protection, section name, schema version, namespace count, value entries, and a hash of high-value mappings. Alert on schema memory outside expected read-only shared regions, in-place content differences, and host DLL paths that resolve outside system directories. Correlate with suspicious DLL load events and kernel writes into PEB memory. Compatibility shims and instrumentation tools may legitimately affect loader behavior; in a protected process, ApiSet redirection should be rare unless an allowlisted product owns it.

### 7.6 `.data` Deep-Dive Matrix: Writable Control Pointers

Writable control pointers are dangerous because they do not require code patching. The attacker changes data, the kernel executes through data, and simple `.text` integrity checks remain clean. A production detector should maintain a per-build manifest of high-risk writable function pointers: symbol name, RVA, expected target module, expected target symbol, PatchGuard risk, registration path, and whether the pointer may legitimately change after boot.

**Generic `.data` pointer hooks (§7.1).** The generic workflow is pointer discovery, original pointer save, replacement with a trampoline, and trigger through a normal OS path. Detection should split pointers into three buckets: static boot-time pointers that should never change; registration-backed pointers that may change only through documented APIs; and cache/state pointers whose values vary but must still point into expected modules. Only the first two are good block-grade targets. For each changed pointer, store old value, new value, writing thread if known, owning section, and whether the new target is executable image code.

**"Data ptr called function" channels (§7.1).** The forum-observed version is a callable writable pointer with a normal syscall or Win32k/D3DKMT trigger. For each high-risk pointer, add the trigger API/syscall, argument positions that can carry a user pointer, expected caller population, and target function-entry status. The best evidence package is a pointer diff, a trigger call from the attacker helper, an argument block with private ABI shape, and a first-hop chain that reaches unknown code. Avoid brittle slot-only IOCs; the slot changes, the callable-writable-pointer shape does not.

**`HalPrivateDispatchTable` (§7.2).** This table needs special treatment because it provides syscall-reachable function-pointer slots. Capture the full table baseline, but prioritize slots reachable from user-mode system calls or high-frequency kernel APIs. Chain-walk each changed slot. If the first target is inside HAL/nt but the bytes differ from disk, or the first target immediately branches out to another driver, treat it like a dispatch hook. The operational mitigation is not to ban on a single weird HAL pointer alone; pair it with the user-mode trigger path (`NtConvertBetweenAuxiliaryCounterAndPerformanceCounter`) and helper activity.

**Security callback pointers (§7.3).** Security subsystem pointers have fewer legitimate third-party writers. Build-specific symbol validation is mandatory because private symbols and layout drift can produce false positives. The evidence needs a post-boot change plus a trigger pattern: token open/query, access-check, logon/session operation, or security-descriptor query from a workload-adjacent process. If no trigger pattern exists, keep the finding as integrity telemetry until corroborated.

**Object-type procedure hooks (§7.4).** The object manager gives attackers many low-frequency callbacks. For each `_OBJECT_TYPE`, record procedure pointer values and object type name after correctly decoding `TypeIndex` on Windows 10+. The likely attacker choice is a rare type because process/thread types are watched more heavily. Detection should score unused-procedure population, target module mismatch, and procedure pointer changes after boot. Also collect the user-mode object operation that could trigger it: open, close, query name, security query, or okay-to-close. This turns an obscure pointer diff into a reproducible evidence path.

**ApiSet redirection (§7.5).** Although this is user-mode loader state, kernel assistance makes it relevant to this document. Capture `PEB->ApiSetMap` address, memory protection, VAD backing, section name, and a hash of the schema header and namespace entries. Then resolve a small set of high-value ApiSet names and compare hosts against a clean process on the same build. A mismatch is meaningful only if the schema pointer or backing memory is abnormal; ordinary SxS, packaged-app, or shim behavior can change DLL load graphs without touching ApiSet state.

---

## 8. Memory-Backed Bidirectional Channels

The channels in §2 to §7 are predominantly *signal* channels: a few bytes of trigger, a few bytes of command, a single pointer reassignment. Real attacker stacks need *payload* channels too: places to move multi-kilobyte memory dumps, render buffers, process state, configuration, and scan results. The natural answer is shared memory, and Windows offers many varieties of it. The attacker's choice among them is driven by attribution friction and integrity coverage, not by raw bandwidth.

### 8.1 Kernel-Created Section

A kernel driver creates a section object with `ZwCreateSection` (or `MmCreateSection` for variants) and maps it into the protected process address space via `ZwMapViewOfSection`. Both sides then share memory directly. The driver implements a ring buffer, mailbox, or command structure inside the section; user mode reads and writes the same buffer.

This is high bandwidth, simple, bidirectional, and requires no repeated syscalls after the initial map. It is also, when the attacker is careless, one of the most visible artifacts in the protected process: an unnamed section with RW protection appearing in the VAD list.

#### Attacker Mechanics: Section as Shared Mailbox

The section is rarely just a raw byte dump. Mature implementations treat it as a shared-memory transport with a small control header and one or more data regions. The header usually contains a magic value, protocol version, total size, generation, producer index, consumer index, current command, status, flags, heartbeat, and sometimes a nonce or integrity field. The data region may be a single command buffer, a fixed-slot queue, or a ring buffer with variable-length records.

The attacker gets several design choices:

1. *Single mailbox.* One command slot and one reply slot. Simple, low overhead, and enough for configuration, pointer queries, and short command/response flows.
2. *Ring buffer.* Producer and consumer counters let UM and KM stream many records without a syscall per command. This fits memory-scan results, entity snapshots, telemetry, and overlay data.
3. *Split control/data.* A small always-mapped control page carries sequence and status fields, while larger pages are mapped only when needed or are addressed by offsets. This reduces noisy writes to large buffers.
4. *Double-buffered snapshots.* One side writes into an inactive buffer, flips an epoch, and the other side consumes a stable snapshot. This avoids locking around high-rate game-state, process-state, or telemetry reads.
5. *Descriptor mailbox.* The section only carries descriptors for other resources: MDL-backed buffers, GPU shared handles, ALPC views, socket tokens, or firmware-table request IDs.

Synchronization is where many channels reveal themselves. A simple implementation polls a status field at frame rate. A quieter one pairs the section with an event, ALPC message, `WaitOnAddress`, thread-pool wait, APC, or completion queue. The section is the payload plane; the wake edge often lives in another chapter of this document. That split is intentional: a defender may see an event with no data or a section with no obvious signal unless both are correlated.

Attackers also use sections for role separation. A short-lived loader can create or duplicate the section, a workload-adjacent helper can own the visible handle, and the kernel component can map or write the pages without exposing its own device object. The name may be absent, random, vendor-looking, or inherited from a legitimate broker process. Reverse engineering should ask more than "is there a section?" Track who created it, who mapped it, who writes which offsets, and which other trigger wakes the reader.

**Detection.** Enumerate mapped sections in the protected process via `NtQueryVirtualMemory` or the VAD tree. The signals stack:

1. *Identity.* Section is not backed by a normal file or known shared-memory object (page-file backed, anonymous).
2. *Protection.* RW (or RWX, though that is increasingly rare under HVCI).
3. *Source.* Creator process or driver is unknown, recently loaded, or unsigned.
4. *Behavior.* Memory content updates with a command-like cadence: periodic writes at regular offsets, ring-buffer head/tail pointer drift, mailbox flag toggling.

Game engines, anti-cheat, graphics stacks, browser overlays, and launchers all use shared sections legitimately. Unknown-section *plus* RW protection *plus* command-like update cadence matters; section presence alone does not.

### 8.2 EPROCESS and ETHREAD Reserved Field Storage

`EPROCESS` and `ETHREAD` contain padding, reserved fields, build-dependent fields, and rarely used flags. A driver stores small state in fields that documented APIs do not expose. The user-mode side cannot read these fields directly, but it observes effects through handle behavior, thread state, or via a companion kernel read path.

This is *low-bandwidth state hiding* more than a primary IPC channel. Useful for flags, hiding markers, and rendezvous metadata, but the structures are version-fragile and may collide with PatchGuard or kernel consistency checks depending on the field chosen.

The attacker usually stores one of four things:

1. *Marker bits.* "This process/thread has been prepared" or "this thread is the receiver".
2. *Small counters.* Epoch or generation values that another kernel path reads.
3. *Pointer breadcrumbs.* Pointers to a real descriptor stored elsewhere.
4. *Policy distortions.* Fields that influence handle, debug, priority, or thread state so another operation behaves differently.

The danger to defenders is layout drift. A field that is padding on one build can be meaningful on the next. A reserved bit that seems harmless can become a kernel invariant. That makes this a poor place for active remediation and a good place for read-only consistency checks.

**Detection.** Use build-aware symbol layouts. Compare critical process/thread fields against independent lifecycle telemetry: ETW process events, `PspCidTable`, handle enumeration, thread start addresses, image-load callbacks, wait-state telemetry, and scheduler-visible thread state. Detect *impossible* state combinations: a thread in an impossible wait reason, a process with `ImageFileName` empty, an active thread with a NULL `Win32StartAddress`, a protected-process flag inconsistent with signer policy, or an object reference state that disagrees with handle tables. Avoid writing to these structures during detection; that surface is fragile under contention and can crash the system.

### 8.3 PEB and TEB Field Mirroring

The kernel driver mirrors state into user-visible PEB / TEB / TLS-expansion / loader-metadata fields. UM reads the state via ordinary memory reads against the PEB or TEB: no IOCTL, no handle, no API call.

The KM side attaches to the process (via `KeStackAttachProcess`), resolves PEB/TEB addresses, and writes selected fields or pointed-to buffers. Object references obtained during the operation must be released correctly after the lookup. The UM side reads the mirrored field, watches for changes, or uses loader/TLS side effects (a TLS callback that runs when a thread is created) as a trigger.

Useful fields and side effects include loader list links, TLS expansion slots, activation context pointers, process parameters, GDI/user callback pointers, thread-local slots, and per-thread exception/stack metadata. An attacker does not need to corrupt obvious fields. It can store a pointer in a rarely used TLS slot, mirror an epoch into loader metadata padding, or add a fake loader entry that only its own code reads.

This is attractive because UM can read its own PEB/TEB cheaply and quietly. It is also dangerous for the attacker because many runtimes, crash reporters, loaders, debuggers, and exception paths assume PEB/TEB invariants. Bad writes crash the protected process or produce obvious loader inconsistencies.

**Detection.** Validate PEB loader lists against VADs and image-load events; a `LDR_DATA_TABLE_ENTRY` referencing a module that is not in the image-load callback history is the signal. Check PEB fields that should point into `ntdll`, `kernel32`, `kernelbase`, or `user32` against expected ranges. Store TLS slot population, loader entry hashes, process-parameter backing, activation-context pointers, and TEB stack bounds for suspicious threads. Monitor unexpected writes to PEB/TEB pages where instrumentation permits. Correlate abnormal TLS and loader metadata with unknown modules.

DRM, packers, anti-cheat, profilers, debuggers, and compatibility layers all modify PEB/TEB state legitimately. The narrow pattern that matters is *kernel writes into PEB by an unknown driver while a known anti-cheat is loaded*; the legitimate population for that specific pattern is essentially empty.

### 8.4 Direct PspCidTable Manipulation

`PspCidTable` maps process and thread IDs to kernel objects. Direct manipulation is one of the older surfaces; it can hide a process by clearing its CID entry or fake a process by injecting one, but its primary modern utility is as a *signaling* and *hiding* primitive rather than a payload channel.

**Entry encoding (corrected).** v6 documented only the pre-Windows-8 encoding (`Object & ~3ULL`). On modern x64 Windows builds, `_HANDLE_TABLE_ENTRY` is commonly represented as a 16-byte packed entry with object-pointer bits rather than a plain pointer. Treat the following as a representative layout, not a portable parser:

```cpp
typedef struct _HANDLE_TABLE_ENTRY
{
    union
    {
        ULONG_PTR VolatileLowValue;
        ULONG_PTR LowValue;
        struct
        {
            ULONG_PTR Unlocked          : 1;
            ULONG_PTR RefCnt            : 16;
            ULONG_PTR Attributes        : 3;
            ULONG_PTR ObjectPointerBits : 44;
        };
    };
    union
    {
        ULONG_PTR HighValue;
        ULONG     GrantedAccessBits : 25;
    };
} HANDLE_TABLE_ENTRY;
```

The object pointer recovery pattern often looks like:

```cpp
// Representative x64 pattern only. Validate against symbols / build-specific
// handle-table helpers before using this in a detector.
// Drop Unlocked (1) + RefCnt (16) + Attributes (3) = 20 lower bits.
// Shift the remaining object bits left by 4 to restore 16-byte alignment.
// Sign-extension depends on the platform's canonical-address model.
ULONG_PTR rawPtr = ((LowValue >> 20) << 4) | 0xFFFF000000000000ULL;
POBJECT_HEADER hdr = (POBJECT_HEADER)rawPtr;
PVOID         object = OBJECT_HEADER_TO_OBJECT(hdr);
```

This is *not* `EX_FAST_REF`. `EX_FAST_REF` applies to notify arrays and fast-referenced objects and uses 3 or 4 lower bits depending on architecture, not the 20-bit lower band of `_HANDLE_TABLE_ENTRY.LowValue`. Detection code that confuses the two will misparse handle table entries silently.

The handle table's tree structure also matters. In the common x64 layouts this document targets, `_HANDLE_TABLE.TableCode` lower bits encode the table level:

- `0`: single level.
- `1`: two-level.
- `2`: three-level.

Incorrect synchronization or parsing of multi-level tables can crash the system. Use symbol-aware and build-aware code, and prefer supported enumeration plus cross-view validation whenever possible.

**Detection.** Prefer supported enumeration plus cross-view validation. Compare `PspCidTable` results against active process lists, thread lists, ETW lifecycle events, and handle enumeration. Detect *impossible* states: live thread without an expected CID mapping, CID mapping to an invalid object, object reference counts that disagree across views.

### 8.5 KernelCallbackTable

Every GUI process stores a pointer to the user-mode callback dispatch table in `PEB->KernelCallbackTable` when `user32.dll` is loaded. On the x64 Windows builds commonly targeted by public research this field is observed at `PEB + 0x58`, but a detector should still resolve the layout per build rather than hard-coding the offset blindly. `win32k.sys` uses this table when `KeUserModeCallback` calls back into user mode: to deliver window messages, paint events, hook callbacks, and a long list of GUI-related kernel-to-user transitions.

**Internals.** The table user32 exports under the name `apfnDispatch` is the actual array `KernelCallbackTable` points to. Modern Windows 11 builds expose more than 100 entries; the canonical names (`__fnCOPYDATA`, `__fnCOPYGLOBALDATA`, `__fnDWORD`, `__fnNCDESTROY`, ...) appear in legacy documentation but the array is much larger today.

**Mechanism.**

1. A GUI-related kernel path reaches `KeUserModeCallback` (or an internal equivalent).
2. The kernel determines an API number: the index into `apfnDispatch`.
3. The user-mode callback pointer is fetched through `PEB->KernelCallbackTable + index * 8`.
4. The function runs in user mode.
5. Control returns to kernel mode after callback completion.

A cheat that controls one of these pointers gets *kernel-triggered user-mode code execution* without injecting a thread, without queueing an APC, and without modifying any code section. The cheat picks a slot, points it at its payload, and the payload runs the next time a window message of the right type is processed.

**Abuse patterns.**

- *Direct entry replacement.* Replace `__fnCOPYDATA` (or any other slot) with a payload pointer. The first `WM_COPYDATA` message that reaches the process triggers the payload.
- *Duplicate table.* Allocate a copy of the original table, modify one or more entries in the copy, and change `PEB->KernelCallbackTable` to point at the copy. MITRE ATT&CK tracks this as T1574.013.
- *Wrapper trampoline.* Wrap the original callback, call it, and add pre-processing or post-processing.

**Detection (corrected and reframed).** v6 treated `KernelCallbackTable` as a P2 research-only check. That was already wrong in v6's frame and is more so now: MITRE ATT&CK DET0577 (last revised May 2026) documents the technique with production-grade detection guidance, and major commodity cheats use it routinely.

A production check has three components:

1. *Pointer validity.* `PEB->KernelCallbackTable` should be inside `user32.dll` or a known-good mapped region for the loaded `user32` image. A pointer to heap, private memory, or an unknown image is high severity.
2. *Table content.* Hash the *entire* `apfnDispatch` array against a clean baseline computed from `user32!apfnDispatch` on the same build. Modern cheats hijack rarely used slots (window-class extra-byte allocators, DWORD message-callback variants) precisely because the canonical `__fn*` slots get checked first. Hashing the whole table catches both.
3. *Post-initialization change.* Normal processes set the field once when `user32` loads and do not modify it afterwards. A change observed after process initialization completes should be treated as a high-severity integrity anomaly unless an allowlisted product owns and explains it.

Legacy injection, accessibility tools, and security products may hook GUI callbacks; protected processes should be held to a strict policy and any deviation should be investigated.

### 8.6 GdiSharedHandleTable

GUI processes expose GDI handle metadata through `PEB->GdiSharedHandleTable`, historically at x64 PEB offset `0xF8`. Older Windows builds leaked kernel addresses through `pKernelAddress` in cross-process views, which made this a useful KASLR-leak primitive. Some cheat designs attempted to use the table as storage or a discovery path.

**Windows 10 1607 and later behavior.** In cross-process views, `pKernelAddress` is nulled. The owning process can still see meaningful information about its own GDI objects. `wProcessId`, `wType`, and `pUserAddress` remain useful metadata. The cross-process KASLR leak is largely closed.

For *covert channel* usage, utility is now limited. Data written in one process context is not necessarily visible cross-process on RS1 and later. Replacing the mapped view is possible in theory but operationally complex and high-risk. Treat this surface as a *supporting signal* in detection for abnormal GDI object creation patterns or unusual GDI table pointer values, not as a primary P0 channel for cheats today.

The remaining abuse value is correlation. A GUI callback-table hijack (§8.5), hidden-window property channel (§2.6), or swap-chain/capture path (§9.4) often changes GDI/User object behavior. Unexpected surges in bitmaps, regions, device contexts, hidden windows, or table pointer relocation can be the side effect that ties otherwise weak GUI evidence together.

**Detection.** Monitor abnormal GDI object creation patterns. Validate GDI shared-table pointers and object counts against the process's documented GDI handle count. Record object type distribution, owner PID/TID, `pUserAddress` ranges, table pointer backing, and changes around injection or window-message events. Treat GDI evidence as corroborating signal unless the table pointer itself is outside the expected shared mapping or object counts diverge from kernel/user views.

### 8.7 LargePageDrivers Shellcode Injection

`LargePageDrivers` abuse relies on large-page driver mapping behavior and alignment slack. A cheat hides shellcode or a trampoline in unused alignment space associated with a legitimate driver mapping, then redirects execution into that area. The target address appears to belong to a legitimate large-page-mapped driver, which causes naive module-range checks to pass.

The trick is range laundering. A pointer-integrity check that only asks "does this target fall inside a loaded signed module range?" will approve a branch into alignment slack, padding, or unused large-page-mapped space. The cheat still needs a separate control edge, such as a dispatch pointer, callback, `.data` pointer, gadget, or exception path, to reach that code. Large-page shellcode is therefore rarely the whole channel; it is the hidden execution body behind another trigger.

The attacker benefits from three defender shortcuts:

1. *Range-only validation.* "Inside signed module" is treated as clean.
2. *Entry-only hashing.* Only exported or known function starts are checked, not unused interior bytes.
3. *No slack model.* The detector does not know which bytes are padding, alignment, hotpatch area, or legitimate code.

The fix is to classify the target, not just the range. A pointer into a signed module is meaningful only if it lands at a valid function entry, known thunk, hotpatch-compatible prologue, or compiler-generated control-flow target. A pointer into padding or a code cave is suspicious even if the containing allocation is signed.

**Detection.** Hash executable driver pages against clean image bytes (HVCI / CodeIntegrity does this for signed images but does not cover every page configuration historically). Inspect alignment slack and padding regions for non-zero executable-looking bytes. Store whether targets land at exported symbols, known function starts, compiler-generated thunks, hotpatch regions, or unclaimed interior bytes. Most importantly, validate that indirect call targets land at *legitimate function entry points*, not merely inside a module's mapped range; the same chain-validation pattern from §6.4 applies. Executable bytes in padding regions should be treated as high severity.

### 8.8 MDL-Backed User-Buffer and Locked-Page Mailbox

The simplest high-bandwidth channel does not always need a section object. A user-mode helper allocates ordinary virtual memory, passes the pointer once through any bootstrap path (IOCTL, registry callback, `.data` pointer trigger, APC, firmware table request, or WFP/filter callback), and the kernel component converts that buffer into stable physical memory by building an MDL and locking the pages. After setup, both sides treat the same user pages as a mailbox, ring buffer, or command/result area.

The important distinction from §8.1 is *provenance*. A kernel-created section creates a visible section mapping. An MDL-backed mailbox can look like normal private committed memory in the helper process. The kernel side has the MDL, PFN array, and possibly a system-space mapping; user mode just sees a heap/VirtualAlloc region. If defenders only enumerate named sections and file mappings, they miss the payload buffer.

The usual setup looks like this at the protocol level:

1. *Allocation.* UM creates a page-aligned buffer, often with guard pages around it, and initializes a header: magic, version, size, producer/consumer indices, epoch, command, status, and optional encryption nonce.
2. *Bootstrap.* UM sends the pointer and size through a low-bandwidth trigger. This is why the registry, firmware-table, `.data`, or dispatch-hook channels matter: they can be just a rendezvous, not the payload bus.
3. *Pinning.* KM probes and locks the pages with an MDL, validates the user-mode range, stores the MDL or derived system mapping, and records the process context that owns the buffer. Direct I/O IOCTLs create similar MDL state in `Irp->MdlAddress`; custom channels can build it manually.
4. *Mapping.* KM either accesses the locked pages through a system-space mapping or temporarily attaches to the process. Some variants map pages into another process to create UM-UM sharing without a section object.
5. *Synchronization.* The mailbox uses cache-line-aligned sequence counters, interlocked flags, `WaitOnAddress` in the same process (§10.11), events, APCs, fence-like counters, or polling. High-skill variants avoid frequent syscalls after setup.
6. *Teardown.* KM unlocks pages and drops the MDL on process exit, command completion, or anti-cheat pressure. Bad teardown leaves locked pages, stale PFNs, process-exit crashes, or memory leaks.

#### Attacker Mechanics: Sectionless Shared Memory

The MDL mailbox is the section channel's stealthier cousin. A named or page-file-backed section creates a recognizable kernel object and VAD relationship. An MDL-backed mailbox starts as ordinary private user memory and only becomes special because a kernel component pins it and keeps a stable mapping. User-mode memory scanners see a heap or `VirtualAlloc` region. Kernel code sees an MDL, PFN array, lock state, and possibly a system-space address. The two views do not naturally meet unless the defender correlates them.

Attackers use this asymmetry in a predictable way:

1. *Pointer transfer is one-time.* The first-stage channel only needs to deliver `(process, address, size, access, generation)` once. Registry callbacks, firmware-table queries, patched dispatch entries, WNF updates, ALPC messages, or hidden IOCTL paths are sufficient.
2. *The mailbox survives the trigger.* After pages are locked, the original trigger can go quiet. A defender who searches only for repeated registry writes or IOCTLs may conclude the channel ended while the payload bus is still active.
3. *Ownership is ambiguous.* The allocation belongs to the helper process, but the long-lived pin belongs to a driver. The helper may look like it owns normal private memory; the driver may look like it owns an unrelated MDL.
4. *Synchronization can be objectless.* Sequence counters and `WaitOnAddress` remove named events. Polling can be hidden inside normal render, overlay, or telemetry loops.
5. *Failure is informative.* Process exit, VAD unmap, protection change, suspend/resume, or guard-page insertion can desynchronize the MDL state. Crashes around exit or locked-page leaks are common implementation scars.

The usual internal layout mirrors a section transport: a small header, one or more command slots, a result area, and optional large pages for bulk data. The difference is how the buffer is discovered and justified. Sections advertise themselves through objects and mappings. MDL mailboxes advertise themselves through lock lifetime, page ownership, and access cadence.

There is also a physical-page flavor. A vulnerable signed driver or attacker-controlled driver maps a physical page range with MMIO-style helpers, exposes a user-mode mapping or compact physical-page descriptor to the helper, and uses that page as a mailbox or bootstrap primitive. The helper normally does not dereference a raw kernel virtual address; it either receives a user mapping, passes the descriptor back through the vulnerable driver, or relies on the driver to perform the physical read/write on its behalf. That variant is noisier and more dangerous because arbitrary physical mapping is a known BYOVD abuse primitive, but cheat and malware ecosystems still catalog vulnerable drivers by "map/unmap physical" capability because it gives a generic memory primitive that can bootstrap any later channel.

**Why attackers use it.** It is fast, cheap, and modular. The visible trigger can be tiny and rare, while the real traffic stays in an ordinary-looking user allocation. It also composes cleanly with manual-mapped drivers: the first trigger installs the MDL mailbox, then the mapped payload no longer needs an obvious device object.

**Detection.** Add MDL and locked-page provenance to memory-channel telemetry:

1. For direct I/O and internal IOCTLs, record `Irp->MdlAddress`, transfer method, buffer size, caller process, target device, and completion status. Repeated fixed-size MDLs from a protected-workload helper to an unrelated driver are suspicious.
2. For kernel-built MDLs, monitor `MmProbeAndLockPages` / unlock balance where instrumentation permits. Store process, virtual address, size, access mode, lock operation, MDL address, system mapping address, and owner driver.
3. Correlate locked user pages with private VADs. A long-lived locked private buffer in a protected-workload helper with ring-buffer headers, sequence counters, or high-entropy command blocks is a stronger signal than a short DMA buffer in a real hardware driver.
4. Track teardown. Pages that remain locked after the helper exits, MDLs held by drivers with no DMA/direct-I/O role, or system mappings into user pages from unknown drivers are high-value leads.
5. Watch for physical mapping primitives. User-mode tools that call into a vulnerable driver to map/unmap physical memory during protected workload runtime should be treated as BYOVD evidence even if no custom attacker driver is visible.

False positives include legitimate direct-I/O drivers, high-performance capture/streaming devices, storage/network hardware, GPU tooling, and anti-cheat itself. Role decides the finding: a storage driver locking a user buffer for a disk request is normal; an unknown workload-adjacent driver locking a small heap buffer and updating a command header at protected-runtime cadence is not.

### 8.9 Windows I/O Ring Queue Abuse

Windows I/O rings arrived for client systems in build 22000 and expose a user-mode API for creating an I/O ring submission/completion queue pair. `CreateIoRing` returns a handle to an I/O ring; the caller builds operations such as asynchronous reads, submits entries to the kernel queue with `SubmitIoRing`, and receives completion queue entries. The API is designed for high-throughput asynchronous I/O, but from a channel-design perspective it has the shape attackers like: a persistent object, user-supplied opaque `userData`, registered buffers and handles, kernel-submitted completions, and a queue whose cadence can be observed without a custom device object.

There are three realistic abuse patterns:

1. *Opaque completion channel.* UM submits benign-looking I/O requests whose `userData`, offsets, lengths, or request ordering encode commands. A cooperating kernel component influences which requests complete, when they complete, or what status code is returned. UM reads completions as the reply stream. This is low bandwidth but blends into normal asynchronous file I/O.
2. *Registered-buffer rendezvous.* UM registers buffers and handles, then uses the I/O ring as the synchronization and completion mechanism around a separate shared-memory payload. The data may live in a section, mapped file, or normal process buffer; the ring carries epochs, completion codes, and mailbox state.
3. *Internal object tampering.* A kernel cheat with build-specific offsets writes into I/O ring internal state or completion structures directly. This is more fragile and closer to kernel object manipulation than normal API use, but it gives the attacker a queue object that many user-mode monitors do not yet inventory.

The surface is not as universally useful as a plain section. It is Windows 11+ only, version-sensitive, and less common in many games than standard overlapped I/O or thread pools. Its value is novelty: defenders often baseline file handles, sections, and ALPC ports before they baseline I/O ring objects and completion cadence.

**Detection.** Add I/O rings to process object inventory where the OS build supports them:

1. Identify protected processes and helper processes that create I/O rings during protected-session runtime. Creation after protected workload start is more interesting than creation during normal application bootstrap.
2. Track ring sizes, registered-buffer counts, registered-handle counts, operation types, and completion cadence. A tiny ring with a stable fixed-rate completion stream is more suspicious than a renderer or asset streamer doing bursty file I/O.
3. Correlate completion status and `userData` entropy. Opaque user data is legal, but high-entropy or opcode-shaped values in a process that does not otherwise use modern async I/O are a hunting signal.
4. Compare with file-system telemetry. I/O ring completions without corresponding plausible file/network/device I/O indicate either an internal object path or a cooperating kernel component.
5. Gate by build. Do not ship detectors that assume one private I/O ring layout across Windows 11 releases; use symbols or supported object telemetry where possible.

False positives come from high-performance storage engines, browser caches, asset streamers, antivirus scanners, and future game engines that adopt the API legitimately. Evidence becomes strong when an unexpected I/O ring appears with an unknown driver load, completion cadence that matches command traffic, and no corresponding benign I/O workload.

### 8.10 Memory-Channel Deep-Dive Matrix: Provenance, Layout, and Synchronization

Memory-backed channels are the payload workhorses. They move data fast and can be made almost silent after setup. A detector therefore needs to focus on setup artifacts and buffer semantics: who created the memory, who mapped it, what backs it, what protection it has, how it is synchronized, and whether the contents look like a protocol rather than normal application data.

**Kernel-created sections (§8.1).** Store section object name if any, backing file or pagefile state, creator process/driver, handle duplication path, mapped processes, base addresses, view size, protection, inherit disposition, and VAD flags. Then inspect layout at a safe sampling rate: magic values, ring indices, sequence numbers, command IDs, high-entropy blocks, and cache-line-aligned control words. The most useful evidence is a pagefile-backed section mapped into the game and a helper, created or duplicated by an unknown driver/service, with a stable mailbox header.

**EPROCESS/ETHREAD reserved-field storage (§8.2).** This is more integrity violation than channel. Attackers use spare-looking fields or overlay assumptions to store pointers, flags, or sequence counters. A defender should avoid brittle blanket checks and instead validate build-specific invariants: fields that should be zero, fields whose values should be kernel pointers of a specific type, reference-count relationships, and list membership. Cross-build symbol validation is mandatory. If a reserved field points to non-image executable memory or a private driver allocation during a game session, the finding is high severity.

**PEB/TEB mirroring (§8.3).** The PEB and TEB are attractive because user mode can read them cheaply and kernel mode can write them with sufficient privileges. The channel usually hides in seldom-inspected fields, TLS/FLS-related state, loader lists, process parameters, or scratch-like values. Detection should compare the protected process against a clean sibling process on the same build and bitness: PEB address, loader list integrity, process-parameter pointers, TLS slots, TEB stack bounds, and unusual page protections. A single unusual value is weak; a kernel write into PEB/TEB followed by user-mode polling is strong.

**PspCidTable manipulation (§8.4).** This surface is about identity and reachability. If a cheat edits handle-table entries or object references, it can hide processes/threads or use object table state as a signal. Detection must decode handle-table entries correctly by build, validate object pointer alignment, object header cookies, reference counts, and CID table consistency against process/thread lists. The high-value check is cross-view: process exists in active process links, scheduler/thread state, ETW, or kernel memory, but is missing or inconsistent in CID lookup.

**KernelCallbackTable (§8.5).** This is a user-mode table but a kernel-assisted setup path. Capture `PEB->KernelCallbackTable`, table backing VAD, protection, module ownership, and per-slot targets. Do not check only famous `__fn*` slots; hash the entire table or compare slot-by-slot against a clean baseline for the same build/session. The channel and injection patterns both rely on the fact that GUI callbacks already cross kernel/user boundaries. Evidence improves when a changed slot is later exercised by GUI activity from the protected process or by message-only window traffic from §2.6.

**GdiSharedHandleTable (§8.6).** This table is weaker on modern Windows because cross-process sanitization reduced its usefulness, but it can still be abused for low-bit state, object discovery, or GUI/GDI correlation. Detection should focus on impossible handle-owner relationships, abnormal GDI object churn, and workload-adjacent processes that create large numbers of GDI objects without rendering need. Treat it as corroboration for GUI callback or window-message channels, not a primary finding.

**LargePageDrivers shellcode (§8.7).** Large-page driver mappings are an integrity and memory-forensics problem. Capture large-page driver ranges, owner modules, section names, code hashes, and whether executable bytes correspond to on-disk images. A cheat using large-page memory for shellcode may avoid some page-level hooks but still needs a control pointer, callback, or dispatch entry to reach that code. Pair large-page anomalies with pointer-chain evidence from §6 or §7.

**MDL-backed user-buffer mailboxes (§8.8).** Store bootstrap trigger, owning process, virtual address, VAD type/protection, MDL address, lock operation, page count, system mapping, owner driver, and unlock time. Then sample the buffer shape safely: header magic, version, size, sequence counters, producer/consumer indices, status fields, high-entropy payload blocks, and cache-line alignment. This surface is strong when a small one-time trigger is followed by a long-lived locked private buffer with command cadence and no matching hardware/direct-I/O role.

**I/O rings (§8.9).** I/O rings have explicit submission/completion structure. Store ring creation process, version, queue sizes, registered buffers, registered handles, operation types, completion cadence, and userData distribution. The suspicious pattern is not "CreateIoRing was called"; it is a ring with registered buffers shared with a helper, opaque high-entropy userData, and completions that correlate with memory scanning or command timing. Because Windows I/O rings are build-gated, always record OS build and API capability before classifying absence or presence.

---

## 9. GPU, DXGK, and D3DKMT Surfaces

This part was reserved as a gap in v5/v6/v7 and is filled here. The graphics stack on Windows is large, performance-critical, and full of *cross-process memory primitives that look exactly like ordinary GPU programming*. Every modern game allocates GPU memory, every overlay creates shared resources, every recording tool inspects swap-chain output. A cheat that uses the same primitives blends into the noisiest part of the system.

This chapter walks the graphics stack as a *communication substrate*, then enumerates the most useful primitives, then closes with the detection surface and its practical limits.

### 9.1 The Graphics Stack as a Communication Substrate

The Windows graphics stack is layered:

```text
   Application
      | (D3D11 / D3D12 / Vulkan / DXGI API)
      v
   d3dXX.dll / dxgi.dll
      | (DDI / DXGI internal)
      v
   user-mode driver (UMD), e.g., nvwgf2um.dll, amdxc64.dll
      | (D3DKMT_* via gdi32.dll)
      v
   gdi32!D3DKMT* / win32u
      | (syscall)
      v
   win32k / dxgkrnl
      | (DDI)
      v
   kernel-mode driver (KMD), e.g., nvlddmkm.sys, amdkmdag.sys
      | (PCIe DMA / MMIO)
      v
   GPU
```

Three properties of this stack matter:

1. *Cross-process shared resources are normal.* DXGI swap-chain sharing, NT-handle resource sharing for browsers and capture tools, overlay compositing: all rely on the same `D3DKMT_OPENRESOURCEFROMNTHANDLE` / `D3DKMT_OPENSYNCHRONIZATIONOBJECTFROMNTHANDLE` primitives. A cheat that uses them looks identical to any of those legitimate consumers.
2. *GPU memory is partly invisible to ordinary endpoint inspection.* VRAM-resident allocations are not part of the protected process's user-mode address space until they are explicitly mapped or copied back. Anti-cheat and EDR-style scanners that walk VADs see only the staging surfaces, not the underlying GPU buffers.
3. *Vendor-specific escape paths exist.* `D3DKMT_ESCAPE` lets a driver expose vendor-defined commands directly to a UM caller. The escape data is opaque to Windows; only the vendor's KMD interprets it. This is a *documented* mechanism for vendor-specific features (overclocking, performance counters, telemetry), and it is also a strong command-channel candidate if the cheat ships its own driver pretending to be a vendor utility.

The cheat's design space is the union of these properties: shared resources for payload, GPU memory for hiding, escape paths for command framing.

### 9.2 D3DKMT Shared Resources

`D3DKMT_OPENRESOURCEFROMNTHANDLE` (and the older `D3DKMT_OPENRESOURCE` / `D3DKMT_OPENNTHANDLEFROMNAME`) let two processes share a GPU resource via an NT handle. The originating process calls `D3DKMTShareObjects` to obtain an NT handle for a resource; the receiving process duplicates the handle (DuplicateHandle, file handle inheritance, or NT handle marshalling) and opens it.

The receiving process gets a *mapping* into the resource. For a texture, that means GPU-visible texels accessible through ordinary D3D APIs. For a buffer, that means a flat memory region that can be written with `Map`/`Unmap` and read on either side. The two processes are now sharing memory that, from the OS object namespace, is owned by `dxgkrnl` and looks like normal graphics state.

**Why attackers use it.** Three reasons:

- *Namespace invisibility.* The shared object does not show up as a section in `\\BaseNamedObjects` or as a file-mapping in the protected process's section list. It shows up as a D3DKMT allocation, and there are typically hundreds of those per process.
- *KM-assisted setup.* A KM driver can pre-create the resource and inject the handle into the protected process. The UM component does not have to call `D3DKMTShareObjects` itself: it just opens a handle that magically appeared.
- *Bandwidth.* GPU buffers can be large. Megabyte-class payloads are routine; gigabyte-class payloads are possible.

**Detection.** This is one of the harder surfaces for defenders to inventory, and the false-positive population is large (overlays, recording software, browser GPU process, every overlay-capable launcher). Three operational checks compose:

1. *Enumeration.* Do not treat `D3DKMTQueryAdapterInfo` as a per-process allocation enumerator. Its public `KMTQUERYADAPTERINFOTYPE` values expose adapter, driver, capability, segment, output-duplication, and performance metadata, not a complete ledger of every shared resource in the protected process. User-mode checks can still query adapter identity/caps, output-duplication client counts, and visible handle relationships, but full shared-resource ownership usually requires handle-table correlation, `D3DKMTQueryStatistics` / `D3DKMTQueryAllocationResidency` side channels where useful, ETW, or a privileged kernel walker against `dxgkrnl` state. The deep enumeration path is build-sensitive and requires per-build offset maps.
2. *Owner correlation.* For each shared resource visible to the protected process, identify the *other* end. In game deployments, the legitimate set is the title's own overlay, anti-cheat overlay if any, the recording tool if running, the GPU vendor's overlay, and the platform overlay (Xbox Game Bar, GeForce Experience, etc.). In broader malware analysis, the equivalent question is whether the other endpoint has a product role that justifies graphics sharing. Anything outside that set is investigation material.
3. *Behavioral.* Update cadence and content shape. A shared resource updated at 60 Hz with frame-like contents is an overlay. A shared resource updated at irregular intervals with command-like fixed-offset writes is a covert channel.

### 9.3 Monitored Fences

A monitored fence is a CPU-visible 64-bit value backed by GPU sync state. `D3DKMTCreateSynchronizationObject2` with `D3DDDI_MONITORED_FENCE` type returns a CPU-visible mapping of the fence's current value, plus a GPU-side handle the driver can use to advance it. The CPU side can wait on the fence (`D3DKMTWaitForSynchronizationObjectFromCpu`) or simply read the current value at any time.

The shape of this primitive makes it a natural low-bandwidth bidirectional channel: a 64-bit value visible to both CPU and GPU, advanceable on either side. The cheat creates a fence in KM, gives the UM side the handle, and uses the fence value as an epoch counter, command code, or rendezvous version. The cheat's KM half advances the fence to signal UM; the UM half polls or waits.

**Bandwidth.** Low. A single fence carries 64 bits. Multiple fences raise the bandwidth proportionally. The strength is not throughput; it is the way the signal hides inside a primitive that every modern game uses thousands of times per second.

The channel shape usually looks like one of these:

1. *Epoch fence.* Fence value increments once per command mailbox update.
2. *Selector fence.* Low bits select which shared resource, section slot, or command family UM should read.
3. *Completion fence.* UM submits ordinary GPU work, KM or a KMD path advances the fence only when a condition is true.
4. *Timing fence.* The delay between expected and actual fence advancement encodes a small state value.

Legitimate renderer fences have strong temporal structure: frame pacing, command queue completion, present synchronization, and compositor timing. Covert fences often advance independently of frame cadence or remain idle for long periods before command bursts.

**Detection.** Inventory monitored fences attached to the protected process. Validate that each fence has a plausible owner: the renderer, swap-chain, compositor, anti-cheat, capture software, GPU utility, or a known overlay. Store adapter LUID, creating process, opened-by process, fence handle relationship, CPU-visible mapping address, last values, waiters, and value-delta distribution. Watch for fences whose value advances at command-like cadence (regular small steps that do not match frame timing) rather than the frame-pacing or render-completion patterns that dominate legitimate use. Like §9.2 this is a build-sensitive walker.

### 9.4 DXGI Swap-Chain Backing Memory

A DXGI swap chain has backing buffers: the textures the GPU renders into and the desktop compositor reads. On systems where the swap-chain backing is in shared system memory (windowed mode, certain compositor configurations), the buffers are mapped into the game's address space and into the compositor's. A cheat that can access both sides has a free shared-memory channel that looks exactly like rendering data.

More usefully, the *captured* swap-chain output is reachable from a second process via the desktop duplication API (`IDXGIOutputDuplication`). A cheat helper process that holds a desktop duplication handle sees every frame the game presents. This is not strictly a KM-UM channel: it is a UM-UM channel that the cheat may use to *exfiltrate* game state without ever reading the game's memory directly.

There are two different defensive questions:

1. *Memory-backed sharing.* Who can map or open the swap-chain buffers or related shared resources?
2. *Visual exfiltration.* Who can observe frames through desktop duplication, capture APIs, overlay composition, or an external capture path?

The first belongs to D3DKMT ownership analysis (§9.2). The second belongs to capture-client and behavior analysis (§13.4). A cheat can use both: capture frames with `IDXGIOutputDuplication`, run CV in another process, then return input through a HID bridge (§13.3).

**Detection.** Track processes holding active `IDXGIOutputDuplication` interfaces or equivalent capture paths during protected workload runtime. Store process owner, signer, window/session, adapter/output, start time, capture cadence, and whether the process renders a visible UI. The legitimate set is recording software (OBS, ShadowPlay, GameDVR), streaming software, accessibility tools, screen-readers, and remote-desktop systems. A duplication client that is none of those, particularly one that runs only during competitive matches or protected sessions, is the high-confidence pattern. Server-side behavioral detection complements this; a cheat using only vision-based input via desktop duplication leaves no on-device memory access pattern at all, which is itself a signal.

### 9.5 Adapter-Local System Memory and GPU-Visible Mappings

A KMD can allocate adapter-local system memory through `DxgkCbAllocateMemory` and similar callbacks, and make it visible to both the GPU and a chosen process's CPU side. The allocation is reachable from UM through D3DKMT APIs but appears in the protected process's address space as a *normal D3D allocation*: nothing about the VAD entry betrays that the memory is dual-use.

This is the architecture-level reason `D3DKMT_ESCAPE` (§9.6) is so attractive: the same plumbing that legitimately exposes GPU performance counters and vendor overlays to UM also exposes any structured payload the KMD chooses to publish.

The payload can be one of several forms:

1. *GPU-visible command buffer.* UM writes a command descriptor into a buffer that the KMD or GPU-side shader path observes.
2. *Readback staging.* GPU or KMD writes data that UM later maps or copies back.
3. *Shared telemetry surface.* Vendor-looking utility and attacker helper read the same adapter-local allocation.
4. *Fence-paired mailbox.* A monitored fence (§9.3) carries the epoch while the allocation carries the data.

The core anti-cheat problem is attribution. The allocation may be legitimate if created by the real GPU KMD for rendering, capture, or overlay. It becomes suspicious when the backing KMD, owning process, or access pattern does not match the renderer/capture role.

**Detection.** Almost all real-time detection of this surface is impractical from inside the protected process. A privileged kernel walker can enumerate D3DKMT allocations, identify which are visible to the protected process, and correlate the backing KMD with the expected GPU vendor driver. Record adapter LUID, allocation size, segment, CPU-visible mapping, owning process, opened-by processes, synchronization objects, and KMD owner. An allocation backed by a non-vendor driver (an attacker KMD impersonating a vendor escape path) is the signal; an allocation backed by `nvlddmkm.sys` or `amdkmdag.sys` is usually noise unless paired with unknown UM access. The check requires per-build knowledge of dxgkrnl internals and is not portable across Windows versions without maintenance.

### 9.6 GPU Scheduling Hooks and D3DKMT_ESCAPE

`D3DKMT_ESCAPE` is the documented vendor-specific extension surface. A UM caller passes an opaque buffer and a target adapter; `dxgkrnl` forwards it to the KMD's `DxgkDdiEscape` entry point. The KMD interprets the buffer however it wants. This is the path NVIDIA and AMD use for their control-panel applets, performance overlays, undervolting tools, and telemetry.

For a cheat shipping its own KMD (or a hijacked KMD), `D3DKMT_ESCAPE` is a clean bidirectional command channel that looks identical to vendor utility traffic. The buffer is opaque, the response is opaque, and the surface is *documented* for vendor extensions. The user-mode side does not need a custom device object; the kernel side does not need a custom IOCTL handler.

A second variant is the *scheduling hook*: patching or intercepting the GPU scheduler's queueing path so that the cheat sees every command buffer submitted by the game. This is conceptually similar to a `MajorFunction` patch (§6.1) but on the GPU side, and lets the cheat correlate UM render commands with GPU memory contents, derive game state without reading process memory, or insert its own command buffers into the queue.

Public cheat research around the graphics kernel also demonstrates a narrower "graphics syscall proxy" shape: pick a D3DKMT or GDI/Win32k function whose normal call path goes through a writable function table or session-specific dispatch pointer, replace that pointer, and use an ordinary graphics syscall as the UM->KM trigger. `D3DKMTSubmitCommand` / `NtGdiDdDDISubmitCommand`-style paths are attractive because games call graphics functions constantly and because Win32k/dxgkrnl tables are not usually part of first-pass anti-cheat dispatch validation. The hook does not have to understand every GPU command. It can simply identify the target process, observe timing, decode a magic argument shape, or use the graphics call as a synchronized moment to update an overlay, shared resource, or command buffer.

This differs from `D3DKMT_ESCAPE`. Escape is a documented opaque vendor command. The graphics-syscall proxy is a pointer-integrity violation in the routing path before or around dxgkrnl/KMD dispatch. In evidence terms, `D3DKMT_ESCAPE` asks "who is issuing opaque vendor commands to which KMD?" The syscall-proxy case asks "did a graphics dispatch pointer or session-state pointer move, and does a normal D3DKMT call now branch through a non-entry-point or unknown target?"

**Detection.** Two distinct checks:

1. *D3DKMT_ESCAPE traffic attribution.* Where ETW or KM instrumentation exposes escape calls (the GPU scheduler ETW provider has relevant events on Windows 11), correlate escape traffic with the loaded KMD's image. Escape calls reaching a KMD that is not the GPU vendor's signed driver are anomalous; escape calls reaching the vendor KMD from a process that is not a vendor utility are still noise but a useful corroborator.
2. *Scheduler-state baseline.* Capture a baseline of `dxgkrnl` dispatch state at boot. Validate at protected workload launch that the GPU scheduler's queue insertion and execution paths still point inside `dxgkrnl` and the vendor KMD. A pointer outside those modules is high severity and lands in the same category as a `HalPrivateDispatchTable` slot redirection.
3. *Graphics syscall route validation.* For build-supported scanners, baseline Win32k/dxgkrnl callable dispatch tables and session-state pointer chains that are reachable from high-frequency D3DKMT or NtGdi/NtUser syscalls. Validate that targets are expected function entries inside `win32kbase.sys`, `win32kfull.sys`, `dxgkrnl.sys`, or the vendor KMD, not pool memory, manual-mapped code, or interior gadgets in signed images. Correlate pointer diffs with caller process, D3DKMT function, argument sizes, adapter LUID, context handle, and present/submit cadence. Because graphics workloads are noisy, pointer integrity is the primary signal and traffic cadence is corroboration.

### 9.7 WDDM 3.x GPU DMA Remapping

Windows 11 introduced GPU IOMMU DMA remapping in the WDDM 3.x display stack, with Microsoft documenting the IOMMUv2 feature as introduced in Windows 11 22H2 (WDDM 3.0). The important distinction is not only "IOMMU on"; older GPU isolation used 1:1 physical remapping, while IOMMU DMA remapping lets `dxgkrnl` provide GPU-visible logical address ranges that can map to physical memory through an IOMMU-managed domain. Microsoft documents this primarily as a display memory-management model, including support for systems whose physical memory exceeds a GPU's directly addressable range. It is still relevant to anti-cheat, but it should not be oversold as a complete GPU anti-cheat boundary.

This matters for KM-UM cheat channels because:

- Driver support is expressed through the display-driver DDI/capability path, including physical-memory and IOMMU capabilities, memory-management caps such as `MapAperture2Supported`, and the `DmaRemappingCompatible` INF value where applicable. A KMD that cannot satisfy these requirements should not be treated as equivalent to a remapping-capable WDDM 3.x driver.
- Logical remapping improves the platform's ability to reason about which GPU-visible mappings exist, but the GPU vendor KMD remains a privileged participant in creating and using those mappings. A malicious or hijacked KMD is still a high-trust failure, not something IOMMU alone can fully contain.
- Windows 10-era GPU isolation is weaker for this specific remapping model; Windows 11 22H2+ with capable hardware and drivers is the practical policy target when a title wants to raise the hardware trust floor.

**Detection.** Verify GPU DMA remapping support and mode in the platform IOMMU/display configuration where the title's policy demands it. Check the loaded GPU KMD's WDDM version, IOMMU caps, memory-management caps, and DMAr compatibility metadata rather than relying on a single "DMA protection enabled" label. Treat IOMMU fault telemetry, if available, as corroborating evidence rather than a guaranteed cheat signature; individual faults can come from driver bugs, reset paths, firmware issues, or legitimate remapping failures and need owner attribution. This is policy-territory more than detection-territory: the right answer is to require Windows 11 22H2+ / WDDM 3.x, IOMMU, capable GPU hardware, and remapping-capable vendor drivers as a *precondition* for competitive launch, not to detect violations after the fact.

Operationally, treat GPU remapping like storage DMAr enforcement rather than like a standalone cheat signature. The evidence package should include OS build, WDDM version, adapter PCI identity, GPU driver version, IOMMU domain/remapping mode where exposed, INF compatibility metadata, fault counts if available, and whether virtualization-based security is active. A single remapping-disabled flag may be an OEM/BIOS/driver support issue, not cheating. A remapping-disabled platform plus unknown GPU-side escape traffic plus impossible game knowledge is a much stronger case.

### 9.8 Detection Surface and Practical Limits

The graphics stack is the largest *untapped* covert channel surface for traditional anti-cheat. Three structural reasons explain this:

1. *Vendor opacity.* GPU vendor drivers are closed-source and large. Vendor escape paths are documented at the API level but the *content* of escape buffers is opaque to anti-cheat. A cheat that disguises itself as a vendor utility (correct signer, correct escape format, plausible adapter affinity) is very hard to attribute.
2. *Cross-process is normal.* DXGI sharing, capture, and overlay primitives mean cross-process resource access is the *expected* steady state. Heuristics that work for IPC namespaces ("any cross-process section is suspicious") do not apply to GPU resources.
3. *Build sensitivity.* Most useful detection in this space requires per-Windows-build offset maps for `dxgkrnl` and per-vendor knowledge of escape formats. Anti-cheat vendors that do not invest in this surface are essentially blind to it.

A pragmatic detection program for the GPU surface starts with:

- *Inventory* the loaded GPU KMD, vendor-utility processes, capture/duplication clients, and overlay clients at protected workload launch. Anything outside the expected vendor + platform overlay set is investigation material.
- *Policy* the platform: require Windows 11 22H2+ / WDDM 3.x, IOMMU, capable GPU hardware, and remapping-capable vendor drivers for competitive matches.
- *Correlate* with server-side behavioral detection. A vision-based cheat using only desktop duplication leaves no on-device memory access pattern at all; the only available signal is gameplay statistics (aim curve shape, target acquisition timing, headshot rate vs. visibility windows).

Operationally, the GPU surface is still *one of the under-defended frontiers*. Cheat vendors that use the GPU as their primary covert channel will stay ahead of many production anti-cheat stacks for a while, and closing that gap is a multi-year program for the platform and major anti-cheat vendors.

### 9.9 GPU Deep-Dive Matrix: Handles, Fences, Residency, and Escape Ownership

The graphics stack is a covert-channel substrate because it already moves shared memory, synchronization signals, command buffers, and opaque vendor messages at high volume. A useful GPU detector does not try to understand every vendor allocation. It builds ownership and timing evidence around handles, resources, fences, contexts, processes, and escapes.

**Graphics-stack substrate (§9.1).** Capture the loaded display miniport driver, user-mode display driver DLLs, graphics kernel clients, GPU scheduler state visible through public APIs, vendor utility processes, overlay processes, capture clients, and adapter identity. This gives a clean baseline for "who is allowed to speak graphics." Unknown workload-adjacent processes that open graphics handles but never render visible UI are worth review.

**D3DKMT shared resources (§9.2).** Shared resources are normal in overlays and capture stacks, so the detector needs handle relationship, not just API presence. Store creator process, opened-by process, NT handle, allocation size where visible, format, flags, adapter LUID, resource lifetime, and synchronization object pairing. A suspicious resource is opened by a helper with no overlay/capture role, has fixed-size updates, and is synchronized by a fence whose values look like sequence counters rather than frame numbers.

**Monitored fences (§9.3).** Fences are natural low-bandwidth signals because they are supposed to be monotonic and cheaply visible. Record fence creator, shared handle, current value, waiters, signalers, adapter, and value deltas over time. Normal frame pacing produces values tied to render cadence. A command fence often advances in bursts around memory operations or helper activity, independent of frame submission. Correlate with CPU-side waits and with shared-resource updates.

**Swap-chain backing memory (§9.4).** Swap chains are visually meaningful and high-volume. Abuse usually hides in extra shared surfaces, unexpected duplication clients, or off-screen resources rather than the primary present path. Capture swap-chain owners, output-duplication clients, capture APIs, overlays, present cadence, format changes, and unusual shared backing handles. False positives include streaming, overlays, accessibility magnifiers, GPU capture tools, and anti-cheat itself.

**Adapter-local and GPU-visible mappings (§9.5).** The core challenge is that adapter-local memory may not be trivially visible to CPU scanners. Defenders should record residency transitions, map/unmap events where visible, allocation residency queries, ETW graphics events, and whether resources are shared back into CPU-visible memory. A cheat that stages data in GPU-visible memory still needs a CPU-side control path, fence, escape, or copy operation; the detection should look for those transitions rather than trying to hash all VRAM.

**GPU scheduling hooks and `D3DKMT_ESCAPE` (§9.6).** Escapes are vendor-defined, so semantic parsing is hard. The defensive record should include adapter LUID, escape type/flags, input/output buffer sizes, caller process, UM driver module, KMD owner, return status, and frequency. A vendor control panel issuing occasional known escapes is normal. A game helper issuing high-frequency opaque escapes with fixed-size payloads to a display miniport is not. If the escape path reaches a handler pointer outside the expected KMD image, elevate to pointer-integrity severity.

**Graphics syscall proxies (§9.6).** For D3DKMT/NtGdi/NtUser route hooks, store the reachable dispatch pointer, session-state chain if applicable, expected target, actual target, first-hop disassembly, caller D3DKMT/NtGdi/NtUser operation, adapter/context identifiers, and call cadence. A graphics call from the game is not suspicious by itself; a Win32k/dxgkrnl pointer that moved to an unexpected target is. Treat this like §7.1 with graphics-specific trigger attribution.

**GPU IOMMU DMA remapping (§9.7).** GPU DMA remapping changes the policy floor but not the channel problem. Record whether remapping is supported/enabled for the adapter, driver model, Windows build, HVCI/VBS state, and any fallback path. A system without GPU remapping support is not automatically compromised, but it changes the risk score for adapter-local memory and DMA-assisted graphics paths. For ranked modes, include this in hardware trust posture rather than in covert-channel telemetry alone.

**Practical limits (§9.8).** Public D3DKMT APIs expose adapter and resource metadata, not a complete per-process allocation ledger. When a finding depends on deep `dxgkrnl` state, isolate it behind build-specific parsers and treat it as high-risk engineering. Prefer cross-view evidence first: handle tables, ETW graphics events, D3DKMT public queries, process ancestry, overlay/capture manifests, and server-side rendering/input behavior.

---

## 10. Signal and Execution-Flow Channels

The channels in §2 through §9 are *object-backed*: a port, a section, a callback, a fence. The channels in this section are *flow-backed*: a thread state transition, an exception, a syscall path. The cheat does not need a data structure to hide in; it needs an event that fires when something happens. The KM side arranges the event; the UM side reacts to it.

### 10.1 Trapped User-Mode Thread

A cheat parks a user-mode thread in a wait, exception, syscall, or controlled loop, then uses kernel actions to release, modify, or signal that thread. The KM side manipulates wait state, memory state, or thread context; the UM side waits for the state transition and treats it as a command.

No named IPC object is required. The trapped thread can disguise itself as a worker thread, a synchronization helper, or an idle wait: pick any normal-looking wait reason and the thread looks like every other game worker.

The channel is encoded in *resume cause* rather than object content. Examples:

1. A thread waits on an event that KM signals after updating a shared section.
2. A thread sleeps in an alertable wait and receives APCs (§10.2).
3. A thread loops on a guard page or debug register trap (§10.3, §10.4).
4. A thread blocks in a syscall whose return timing or status is influenced by a kernel hook.
5. A thread's context is modified while suspended, and resume becomes the command edge.

The defender should treat the thread as a protocol endpoint: start address, wait reason, wait object, owning module, last resume reason, stack shape, context changes, and companion memory object. A suspicious wait is much stronger when it points at a section, event, APC routine, VEH handler, or private mapping already seen elsewhere in the catalog.

**Detection.** Identify suspicious long-lived threads with unusual wait reasons or wait targets. Inspect start addresses and call stacks. Record wait object type/name, start module, current RIP, last wait API, last resume status, alertable state, suspend/resume count, context-set activity, and whether the stack contains unknown private memory. Threads waiting on objects that no documented API would create, or waiting in user-mode code that lives in a private mapping, are the high-confidence pattern. Game engines, audio, networking, anti-cheat, and overlays all have worker threads; the discriminator is start address ownership and correlation with a covert trigger.

### 10.2 APC Queueing and Alertable Wait

APCs are delivered when a thread enters an alertable state. Microsoft documents the user-mode shape as `QueueUserAPC(pfnAPC, hThread, dwData)`: the sender needs a thread handle with `THREAD_SET_CONTEXT`, the routine address is the eventual user-mode target, and `dwData` is a single pointer-sized argument. The queued APC is not executed immediately; it is dispatched when the target reaches an alertable wait such as `SleepEx`, `WaitForSingleObjectEx`, `WaitForMultipleObjectsEx`, `SignalObjectAndWait`, or `MsgWaitForMultipleObjectsEx`, and the wait returns `WAIT_IO_COMPLETION`. Pending user-mode APCs are handled in FIFO order after the thread enters an alertable state.

Microsoft explicitly warns that queuing APCs to threads outside the caller's process is not recommended because DLL rebasing, bitness mismatch, and address validity can break the callback. That warning is part of the detection model: stable cross-process APC execution usually implies a same-process helper, carefully mapped target routine, native injection setup, or kernel assistance.

Three cheat layouts show up in practice:

1. *Dedicated receiver thread.* UM creates a thread whose only job is to sit in an alertable wait loop. KM or a UM helper queues APCs to that thread. The channel state is `(routine VA, dwData, dispatch time)`.
2. *Hijacked legitimate completion thread.* The cheat chooses a thread that already uses alertable I/O completion, waitable timers, or runtime callbacks. This lowers the anomaly of alertable waits but raises the importance of routine-address validation.
3. *Pointer-staged command.* `dwData` does not carry the whole command. It points to a shared section, guarded page, heap slot, atom string, or compact command descriptor. The APC is the trigger; the real payload lives elsewhere.

Kernel-mode versions are more direct because the driver can build or insert kernel APC state and request a user-mode callback path without calling the Win32 API. The defender should still normalize the event into the same fields: target process, target thread, target routine, argument value, queueing component, and alertable wait site.

APC existence is not interesting by itself. Windows uses APCs for completion routines, timers, and runtime plumbing. A case becomes interesting when the target routine lives in a private executable mapping, the APC cadence lines up with cheat commands rather than I/O completion, or the same unknown driver repeatedly releases a game thread from alertable waits.

**Detection.** Monitor suspicious APC delivery to game threads, particularly user-mode APCs originating from kernel drivers that are not part of I/O completion, timer, debugger, profiler, or thread-pool infrastructure. Validate APC routine target addresses against loaded image ranges. Record `dwData`, target TID, wait API, wait return reason, and stack at the alertable wait. Alertable wait loops in unknown user-mode modules are themselves a signal. High-confidence clusters combine private-memory APC routines, repeated `WAIT_IO_COMPLETION` returns, a stable target thread, and an unrelated kernel driver that can explain neither the wait nor the callback.

### 10.3 Hardware Breakpoint Channels

Debug registers `DR0`-`DR3` hold watched addresses, `DR6` records breakpoint status, and `DR7` controls enablement, access type, and length. The watched condition can be instruction execution, data write, or data read/write depending on the `DR7` R/W and LEN fields. An attacker sets debug registers per-thread and uses the resulting `#DB` / `STATUS_SINGLE_STEP` exception as a low-slot-count trigger channel without patching any code bytes.

This is attractive because it is exact and byte-invisible. There is no inline hook, no import rewrite, and no guard-page bit to enumerate. The trigger can be a hot game variable, service state field, function entry, read of a command slot, or write to a shared flag. The command selector can be encoded by which debug register fired, the faulting address, a thread-local register value, or a small state machine in the VEH handler (§10.5).

The constraints are also strong. There are only four architectural address slots per thread, the state is thread-scoped in normal use, and context switches require the OS to preserve debug-register state. That makes the technique better as a trigger or selector than as a bulk channel. It often rides with a user-mode VEH, a hidden receiver thread, or a page-guard channel so that one breakpoint releases a larger payload path.

**Detection.** Inspect debug register state from kernel mode on protected-process threads and record all `DR0`-`DR7` values, not just a boolean "has breakpoint". Watch for non-zero hardware breakpoint configuration in threads that should not be debugged. Correlate `#DB` exceptions with unknown VEH handlers, recent `SetThreadContext` / `NtSetContextThread` activity, suspend/resume bursts, and private executable mappings in the protected process. Debuggers, profilers, anti-cheat, DRM, and some instrumentation tools legitimately use hardware breakpoints, so the discriminator is owner image, thread role, watched address ownership, and exception cadence.

### 10.4 Page Fault Handler Interception

Three variants exist, with very different practicality.

**10.4.a Direct KiPageFault Hook (PG-Conflict).** Hooking `nt!KiPageFault` directly modifies kernel code. PatchGuard detects this rapidly on modern Windows and bugchecks the system. Treat as non-viable for production attacker tooling on modern Windows.

**10.4.b VEH plus PAGE_GUARD Trigger (the practical version).** The attacker sets `PAGE_GUARD` protection on selected user memory from KM. UM touches the page, raising `STATUS_GUARD_PAGE_VIOLATION`. The attacker's VEH (§10.5) handles the event, reads the faulting address as the command, and resumes.

`PAGE_GUARD` is *one-shot*. When an access faults on a guard page, the OS clears the `PAGE_GUARD` bit before raising the exception. A covert channel built on this primitive must explicitly re-arm the page inside the handler:

```cpp
DWORD oldProt = 0;
VirtualProtect(addr, size, oldProt | PAGE_GUARD, &oldProt);
```

The re-arm pattern is itself a useful detection signal. Repeated `STATUS_GUARD_PAGE_VIOLATION` exceptions plus repeated `VirtualProtect(... PAGE_GUARD ...)` calls plus a private-memory VEH handler is the canonical signature.

**10.4.c Hardware Watchpoint Read (DR-based).** Debug registers can trigger `#DB` on memory access (read or write), per-thread. Slot-count-limited like §10.3 but useful when guard-page granularity is too coarse.

**Detection.** Enumerate abnormal `PAGE_GUARD` regions in the protected process. Validate the VEH chain (§10.5). Monitor high exception rates and exception types. Inspect debug registers on protected-process threads from kernel mode. The combined signal "private-memory VEH plus high `STATUS_GUARD_PAGE_VIOLATION` rate plus `PAGE_GUARD` re-arm" is high-confidence unauthorized instrumentation or attacker activity.

### 10.5 VEH Chain Injection

Vectored Exception Handlers are process-wide user-mode exception callbacks registered via `AddVectoredExceptionHandler`. An attacker injects a handler and uses exceptions as command triggers, often paired with §10.3, §10.4, or with deliberate access violations and invalid instructions.

Microsoft documents that the `First` parameter controls ordering: non-zero inserts the handler at the front, zero at the end. That ordering matters. An attacker wants first look at `STATUS_GUARD_PAGE_VIOLATION`, `STATUS_SINGLE_STEP`, `STATUS_BREAKPOINT`, `STATUS_ACCESS_VIOLATION`, or deliberately generated illegal-instruction faults before the application's own handlers or crash reporter see them. A front-of-chain unknown handler is therefore much more suspicious than a known runtime handler near the end.

The KM side creates the condition that triggers the exception: guard page state, debug register state, memory protection changes, controlled invalid access, or an execution edge that deliberately faults. The UM side decodes `ExceptionCode`, `ExceptionAddress`, `ExceptionInformation[]`, and the `CONTEXT` record as the command. A minimal command can be "which address faulted"; a richer one can use faulting register values, a shared-memory pointer, or a per-thread state table.

The lifetime model is another artifact. Microsoft notes that if a handler points into a DLL and that DLL unloads, the handler remains registered. Legitimate software should remove the handler with `RemoveVectoredExceptionHandler` before unload. A dangling or stale VEH entry pointing into freed, remapped, or private memory is a strong sign of injected control flow or broken cleanup.

**Detection.** Enumerate VEH chain entries (the chain is rooted in `LdrpVectorHandlerList` in ntdll, walkable from a privileged scanner). Validate handler addresses against expected image ranges; alert on handlers in private RWX/RX memory, unknown modules, recently unmapped modules, or handlers inserted at the front without a known owner. Monitor abnormal exception rates and exception-type distributions in the protected process. Correlate VEH changes with page-protection changes, debug-register state, and module load/unload events. A new front-of-chain handler plus private executable memory plus repeated guard-page or single-step exceptions is the canonical signature.

### 10.6 NMI and IPI Hijack

NMI and IPI paths can interrupt normal execution across cores. A driver registers an NMI callback via `KeRegisterNmiCallback` or triggers cross-core activity via `KeIpiGenericCall`; the resulting interruption gives a high-privilege observation or signaling path that user-mode defenders cannot directly observe.

This is mostly used for anti-debug, anti-inspection, and sampling state outside normal scheduling, not as a primary data channel. The attacker's KM side can sample CPU state during the asynchronous interruption, use an IPI as a cross-core rendezvous edge, or latch a one-bit state transition that another channel later consumes. NMI/IPI is therefore a control-plane primitive: "interrupt now", "sample now", "flush now", "switch state now".

The operational constraints are severe. NMI context cannot tolerate pageable code, blocking, locks, or long work. IPI callbacks run in a timing-sensitive path that can stall other processors. Any attacker that abuses this surface risks visible latency, bugchecks, watchdog symptoms, and strange per-CPU timing artifacts. That instability is useful to defenders: reliable commodity tooling tends to keep the NMI/IPI body tiny and pair it with a safer storage or execution channel.

**Detection.** Enumerate NMI callbacks where possible and validate target addresses against loaded driver images and expected vendor components. Correlate unexpected NMI registration with unknown driver load, DPC/ISR latency spikes, per-CPU stalls, high `KeIpiGenericCall` cadence, and sudden cross-core synchronization bursts during protected workload runtime. Keep defender-side NMI handlers minimal. Long-running NMI handlers cause stability problems, and an attacker's NMI handler is itself a liability; evidence should focus on registration, owner, timing, and correlation rather than heavy in-NMI inspection.

### 10.7 Process Instrumentation Callback

`ProcessInstrumentationCallback` is process information class 40 (`0x28`) for `NtSetInformationProcess`. It lets a privileged caller install a user-mode callback that the kernel invokes on selected kernel-to-user transitions. In the classic x64 model the kernel stores the original return address in `R10`, changes the trap-frame return RIP to the callback, and expects the callback to return to the saved address.

The attacker installs the callback (via a driver or vulnerable signed driver path) and runs payload code on every syscall return. The callback can inspect state, run a mapped payload, or use the callback as a recurring UM execution trampoline. This is powerful: kernel-triggered UM code execution without injecting a thread, without code modification, and without queueing APCs.

The protocol is syscall-return driven. UM calls ordinary `Nt*` functions; the callback runs on return to user mode; the callback can read registers, thread-local state, a shared mailbox, or a mapped payload. An attacker can therefore avoid creating new threads and avoid APC noise. It can also rate-limit itself by acting only on selected syscall returns or selected thread IDs.

The abuse becomes stealthier when the callback target is inside a legitimate image but not at a valid function entry, or when it is a small wrapper that immediately dispatches through a private table. This is the same first-hop problem as §6.4 and §7.1: range validation is not enough.

**Detection.** Query the process instrumentation callback where supported. Validate the callback address against expected images; flag private memory, unknown module targets, non-entry-point targets inside signed modules, and first-hop trampolines. Walk the `KPROCESS` / `EPROCESS` instrumentation callback field directly with build-specific offsets; the value should usually be NULL on protected processes unless an allowlisted security, instrumentation, compatibility, or anti-cheat product set it. Correlate callback presence with private executable mappings, syscall-heavy threads, unexpected `NtSetInformationProcess` activity, and vulnerable-driver load.

Security products, instrumentation frameworks, anti-debug tools, compatibility tools, and some anti-cheat products legitimately use this feature; in a competitive game process the field should be zero unless the anti-cheat itself set it, while enterprise workloads should rely on a product allowlist and ownership evidence.

### 10.8 AltSyscall

Alternative syscall routing on Windows 11 has evolved beyond the simple `PsAltSystemCallHandlers` array that older research described. Newer builds involve syscall-provider dispatch state and more complex per-process / per-thread routing. v5 assumed a single handler array and one debug bit; that assumption is wrong on current Windows 11 builds.

An attacker that influences alternative syscall routing can intercept selected syscalls without classic SSDT modification. The trigger is the syscall itself; the command selector can be the syscall number, argument tuple, caller thread, process context, or a small per-thread state bit. From UM, the activity can look like ordinary `Nt*` calls. From KM, the abnormality is that a nonstandard provider path sees or rewrites calls that should have gone through the normal service dispatch path.

The defensive mistake is treating this as one legacy global pointer. On current Windows 11 builds, the relevant question is "which provider state and process/thread routing decisions can cause this syscall to take a different path on this build?" That requires PDB-backed or reverse-engineered baselines per build, not a universal offset. It also requires separating legitimate platform, compatibility, tracing, and security-provider state from unsigned or vulnerable-driver-written state.

Forum guidance around direct and indirect syscalls matters here because it changes the *trigger hygiene* of every syscall-backed channel in §7, §9, and §10. An attacker helper may avoid high-level Win32 APIs, issue native syscalls through copied stubs, jump into legitimate `ntdll.dll` / `win32u.dll` syscall instructions, spoof return addresses, or shape call stacks so the trigger looks like normal system-library traffic. That does not create the kernel channel by itself; it makes the user-mode half of an existing kernel hook harder to attribute.

The detection consequence is straightforward: do not classify only by "which API was imported." Normalize the event to syscall number, syscall module/stub address, return address, call stack module ownership, argument shape, and kernel-side route. A `.data` pointer hook reached through an indirect syscall is still a `.data` pointer hook. The syscall wrapper only affects how confidently the defender can attribute the UM caller.

**Detection.** Validate syscall dispatch state against clean-build baselines, using build-specific knowledge of the current syscall-provider model. Monitor unusual syscall argument patterns from the protected process, especially repeated low-noise syscalls whose arguments encode selectors but have little legitimate semantic value. Correlate with private executable mappings, process instrumentation callbacks (§10.7), vulnerable-driver load, and kernel write telemetry. On Windows 11 builds that use syscall-provider dispatch state, validate provider slots, per-process dispatch context, and per-thread flags rather than only checking a single legacy global handler array. HVCI may prevent writes to some service-descriptor structures, but legitimate syscall-provider mechanisms still need inventory.

### 10.9 PerfInfoLogSysCallEntry Stack Replacement

`PerfInfoLogSysCallEntry` is an internal syscall tracing function. A pattern observed in some security software replaces a syscall-handler address stored on the kernel stack at a precise tracing point, allowing a wrapper to run before forwarding to the original path. The UM side simply issues syscalls.

As a covert channel, the interesting property is not the trace function itself; it is the narrow moment where syscall metadata, stack-resident dispatch state, and performance tracing logic intersect. A wrapper can use selected syscall numbers and argument shapes as selectors, observe the caller before normal dispatch resumes, and return through the original path so that SSDT bytes and common syscall stubs remain clean.

This is more subtle than direct SSDT modification but mostly academic for game cheats and most commodity malware. §10.7 and §10.8 are simpler, more general, and easier to maintain across builds. Still, it belongs in the document because defenders who only hash SSDT entries can miss stack-mediated or trace-path-mediated syscall interception.

**Detection.** Validate syscall tracing code, call targets, and control flow against a clean build. Monitor unexpected hooks around `PerfInfoLogSysCallEntry` or adjacent syscall tracing paths. Where advanced telemetry permits, correlate with altered kernel stack return or handler pointers, unusual ETW/perf tracing enablement, and syscall argument patterns that look like selectors rather than normal API use. Treat this as a high-skill hunting area with significant noise from legitimate security products that have experimented with similar techniques.

### 10.10 NtRegisterThreadTerminatePort

`NtRegisterThreadTerminatePort` is an undocumented syscall that registers an LPC/ALPC port to receive `LPC_CLIENT_DIED`-style notification when the calling thread terminates:

```cpp
NTSTATUS NtRegisterThreadTerminatePort(
    IN HANDLE PortHandle);
```

The attacker creates or connects to an ALPC port, registers threads, and treats thread exits as signals, which is useful for watchdogs, teardown signaling, and lifecycle state. It can also invert the meaning: a helper intentionally terminates a short-lived thread to signal "advance epoch", while the receiving port turns lifecycle noise into a command bit.

This surface is low bandwidth, but it is attractive for cleanup and coordination because thread termination is a normal event and the notification path is native. It pairs well with §2.2 ALPC ports and §10.1 trapped threads: one thread waits, another exits, the port notification wakes the owner, and a different channel carries the real payload.

**Detection.** Monitor abnormal ALPC port registrations. Where ETW or syscall telemetry exposes thread-terminate port registrations, correlate with protected-process threads registering ports owned by unknown processes. Store registering TID, port owner, port name, thread lifetime, exit status, and whether the same port also carries ordinary ALPC messages. The legitimate population is small (some system components and diagnostics); any registration from workload-adjacent unknown code is high signal.

### 10.11 WaitOnAddress and Keyed-Event Rendezvous

`WaitOnAddress` is a Windows 8+ user-mode synchronization primitive that waits until a value at an address changes. It is efficient because no named event object is required: a thread waits on a memory address, another thread in the same process changes the value and calls `WakeByAddressSingle` or `WakeByAddressAll`. Microsoft documents that the wake is process-local; shared memory alone does not let a helper process wake a waiter in the protected process. The primitive becomes interesting only when the shared value is paired with a same-process wake surrogate, injected helper thread, timeout/spurious-wake loop, keyed-event style runtime primitive, or another trigger path. Native keyed-event mechanisms sit underneath similar futex-style designs, and some runtimes build higher-level synchronization on this pattern.

By itself, `WaitOnAddress` does not let a kernel driver wake an arbitrary user-mode waiter through the documented API. The abuse appears when combined with §8.1, §8.3, or §8.8:

1. KM and UM share or mirror a small mailbox field.
2. UM parks a thread in `WaitOnAddress` on that field or in a runtime primitive that lowers into the same address-wait behavior.
3. The attacker changes the mailbox value from another UM helper, through a mapped section, through PEB/TEB mirroring, or through a kernel write followed by a same-process wake surrogate.
4. The waiting thread wakes, validates the new value, and treats it as a command epoch.

The attraction is *absence of objects*. There is no named event, no semaphore, no pipe, and no alertable APC. The wait target is just an address. CPU usage is lower than polling, and the user-mode stack can look like an ordinary runtime wait. This is especially useful for attacker stacks that already have a shared section but want to remove the obvious "event object named GpuCacheWReady" artifact.

**Detection.** This is hard to see directly without user-mode instrumentation, so treat it as a correlation layer:

1. Identify suspicious shared memory first: anonymous sections, private RW mappings, PEB/TEB mirrors, or unusual mapped files.
2. Inspect long-lived protected-process/helper threads waiting in synchronization APIs with start addresses in private or unknown modules.
3. Sample wait stacks and wait durations. A thread that spends the whole match waiting on address-sized state in a private mapping is more interesting than a normal engine worker waiting on a documented event.
4. Correlate mailbox mutations with thread wakeups. Repeated writes to a 1/2/4/8-byte field followed immediately by worker activity is the pattern.
5. Remember spurious wake semantics. Correct code re-checks the value after wake; a tight loop of wake/re-check around a high-entropy field is more suspicious than ordinary one-shot runtime synchronization.

False positives are common in modern runtimes, allocators, browsers, and game engines. `WaitOnAddress` presence is not a finding. The finding is address-wait synchronization over an unexplained shared mapping whose update cadence matches command traffic.

### 10.12 Thread-Pool Work Items, WorkerFactory, and Completion-Queue Triggers

Black Hat Europe 2023's Pool Party research is user-mode process-injection research, but it changes how defenders should think about "normal" user-mode execution triggers. Modern Windows processes commonly have thread-pool infrastructure: worker factories, worker threads, task queues, timer queues, I/O completion queues, wait work items, ALPC work items, job work items, and file-I/O completion work. An attacker that already has a kernel write primitive, duplicated handle path, or injected helper does not need to create a suspicious remote thread. It can arrange for existing thread-pool workers in the protected process or a trusted helper process to execute a queued callback as a consequence of an ordinary-looking event.

**Presented case note.** SafeBreach's writeup describes multiple work-item families, including asynchronous paths such as TP_IO, TP_ALPC, TP_JOB, and TP_WAIT that can be associated with completion queues and completion keys. The communication translation is: the work item is usually not the payload. It is the wake edge that tells a legitimate worker to consume a section, MDL mailbox, ALPC view, heap buffer, or COM/RPC method result. For defenders, record worker-factory handles, completion queues, completion keys, wake source type, callback target, and the first memory object touched after wake.

For KM-UM communication, the important idea is not remote-code injection by itself. It is *trigger laundering*. The kernel side or privileged broker causes a legitimate object transition; the user-mode thread pool wakes and runs code that reads a mailbox, consumes a shared section, opens an ALPC port, or processes a command. The visible event can be "file I/O completed", "ALPC message arrived", "job notification delivered", "wait object signaled", or "timer expired" rather than "unknown thread started."

Useful channel shapes are:

1. *WorkerFactory wake trigger.* A protected process or helper process has a worker factory whose worker-thread behavior changes near protected-session runtime. The channel uses worker-thread creation or readiness as the epoch edge, while the payload lives in a mapped mailbox.
2. *TP_IO completion trigger.* A file, pipe, socket-like object, or device handle is associated with completion-style delivery; completion wakes a thread-pool callback that consumes command state.
3. *TP_ALPC trigger.* An ALPC connection or message arrival causes a thread-pool callback path. This hides the execution edge one layer below the ALPC transport described in §2.2.
4. *TP_JOB trigger.* A job notification, normally lifecycle noise, becomes a command epoch. This connects directly to §2.10 job-object completion-port channels.
5. *TP_WAIT trigger.* A signaled event, mutant-like synchronization object, or waitable state wakes the callback without any named pipe or IOCTL.
6. *TP_TIMER trigger.* A delayed timer work item lets the visible helper exit before the payload executes, which weakens parent/child attribution if the defender only looks at live processes.
7. *Direct completion-queue trigger.* I/O completion queue state or completion-key-like metadata becomes the bridge between an object event and a thread-pool callback.

This matters for covert-channel analysis because many kernel-assisted attacker stacks split responsibilities: KM produces the hidden state, UM performs overlay, input, configuration, persistence, or broker logic, and a normal-looking thread-pool wake hides when UM consumes the command. The thread pool is not the data bus. It is the execution edge that makes another bus look quiet.

#### Attacker Mechanics: Laundering the Wake Edge

The thread-pool pattern is attractive because defenders often key on new thread creation, suspicious thread start addresses, and obvious remote-thread injection. A thread-pool channel changes that question. The worker thread already exists, its start address belongs to `ntdll` or a runtime library, and the suspicious transition is not "thread started" but "work became ready."

The attacker composes three pieces:

1. *Wake source.* An event, ALPC message, I/O completion, job notification, timer, wait object, or file/device completion that is ordinary for the process role.
2. *Callback target.* Code that runs in the target process when the wake source fires. In a fully injected design this may be private code; in a more careful design it is a legitimate callback path that reads attacker-controlled state.
3. *Mailbox consumer.* A section, MDL-backed buffer, ALPC view, mapped GPU resource, or process-local heap structure that contains the actual command record.

This lets the channel hide in plain lifecycle traffic. A helper can prepare a mailbox and signal a wait object. A broker can deliver an ALPC message. A kernel component can complete a pending I/O request with a chosen status. The visible artifact is a normal worker waking up; the protocol action is what the worker reads immediately afterward.

The protocol rhythm is usually: arm a work item or completion association, update the mailbox header, trigger the wake source, let the worker consume one epoch, write status back to the mailbox, and re-arm or retire the wake source. Delayed timers and completion queues add another advantage: the process that prepared the work can exit before the command is consumed, weakening simple parent/child attribution.

**Detection.** Add thread-pool evidence to execution-flow telemetry:

1. Inventory worker-factory handles, I/O completion handles, timer queues, and thread-pool worker threads in protected-process, launcher, overlay, browser, updater, service, and helper processes.
2. Record duplicated or inherited handles to worker factories and I/O completion objects, especially when the source process is unrelated to the target process.
3. Track thread-pool worker start addresses, callback target modules, callback cadence, wait reason, and wake cause. A callback target in private executable memory or a recently mapped helper module is stronger than the existence of thread pools.
4. Correlate ALPC messages, job notifications, wait-object signals, file/device completions, and timer expirations with immediate reads from suspicious sections or MDL-backed mailboxes.
5. Treat delayed execution as evidence. A helper that exits cleanly and is followed seconds later by thread-pool execution inside the protected process is not clean just because the helper is gone.
6. Baseline legitimate engine and runtime thread-pool behavior. Unreal, Chromium overlays, voice chat, GPU vendors, anti-malware, and crash reporters all use thread pools heavily; the finding is role mismatch, private callback ownership, unexpected handle duplication, and command-cadenced wakeups.

### 10.13 Flow Deep-Dive Matrix: Trigger, Wait State, and Resume Cause

Execution-flow channels are difficult because the channel is often a transition rather than an object. A detector needs to capture where a thread waits, what wakes it, and what it does immediately after wake. Sampling only thread start addresses misses most of this class.

**Trapped user-mode thread (§10.1).** Record thread start module, current wait reason, wait API stack, wait duration, alertable state, context switches, and the first user-mode instruction path after wake. A suspicious trapped thread spends most of the protected session asleep in a private module or runtime wait, wakes in tight correlation with kernel events or shared-memory mutations, then performs short command bursts. Normal engine, browser, service, and runtime workers also sleep often, so the discriminator is unexplained wake cause and command-like post-wake work.

**APC queueing (§10.2).** APC-based channels require an alertable wait or a target thread whose delivery can be controlled. Capture alertable wait sites, queued user APC counts where visible, source process, target thread, routine address, and whether the routine belongs to a signed expected module. A channel shape is "helper queues APC -> protected thread wakes -> private routine reads mailbox." Defensive evidence improves when the APC routine target is in private memory or an injected module and the target thread has no reason to be alertable.

**Hardware breakpoints (§10.3).** Debug registers provide tiny but precise triggers. Record debug-register state per thread during trusted sampling, thread context modifications, exception cadence, and whether a VEH/SEH path consumes single-step or breakpoint exceptions. Legitimate debuggers, profilers, and anti-cheat instrumentation may use debug registers, but a protected process with persistent DRx state and no debugger or allowlisted instrumentation owner is suspicious.

**Page-fault and guard-page channels (§10.4).** Guard pages are one-shot and must be rearmed. Capture guard-page VADs, protection flips, fault addresses, handler module, rearm cadence, and whether the same address repeatedly faults with command-like timing. A memory scanner or engine allocator may fault naturally; a single 4 KB page used as a repeated mailbox trigger is different. Page-fault covert channels should be correlated with the handler chain and the backing memory's provenance.

**VEH chain injection (§10.5).** VEH channels rely on handler order. Record handler list addresses, module ownership, registration timing, exception types handled, and whether handlers return `EXCEPTION_CONTINUE_EXECUTION` after modifying context. Suspicious handlers live in private modules, register after protected workload start, handle only a narrow exception pattern, and interact with a shared mailbox or patched code path.

**NMI/IPI hijack (§10.6).** This is high-risk and usually PatchGuard/instability territory. Detection should focus on integrity of interrupt-related dispatch paths, unexpected high-rate NMIs/IPIs, and owner attribution for code reachable from those paths. Treat this as a kernel-integrity finding rather than an ordinary channel; if an attacker is here, it is already in deep kernel control.

**Process Instrumentation Callback (§10.7).** Capture the callback pointer through the process-information path or kernel view, validate target address, and monitor syscall-return behavior if instrumentation is enabled. This is high-signal when a protected process has a callback pointer into a private or unexpected module. False positives include security products and instrumentation frameworks, but those should have stable signed ownership and product context.

**AltSyscall (§10.8) and PerfInfo syscall stack replacement (§10.9).** These are syscall-provider / telemetry hot-path surfaces. Detection requires build-aware validation of syscall routing, provider tables, ETW/PerfInfo paths, and code integrity around the first few instructions. The evidence is cross-view: user-mode syscall behavior, kernel expected route, and actual observed target diverge. These checks are expensive; reserve them for high-trust kernel detector builds and lab validation.

**Thread terminate ports (§10.10).** This is a lifecycle signal, not a payload channel. Record ALPC port, registered thread, owner process, and exit timing. A protected-process thread registering a terminate port owned by an unknown helper is unusual. Correlate with helper shutdown or cleanup behavior.

**`WaitOnAddress` (§10.11).** Address-wait channels are objectless, so detection begins with shared-memory suspicion. Store wait stacks, address ranges if instrumented, mailbox field mutations, and wake-to-work timing. The finding is "thread waits on address inside unexplained shared memory and wakes on command cadence," not use of the API.

**Thread-pool work items and WorkerFactory triggers (§10.12).** Treat thread-pool execution as a wake-source problem. Store worker-factory handles, I/O completion queues, callback target addresses, ALPC/JOB/WAIT/TIMER associations, duplicated handle sources, timer due times, and post-wake memory access. The suspicious pattern is "ordinary object completion wakes thread-pool code that immediately consumes a suspicious mailbox," especially when callback ownership is private or unrelated to the process role.

---

## 11. CPU and Hypervisor Channels

The channels in this section sit *below* the kernel: they use page-table state, MSRs, descriptor tables, or hypervisor-managed memory views. They are the highest-value attacker surfaces and the highest-cost defender surfaces. PatchGuard covers some of them aggressively; others are intentionally outside its scope. Software anti-cheat alone cannot close the upper-bound: at L4 the defender's strongest move is usually platform attestation, not behavioral detection.

### 11.1 EPT MMIO Channel

A malicious hypervisor creates EPT (Extended Page Table) mappings where selected guest physical accesses trap to the hypervisor. The trapped access acts like MMIO: guest code reads or writes selected addresses, the hypervisor interprets the access as a command, and the hypervisor returns data or modifies guest state in response.

This is the canonical L4 channel. The hypervisor side has full visibility into guest physical memory, can hide its own footprint from the guest, and can present different memory views to the guest kernel versus the guest user mode. The guest side does not see the hypervisor at all unless it specifically probes for it.

The channel has three common shapes:

1. *Trap-on-read.* Guest reads a magic address; the hypervisor returns data derived from hidden game memory or external state.
2. *Trap-on-write.* Guest writes a selector or command; the hypervisor updates hidden state, EPT mappings, or an external output path.
3. *Dual-view memory.* The same guest physical page resolves to different contents depending on whether the observer is the cheat, anti-cheat, or normal kernel path.

There is also a hypercall-style mailbox variant. Instead of touching a magic memory page, the guest executes an instruction or operation that the hypervisor can intercept by design: `CPUID`, `VMCALL` / `VMMCALL`, selected MSR reads/writes, I/O port accesses, or a deliberately faulting instruction. A malicious hypervisor treats a register tuple as `(magic, command, pointer, length)` and returns data in registers, a mapped page, or a separate shared buffer. Public cheat discussions around Voyager-like hypervisors and `vmexit` keys point to this design pressure: keep the guest artifact tiny, put the real logic below the guest, and trigger only when a private key or register shape is present.

For a defender, the exact instruction is less important than the VM-exit contract. A normal system may execute `CPUID` constantly and may run under Hyper-V/VBS. A cheat hypercall channel is suspicious when a game helper or injected module issues repeated low-level probes with unusual leaves, magic constants, tight timing loops, or register values that correlate with hidden memory reads. A competent attacker can emulate most guest-visible hypervisor probes, so this remains supporting evidence unless platform attestation fails.

Black Hat USA 2018's Hyper-V architecture research broadens this beyond raw `CPUID` / `VMCALL` thinking. In a Hyper-V environment, the highest-value communication path may be a root-partition service, VMBus channel, synthetic device, virtual switch, virtual storage path, MMIO interception path, or user-mode VM worker process mapping rather than a direct guest-visible hypercall. The key observation is that much of the practical Hyper-V attack surface sits in the root partition and its service stack, while guests communicate with it through well-defined interfaces such as VMBus, synthetic devices, intercepted I/O ports, MMIO ranges, and hypercall-forwarded paths.

**Presented case note.** The Hyper-V architecture presentation maps to covert communication as a trust-boundary shift. The guest-visible artifact can be a VMBus message, synthetic-device ring, MMIO access, I/O-port access, or VM worker relationship; the controlling logic lives in the root partition or a coupled hypervisor component. The evidence fields are therefore synthetic-device class, VMBus channel identity, ring-buffer ownership, MMIO/port access cadence, root-side service/process identity, VM worker mappings, and whether this virtualization traffic appears only during protected workload runtime.

For covert-channel analysis, this produces a different L4 shape:

1. *Synthetic-device mailbox.* A malicious or coupled virtualization component exposes a synthetic device whose ring buffer, message queue, or MMIO range carries command state.
2. *VMBus ring traffic.* Guest-side code sends ordinary-looking VMBus messages; the root-side component interprets selected message shapes as cheat commands.
3. *Root-partition broker.* The visible user-mode artifact is a VM worker, virtualization service, container component, or root-partition helper rather than a process owned by the protected workload.
4. *Shared-page or aperture rendezvous.* The host maps guest physical pages and uses them as a mailbox while the guest sees only normal synthetic-device or MMIO behavior.
5. *VBS adjacency.* On consumer systems with VBS / Hyper-V enabled, a malicious component may try to blend into legitimate virtualization traffic instead of presenting a separate hypervisor signature.

This is rare in commodity cheats, but it matters for lab policy and tournament hardware because a guest-side anti-cheat can be perfectly clean while the root-side component sees memory, input, and timing from outside the guest trust boundary.

The guest-visible code can be tiny: a memory load, a store, a timing probe, or a syscall that eventually touches a watched page. The real protocol lives below the guest. That is why local code-integrity checks and driver-object inventories can be perfectly clean while the cheat still sees memory.

#### Attacker Mechanics: Guest Stub, VM-Exit Contract, Hidden State

An EPT or hypercall channel splits the implementation across trust boundaries:

1. *Guest stub.* The visible code in the game, helper, or driver performs a small operation: read a watched address, write a selector, execute a probe instruction, touch an I/O port, or call an API that eventually reaches a watched page. The stub can be tiny because it does not contain the memory reader or decision engine.
2. *Exit condition.* The hypervisor decides which access pattern causes a VM exit: EPT permission fault, MMIO range access, CPUID leaf, MSR number, I/O port, VMCALL-like instruction, timing-sensitive page, or synthetic-device queue event.
3. *Hidden state.* The hypervisor stores the real command table, memory translations, entity cache, feature flags, and output data outside the guest's normal kernel memory view.
4. *Reply injection.* The result is returned by changing register values, emulating a memory read, modifying a guest page, completing a synthetic-device message, changing timing, or updating a shared page that the guest believes is ordinary memory.

This architecture is powerful because the guest artifact can be intentionally uninteresting. A static scan may find only a `CPUID` loop, a memory load, or a small driver that appears to do feature probing. The payload logic lives in the hypervisor or root-side service, where guest-side anti-cheat cannot directly inspect it.

The attacker's protocol design still resembles the L1-L3 channels: magic, version, command ID, pointer or guest physical address, length, flags, sequence, and status. The difference is that the selector may be encoded in registers, page offset, access size, faulting address, I/O port, or synthetic-device message type. The payload may be returned through registers for small values, through an emulated memory page for medium responses, or through a root-side shared buffer for larger data.

Operationally, this channel is most attractive when the attacker wants clean guest telemetry. No suspicious device object, ALPC port, registry callback, or section needs to exist in the guest if the hypervisor can read game memory directly and feed only small decisions back to the visible stub. The cost is high: platform compatibility, VBS/Hyper-V coexistence, attestation risk, and the need to emulate guest-visible hypervisor behavior consistently.

**Detection.** Hypervisor presence inconsistencies are the main software-side signals: timing differences between VM-exit-heavy and normal operations, `CPUID` and MSR responses that disagree with VBS-reported state, unexpected hypervisor signatures, EPT-view inconsistencies, and unexplained TLB/timing behavior. None of them are reliable against a competent attacker hypervisor that emulates the expected platform consistently.

For hypercall-style mailboxes, record suspicious `CPUID` leaves/subleaves, repeated `VMCALL`/`VMMCALL` exceptions where visible, MSR access patterns, I/O port accesses, caller module, thread, timing, and whether the register tuples contain stable magic values. For Hyper-V / VMBus-style paths, record hypervisor presence state, VBS mode, root-partition / guest relationship if known, synthetic device inventory, VMBus channel classes, virtual switch/storage activity, guest service drivers, unusual MMIO or I/O-port access cadence, and whether virtualization traffic appears only during protected workload runtime. Treat these signals as L4 correlation inputs, not standalone ban triggers. Legitimate Hyper-V, WSL2, Windows Sandbox, VBS, containers, enterprise security products, CPU feature detection, DRM, and performance tooling all create VM-exit-heavy or VMBus-heavy paths.

Platform attestation is the durable defense. A TPM-anchored Quote that includes PCR[17] (DRTM, via Intel TXT or AMD SKINIT) and the VBS-related measurements proves the secure execution environment was established correctly, independent of what a guest-side hypervisor presents. Without attestation, software detection is limited to corroborating signals.

Legitimate virtualization, VBS, Hyper-V, anti-cheat hypervisors, and enterprise security products produce hypervisor signals. Distinguishing a legitimate hypervisor from a malicious one requires either a vendor allowlist or platform attestation, not raw signature presence.

### 11.2 CR3 and Page-Table Walk

CR3 manipulation and direct page-table walks are more often used for *memory access* and *hiding* than for high-bandwidth command traffic. The privileged component reads CR3, walks page tables, or switches address spaces to access memory without using ordinary handles or copy APIs. The UM side receives results through another channel or triggers memory reads whose translation is handled by KM / hypervisor code.

The attacker advantage is bypass of user-mode handle and VAD monitoring. Hypervisor-backed variants can present different views to defender code versus attacker code by switching EPT contexts on the fly.

As a channel, CR3/page-table access usually provides address translation and stealth rather than the payload bus itself. The payload still returns through a section, APC, firmware table, external DMA bridge, or HID path. The page-table component is the hidden read/write engine: it discovers where the game object lives, bypasses handle telemetry, and optionally hides the modified mapping from one observer.

The practical variants differ by privilege:

1. *Kernel walker.* A signed or vulnerable driver walks page tables directly.
2. *CR3 switcher.* The component switches or borrows address spaces to read memory with fewer API artifacts.
3. *Hypervisor split view.* EPT chooses which translation view each observer receives.

**Detection.** Cross-view validate VADs, PTEs, working sets, and image-load telemetry; a region with no VAD entry but valid PTEs and resident pages is suspicious. Compare section objects, prototype PTEs, file backing, and ETW image-load history. Monitor CR3 reads or page-table walks in unknown drivers where possible, and correlate with BYOVD load, disabled HVCI, or unusual kernel memory reads. Use HVCI / VBS / kernel memory integrity to reduce tampering, and treat full detection of hypervisor-backed page-table manipulation as policy / hardware territory rather than something software anti-cheat alone can solve.

### 11.3 MSR Manipulation

MSRs store CPU state. Some are aggressively PatchGuard-protected; others are not. The cheat can encode a few bits in writable MSRs or use MSR changes as triggers, but UM cannot read or write MSRs directly without a driver or vulnerable driver path.

MSR channels split into two families. Critical control MSRs such as `IA32_LSTAR` are attractive in theory but effectively PG-conflict on modern systems. Low-impact debug, performance, and power-management MSRs are more plausible as low-bit side channels, but they are noisy because hypervisors, profilers, CPU utilities, and power management legitimately touch them. The realistic cheat value is not bandwidth; it is hidden per-core state, timing modulation, or a trigger that another privileged component reads.

**PatchGuard risk by MSR.**

| MSR | Name | PatchGuard Class | Cheat Use |
|-----|------|------------------|-----------|
| `IA32_LSTAR` (`0xC0000082`) | Syscall handler base | PG-Conflict | Changing it bugchecks rapidly. Read-only monitoring only. |
| `IA32_KERNEL_GS_BASE` (`0xC0000102`) | Per-CPU kernel GS | Not generally PG-protected | Low practical value. |
| `IA32_DEBUGCTL` (`0x1D9`) | Debug control | Not generally PG-protected | Low-bandwidth side channel. |
| `IA32_PERF_GLOBAL_CTRL` (`0x38F`) | Performance counter control | Not generally PG-protected | Low-bandwidth side channel. |
| `IA32_CLOCK_MODULATION` (`0x19A`) | Clock modulation | Not generally PG-protected | Very low bandwidth. |
| `IA32_STAR` (`0xC0000081`) | Legacy syscall | PG-Conflict | Not used on x64 for this purpose. |

**Detection.** Capture boot baselines for critical MSRs. Treat `IA32_LSTAR` changes as P0 (they correspond to syscall handler hijacking). For non-critical MSRs, compare per-core values against expected ranges and expected owner components. Store per-core value, sampling time, CPU model, hypervisor/VBS state, driver load context, and whether the value changes in lockstep with game/helper activity. Correlate MSR changes with driver-load events and privileged-instruction usage. Performance tools, hypervisors, power management, and CPU-vendor utilities legitimately modify some MSRs; the discriminator is owner driver, specific MSR, and game-coupled timing.

### 11.4 IDT and GDT Entry Hijack

Interrupt Descriptor Table and Global Descriptor Table entries redirect exception, interrupt, or segmentation-related control flow. On modern Windows x64, direct IDT/GDT hijacking is generally PG-Conflict and highly unstable; this surface has largely been retired by mainstream attacker tooling.

The residual value is specialized triggering. A changed #DB, #PF, #BP, NMI, or other descriptor path can intercept exceptions that the cheat already uses elsewhere in §10. But direct descriptor tamper is so noisy and dangerous on modern retail Windows that a production cheat usually prefers VEH, debug registers, page guards, or hypervisor EPT traps.

**Detection.** Baseline IDT/GDT entries per CPU at boot. Validate handler targets against expected kernel ranges and clean-build metadata. Store per-CPU IDTR/GDTR base and limit, descriptor attributes, target address, target module, and whether the target bytes match clean image code. Treat any modified descriptor path as critical unless explained by a trusted hypervisor or platform component. Legitimate hypervisors, kernel debuggers, and platform security features can affect low-level descriptor handling, so the signal is "unexplained modification" not "any modification."

### 11.5 CPU/Hypervisor Deep-Dive Matrix: Software Signal vs. Attestation Boundary

The L4 boundary is where local software certainty breaks down. A document that treats EPT, CR3, MSR, IDT, and GDT findings like ordinary IPC findings overpromises. Split evidence into "guest-visible anomaly" and "platform-attested state."

**EPT/MMIO (§11.1).** Guest-visible signals include timing anomalies, inconsistent CPUID/MSR behavior, unexpected hypervisor leaves, nested-virtualization artifacts, and memory-view inconsistencies. A strong attacker can emulate many of these. Platform evidence includes Secure Boot, DRTM, VBS/HVCI, IOMMU, and TPM quote material. For ranked enforcement, use local heuristics as suspicion and attestation as the policy gate.

**Hypercall mailboxes (§11.1).** CPUID/VMCALL/VMMCALL/MSR/I/O-port channels are low-artifact guest triggers. Store instruction family, register tuple, caller module, frequency, timing distribution, and whether the tuple contains a stable private key. The evidence is meaningful when paired with hypervisor-state inconsistency, impossible game knowledge, or failed attestation. Do not ban on unusual CPUID leaves alone; legitimate feature detection and virtualization stacks are noisy.

**CR3/page-table walk (§11.2).** Software checks can compare VADs, PTEs, working sets, image-load events, and section mappings. Hypervisor-backed cheats can present different page tables or EPT views to different observers. The defender should therefore collect cross-view inconsistencies but avoid claiming complete coverage unless a trusted lower layer vouches for the memory view.

**MSR manipulation (§11.3).** Separate catastrophic MSRs from low-bit side-channel MSRs. `IA32_LSTAR` and syscall-route MSRs are critical integrity checks; performance and power MSRs are noisy and require owner attribution. Store per-core values, sampling time, expected platform range, and driver/hypervisor components known to manage the MSR. A single unexpected noncritical MSR value is not enough; a noncritical MSR changing in lockstep with a game helper is meaningful.

**IDT/GDT (§11.4).** Descriptor tables are high-integrity structures. Capture per-CPU base, limit, entry targets, and target module classification. Legitimate variation exists with hypervisors and debugging, but retail systems should be stable. Any unexplained descriptor target outside expected kernel/hypervisor code should be escalated as platform compromise, not just covert-channel telemetry.

---

## 12. Persistent Storage and Firmware Channels

The channels here persist across reboot. They are not high-bandwidth command paths during a session: they are configuration, license-state, and bootkit-coordination surfaces. The defender's question is rarely "what is moving through this channel right now"; it is "what is stored here that should not be."

### 12.1 Registry Hidden Values

Registry values can be hidden with SACL tricks, restricted SIDs, symbolic-link keys, unusual Unicode names (combining characters, BIDI overrides, NUL-prefixed names that bypass naive enumeration), volatile keys, or ACLs that block the most common enumeration tools. The attacker uses the registry for configuration, license state, reboot-persistent command state, and defensive tripwires, often paired with `CmRegisterCallbackEx` (§5.2) to detect when defenders enumerate the path.

**Detection.** Combine these signals:

- *Cadence.* Monitor protected-runtime registry writes by the protected process, helper processes, and unknown drivers. High-frequency polling and volatile-key creation near protected workload launch are atypical.
- *Enumeration.* Use backup/restore privileges and security-descriptor inspection to enumerate paths that ordinary tools cannot see.
- *Symbolic links.* Resolve registry symbolic links before trusting any path. The same path string can be redirected to different physical hives without naive enumeration noticing.
- *Callback correlation.* Protected-process or helper registry writes that fire callbacks in unknown drivers are high signal.

Games, launchers, anti-cheat, EDR, overlays, and GPU tools all use the registry. Cadence, path ownership, and ACL abnormality matter more than presence.

### 12.2 UEFI Runtime Variables

UEFI runtime variables are firmware-backed key-value entries that persist across reboot. Windows exposes them through `GetFirmwareEnvironmentVariableExW` / `SetFirmwareEnvironmentVariableExW` in user mode (with `SE_SYSTEM_ENVIRONMENT_NAME` privilege) and `ExGetFirmwareEnvironmentVariable` / `ExSetFirmwareEnvironmentVariable` in kernel mode at `PASSIVE_LEVEL`.

The namespace is `(VariableName, VendorGuid, Attributes)`. That tuple is the unit defenders should reason about. Two variables with the same visible name but different vendor GUIDs are different variables; a familiar-looking name under an attacker-controlled GUID is not familiar. Attributes also matter: non-volatile, boot-service-access, runtime-access, authenticated-write, and append-write semantics change survivability and who can touch the value.

The attacker uses UEFI variables for boot-persistent storage: HWID spoofers, license state, bootkit coordination, delayed activation flags, and "last known good" rollback state. State stored here is outside normal file and registry scans, and on some platforms persists across OS reinstall. A small variable can be enough: a GUID namespace, an encrypted license blob, a seed, a hardware-profile delta, a boot counter, or a command epoch.

The stealth pattern is GUID laundering. The attacker chooses a vendor-looking GUID, copies an OEM-style variable name, or writes a compact binary value whose size resembles firmware configuration. The value may be written only during setup or only after anti-cheat shutdown, leaving no obvious runtime file artifact.

**Detection.** Monitor unusual UEFI variable names, vendor GUIDs, attributes, sizes, and write cadence. Track `ExSetFirmwareEnvironmentVariable` and user-mode firmware-environment API usage, including caller process, privilege state, and driver image. Compare firmware variables against known OEM, Windows, boot-manager, BitLocker, capsule-update, and platform-security namespaces. Preserve read-only inventory snapshots so incident response can diff `(name, GUID, attributes, size, hash)` across boots. Firmware tools, OEM utilities, BitLocker, boot managers, and update tools use UEFI variables legitimately; the discriminator is GUID namespace, variable-name pattern, attributes, caller identity, and protected-workload timing rather than API use alone.

### 12.3 TPM NV Indices

TPM 2.0 Non-Volatile indices store small blobs inside the TPM. Depending on index policy, they can be read and written through TBS (TPM Base Services) or platform TPM stacks. This is not a bandwidth channel; index sizes are small, but it is persistent secure-ish storage, useful for license state, spoofing metadata, and attestation experiments.

The relevant unit is the NV index handle plus its public area: size, attributes, name algorithm, authorization policy, read/write permissions, and whether the index can be extended, counter-like, bit-like, or ordinary. An attacker does not need much space. It can store a license epoch, hardware-binding seed, server token, boot counter, or attestation experiment output. The TPM gives persistence and a hardware-adjacent hiding place; it does not give a practical high-bandwidth command bus.

On Windows, user mode usually reaches the TPM through platform services or TBS. `Tbsip_Submit_Command` is the important low-level tell because it submits raw TPM command buffers through a TBS context. A workload-adjacent helper that repeatedly submits `NV_Read`, `NV_Write`, `NV_DefineSpace`, `NV_UndefineSpace`, `Policy*`, or authorization commands near protected workload launch is much more suspicious than a one-time Windows Hello or BitLocker operation during sign-in or boot.

**Detection.** Enumerate unexpected NV index handles where platform access permits, and record handle, size, attributes, authorization policy visibility, owner hierarchy, and name. Monitor TBS command submission during protected workload runtime; normalize commands by ordinal, caller, TBS context, locality where visible, size, return status, and timing. Correlate TPM access with unknown helper processes, vulnerable-driver activity, firmware-variable writes (§12.2), and license-state file or registry updates. Windows Hello, BitLocker, platform attestation, enterprise security, and OEM tooling legitimately use the TPM; the discriminator is process owner, command pattern, and launch-time coupling to the protected workload.

### 12.4 Common Log File System (CLFS) Streams

CLFS is a general-purpose logging service available to user-mode and kernel-mode clients. Microsoft documents dedicated and multiplexed logs, log sequence numbers, marshalling areas, stable storage, metadata, and both Win32 and kernel-mode interfaces. User mode can create or open logs with paths such as `LOG:c:\\path\\name`, which materialize as `.blf` files and associated containers. Kernel clients can write and read records through the CLFS library. That makes CLFS a natural persistent rendezvous surface: a real OS logging subsystem, not an ad hoc file format.

An attacker uses CLFS differently from normal logging:

1. The log path is chosen to look like a telemetry, crash, update, or service log under a plausible vendor directory.
2. Records carry encrypted configuration, license state, hardware profile deltas, kernel scan results, or reboot-to-reboot command state.
3. LSN ordering is used as an epoch counter. The newest record wins; older records provide rollback or anti-forensic padding.
4. UM and KM both read the same stream, or a UM service translates between CLFS and a kernel-private channel.
5. Containers may be preallocated, renamed, ACL-protected, or placed under directories that normal product-focused scans ignore.

The attraction over a flat file is operational polish. CLFS has a real API, stable storage semantics, marshalling, record headers, multiplexed streams, and a history of use by system components. It also produces artifacts that many detectors do not parse deeply: `.blf` files, container files, stream metadata, and LSN state rather than obvious JSON or binary config blobs.

**Detection.** Add CLFS to persistent-artifact triage:

1. Enumerate `.blf` and CLFS container files created or modified near protected workload runtime, especially under user-writable vendor-looking directories.
2. Track `CreateLogFile` / CLFS API usage from workload-adjacent processes and services. Most games, overlays, and ordinary protected workloads do not need CLFS directly.
3. Inspect ACLs, owner SIDs, timestamps, stream names, container counts, and whether logs are reset or truncated around anti-cheat start.
4. Correlate CLFS writes with driver load, registry callbacks, or process start. A log that changes only when an unknown driver is loaded is not normal telemetry.
5. Parse enough metadata to distinguish real product logs from opaque command records. High-entropy fixed-size records, monotonically increasing small command blobs, or records whose size distribution does not match text/event logging are hunting signals.

False positives come from system components, databases, enterprise agents, and security tools. Score workload adjacency and role. A SQL engine or enterprise backup agent using CLFS is expected; a per-user "GPU cache" directory with fresh CLFS containers touched only during protected sessions is not.

### 12.5 ACPI Control-Method Evaluation

ACPI is already present in §3.1 as a firmware-table provider. A separate, easily missed path is *control-method evaluation*. Microsoft documents `IOCTL_ACPI_EVAL_METHOD` and `IOCTL_ACPI_EVAL_METHOD_EX` as requests that evaluate ACPI namespace methods for a device. `Acpi.sys` handles the request for devices described by ACPI tables, and the request carries a method name, input buffer, output buffer, and target device object. Starting with Windows 8, UMDF drivers can use these requests as well, which makes the path not purely WDM/KMDF.

This is not a mainstream cheat channel today, but it is a credible OEM-camouflage surface. Many laptops and motherboards expose vendor ACPI methods for thermal policy, performance mode, keyboard backlight, fan curves, battery, sensors, embedded controller access, and device-specific configuration. A malicious or cooperating driver can send ACPI method-evaluation requests to a legitimate ACPI PDO and encode command state in method name, integer/string/custom arguments, output size, returned package values, or status. A user-mode helper usually cannot issue these IOCTLs directly to arbitrary ACPI PDOs, but it can talk to an OEM service, UMDF driver, vendor control panel, or attacker-owned proxy that performs the evaluation.

Practical channel shapes:

1. *Vendor-method selector.* `_DSM`, vendor-specific methods, or device-private method names act as selectors. The payload is a small integer, string, or custom argument package.
2. *Embedded-controller side effect.* The ACPI method touches EC-backed state that another driver, service, or firmware path later observes.
3. *OEM-service proxy.* UM talks to a normal-looking vendor utility; the utility or its driver evaluates ACPI methods and returns status. The attacker hides behind platform-control software.
4. *Output-buffer mailbox.* The ACPI method returns a small package or buffer whose shape is interpreted by a driver or helper.
5. *Phase trigger.* The request does not carry a payload; the mere method evaluation or returned status transitions another channel.

**Detection.** ACPI method evaluation should be treated as firmware-adjacent telemetry:

1. Record `IOCTL_ACPI_EVAL_METHOD` / `_EX` requests where feasible: caller driver, target PDO, device stack, method name, input argument type, input size, output size, status, and timing.
2. Attribute the higher-level owner. Is the request coming from an OEM ACPI/filter driver, UMDF device stack, thermal service, power service, or an unrelated protected-runtime driver?
3. Baseline vendor utilities before protected workload launch. Thermal/fan/RGB/performance tools are noisy at boot and profile changes, but not usually at fixed command cadence during a protected session.
4. Flag role mismatch: a storage, input, anti-cheat-adjacent, or generic "system monitor" driver issuing vendor ACPI method requests without owning that device stack.
5. Correlate ACPI activity with firmware-table provider queries (§3.1), WMI provider blocks (§4.3), power/PnP callbacks (§5.5), and UEFI-variable writes (§12.2). OEM control software often uses several of these together; attacker tooling may imitate only one or two.

False positives are OEM-heavy. Do not block on ACPI method evaluation alone. The evidence becomes meaningful when the owner is wrong, the cadence is workload-coupled, the method set is tiny and selector-like, or the request appears immediately after an unknown driver loads.

### 12.6 KTM, TxF, and Transacted Registry Channels

Kernel Transaction Manager is the kernel component behind transactional resources such as Transactional NTFS and the Transacted Registry. Microsoft documents the programming model as creating a transaction handle and passing it to transacted file or registry APIs. The important defensive consequence is that an operation can have a *dirty transaction view*, a committed view, and a rollback path. A scanner that observes only final committed file/registry state can miss command state that existed long enough to trigger a callback, map a section, or feed a cooperating process, then rolled back.

The attacker value is not durability; CLFS, registry, and UEFI variables are better for that. The value is *ephemeral committed-state avoidance*:

1. *Transacted registry trigger.* UM creates or opens a key through `RegCreateKeyTransacted` / `RegOpenKeyTransacted`, writes selector values, and rolls back after the kernel registry callback or cooperating driver has seen the pre-operation data.
2. *Transacted file staging.* UM opens a file through `CreateFileTransacted`, writes a dirty view, maps or reads through a transacted handle, then rolls back so ordinary file scans see the committed clean file.
3. *Minifilter transaction context.* A file-system minifilter sees transaction-aware operations and transaction context, allowing the attacker to treat transaction ID, commit/rollback timing, or dirty-view access as the command.
4. *Rollback as acknowledgement.* `CommitTransaction` and `RollbackTransaction` become protocol edges: commit means "apply"; rollback means "consume and erase."
5. *TxF metadata artifact.* `$TxfLog` and transaction metadata may preserve forensic traces even when user-visible file content rolls back. That can be a hunting opportunity.

This should be treated as a niche but high-interest channel. TxF is deprecated and not a preferred Microsoft development path, but the APIs still appear in modern documentation and historical offensive research around process doppelganging keeps the primitive alive in defender vocabulary. For covert KM-UM communication, the realistic use is not full process creation. It is small, rollback-friendly command staging paired with §5.2 registry callbacks, §5.4 minifilters, or §8.1 section mapping.

**Detection.** Add transaction awareness to registry and file telemetry:

1. Record transaction object handles, creator process, create/commit/rollback timing, enlistments where visible, and which file or registry handles are associated with the transaction.
2. For registry callbacks, preserve transaction context when available: key path, operation class, value type, value size, transacted vs non-transacted view, and whether the transaction later commits or rolls back.
3. For file paths, record `CreateFileTransacted` usage, transacted directory handles, miniversion/dirty-view indicators, mapped sections created from transacted handles, and minifilter transaction context.
4. Correlate rollback-heavy transactions with protected workload runtime. Backup tools, installers, databases, and system services may use transactions; games, overlays, and ordinary protected workloads rarely need repeated transacted registry/file operations during a protected session.
5. Preserve forensic metadata rather than trying to clean it live. Transaction logs and TxF metadata are fragile; aggressive cleanup can corrupt legitimate state.

False positives include installers, backup/restore, enterprise agents, database-like workloads, and legacy applications. Suspicion rises with a small fixed set of transacted paths, short lifetime, rollback-heavy pattern, and correlation with callbacks or unknown driver activity.

### 12.7 Persistence Deep-Dive Matrix: Namespace, Policy, and Survivability

Persistent channels are rarely live command buses. Their value is survivability: configuration, license state, hardware identity deltas, boot coordination, and delayed activation. The defender should treat them like forensic artifacts with provenance and retention.

**Hidden registry values (§12.1).** Record full key path after symbolic-link resolution, hive, value name bytes, normalized Unicode form, type, size, security descriptor, owner SID, last-write time, and whether backup/restore enumeration sees more than ordinary enumeration. Suspicious artifacts often use visually normal names with hidden Unicode behavior or ACLs that block simple scanners. Pair registry storage with registry callback evidence from §5.2 whenever possible.

**UEFI variables (§12.2).** Store vendor GUID, variable name, attributes, size, write time if available, caller process/driver, and privilege context. The high-signal case is a non-OEM GUID or vendor-looking GUID used by a workload-adjacent helper, especially if writes happen near protected workload or defender startup. Because firmware variables can be sensitive, detectors should use strict read-only inventory by default and avoid destructive cleanup unless the platform owner explicitly controls the policy.

**TPM NV indices (§12.3).** Store index handle, size, attributes, authorization policy where visible, command pattern, caller identity, and timing. TPM access during gameplay is unusual for ordinary games but common for platform security. More generally, a helper that submits a small repeated TBS command sequence only when the protected workload launches should be investigated. Treat TPM data carefully; the artifact can belong to Windows Hello, BitLocker, or enterprise attestation.

**CLFS (§12.4).** CLFS artifacts require file-system plus format-aware triage. Record `.blf` path, container paths, stream names, base/latest LSN, record size histogram, entropy, ACLs, owner, and modification times. A real product log has explainable text/event/transaction shape. A covert CLFS store often has fixed-size binary records, monotonic command epochs, and lifecycle tied to driver load or match start.

**ACPI control methods (§12.5).** Store target ACPI PDO, device stack, caller driver, method name, input/output argument shape, status, and timing. ACPI is noisy in OEM control software, so the high-signal case is role mismatch: an unrelated protected-runtime driver or unknown service evaluating a tiny set of vendor methods at command cadence. Correlate with WMI, power/PnP callbacks, firmware-table queries, and UEFI variables to distinguish real OEM utilities from imitation.

**KTM / TxF / Transacted Registry (§12.6).** Store transaction handle provenance, associated file/registry handles, dirty-vs-committed view indicators, commit/rollback outcome, and callback/minifilter context. A rolled-back transaction is not benign if a registry callback, minifilter, mapped section, or helper process consumed the data before rollback. The finding is transaction-coupled command staging, not the mere existence of KTM.

---

## 13. External and Hardware-Assisted Channels

When the cheat surface lives outside the gaming PC, software anti-cheat is structurally outmatched. The cheat code does not run on the protected host. The host sees only the side effects: PCIe devices it does not control, HID inputs that look like user activity, capture cards on the display path. Defense is policy, server-side behavioral detection, and platform attestation, not on-device software detection.

### 13.1 DMA Cards

External DMA hardware reads or writes system memory without normal in-OS APIs. PCIe DMA cards installed in the gaming PC (typically M.2 NVMe slots) issue Memory Read TLPs against game memory, transferring contents to a second machine over USB or network. There is no in-game module, or only a small overlay/input component on the host.

This is the dominant high-end FPS cheat surface. The dedicated DMA companion post, [About PCIe DMA Cheats: Protocol, IOMMU, Hardware, and Detection](https://kernullist.github.io/kernullist-blog/posts/pcie-dma-cheats/), treats this surface in depth. Summarized here:

**Detection.**

- Enumerate PCIe topology and flag suspicious devices (unusual donor signatures, BAR-size mismatches, mismatched MSI/MSI-X behavior).
- Enforce IOMMU / Kernel DMA Protection policy. Microsoft documentation confirms Kernel DMA Protection uses the system IOMMU to block or isolate DMA-capable peripherals and that supporting systems enable it automatically.
- Monitor Thunderbolt, USB4, CFexpress, M.2, and other DMA-capable device changes.
- Use hardware allowlists for competitive environments.
- Correlate impossible in-game knowledge with the absence of local memory-access indicators.
- Require DMA-remapping-compatible storage and PCIe drivers in hardened modes. Riot Vanguard's January 2026 support guidance explicitly states VALORANT is blocked when storage drivers do not meet its DMAr requirements.

False positives come from capture cards, high-speed storage, docking stations, and legitimate PCIe devices that have unusual signatures. Policy and allowlisting handle the FP population; pure-detection approaches over-trigger.

### 13.2 VMI and VIC

Virtual Machine Introspection moves cheat logic *outside* the guest OS: a hypervisor or second machine reads game state from a vantage point the guest cannot see. The 2025 VIC paper formalized this surface and reported working radar, wall-hack, and trigger-bot prototypes against multiple titles and anti-cheats.

Visual Input Capture (VIC) is a related approach: a capture pipeline observes the game's display output and returns decisions through input emulation. The local system may receive only input events; no memory access happens.

VMI splits observability. The protected guest may see a hypervisor bit, virtualization artifacts, unusual timing, device-model choices, or nothing at all. The real cheat logic lives in the host, a nested hypervisor, or a companion analysis machine. It reads guest physical memory, reconstructs game structures externally, then returns decisions through an input path, overlay path, network side channel, or human-readable second-screen radar.

VIC splits the problem differently. It does not need memory semantics. The external pipeline observes rendered frames, detects targets, estimates state, and returns mouse/keyboard decisions through HID emulation (§13.3) or another input bridge. This makes host memory scanners irrelevant. The defender sees display topology, capture devices, input timing, and gameplay outcomes rather than code injection or handles.

The practical defense is therefore layered:

1. *Host evidence.* Hypervisor/virtualization inventory, boot attestation, PCIe/USB topology, display/capture topology, EDID history, and HID descriptor provenance.
2. *Behavioral evidence.* Reaction time, target acquisition, aim correction shape, pre-aim through occlusion, impossible tracking continuity, and cross-match consistency.
3. *Policy evidence.* Tournament hardware control, streaming/capture disclosure, blocked virtualized environments for high-trust queues, and hardware allowlists where the competitive risk justifies them.

**Detection.** Hardware and capture-pipeline policy, input anomaly detection, PCIe / USB / display device inventory, and competitive-integrity rules for tournament environments. On-device software detection is essentially impossible against a well-engineered VMI cheat that leaves no guest artifact. Durable defenses are server-side behavioral detection, measured-boot or attestation policy where acceptable, and controlled hardware layouts for high-stakes play.

### 13.3 KMBox and Arduino HID Input Separation

Hardware cheats often separate memory acquisition from input delivery. A second PC or DMA controller computes aim movement, then sends the movement to a microcontroller that emulates a USB HID mouse on the game PC. KMBox, RP2040 boards, Arduino-class devices, and similar HID emulators all fit this pattern.

The gaming PC sees a USB HID mouse. Ordinary mouse deltas and clicks reach the game. There may be no cheat process on the game PC at all.

The return path matters more than the compute path. The memory read may happen through DMA (§13.1), VMI (§13.2), or visual capture (§13.4), but the host often receives only HID reports. A microcontroller can spoof common VID/PID pairs, but it is harder to perfectly clone report descriptors, string descriptors, serial behavior, polling jitter, firmware update interfaces, endpoint layout, and timing under load.

Evidence splits into three layers:

1. *Descriptor evidence.* VID/PID, manufacturer/product strings, report descriptor, endpoint count, polling interval, serial number, HID usage pages, and whether descriptors match a known retail device.
2. *Topology evidence.* USB port path, hub chain, hotplug timing, power state, composite-device layout, and whether the device appears only during protected gameplay.
3. *Behavior evidence.* Delta distribution, micro-corrections, acceleration shape, target-relative correction, reaction time, click timing, and whether input begins shortly after visual exposure.

**Detection.** Inventory HID descriptors, vendor IDs, product IDs, report descriptors, polling rates, and serial-number patterns. Look for descriptor mismatch; a "gaming mouse" branding with generic microcontroller report descriptors is a tell. Analyze input dynamics: unnatural jitter, acceleration shape, reaction time, target snapping, target-relative correction, and click timing. Fuse client-side HID telemetry with server-side behavioral detection; the input-pattern evidence alone is rarely sufficient to ban, but combined with hardware identity mismatch it builds an evidence package.

False positives come from accessibility devices, KVMs, macro pads, custom keyboards, high-end gaming mice, and legitimate microcontroller projects. Hardware-identity evidence must be corroborated with input-pattern evidence and gameplay-behavioral evidence.

### 13.4 External Capture Card Screen Separation

The game PC's HDMI or DisplayPort output is split to a capture card on a second machine. The second machine runs computer vision and sends input back through a HID emulator (§13.3). There may be no memory-reading component at all: the cheat is entirely vision-based.

The host evidence is weak because the capture device may be electrically outside the PC's control path. A splitter can present a normal monitor EDID to the GPU while duplicating the signal downstream. A dual-PC streaming setup can look similar. The return path is usually the stronger evidence: HID emulator, network-to-HID bridge, serial microcontroller, or synchronized second-PC input.

The computer-vision loop has measurable behavior even when hardware identity is ambiguous. Vision cheats must wait for a frame, process it, decide, and inject input. That produces latency and correction shapes that differ from both human aim and memory-based aimbots: small frame-quantized corrections, consistent target-box centering, stable color/outline dependence, and reaction windows tied to display refresh rather than game-state update.

**Detection.** Monitor display topology, EDID changes, capture-card-like sinks, duplicated connectors, unusual refresh-mode changes, and suspicious splitters where possible. Server-side aim, reaction-time, frame-quantized correction, and target-acquisition analysis is the primary defense. Correlate with HID emulator indicators: descriptor mismatch, impossible polling stability, serial-number reuse, and input deltas that begin shortly after visual exposure. In tournament or high-trust environments, enforce hardware-layout policy with physical inspection. Streaming setups, capture cards, dual-PC broadcast rigs, accessibility systems, and legitimate recording workflows are common, so on-device detection alone leans heavily on owner attribution and correlation with behavior.

### 13.5 CXL, PCIe IDE, SPDM, and TDISP Boundary Drift

This is a forward-looking hardware channel rather than a commodity cheat surface today, but it belongs in the defender roadmap. PCIe security is moving from "enumerate the device and hope IOMMU policy is enough" toward device authentication, link encryption/integrity, trusted device assignment, and coherent memory fabrics. The relevant acronyms:

- *SPDM* provides device authentication, measurement, confidentiality, and integrity primitives across device ecosystems.
- *PCIe IDE* provides Integrity and Data Encryption for PCIe traffic.
- *TDISP* builds on SPDM and IDE for trusted I/O virtualization and trusted device-interface assignment.
- *CXL* extends PCIe into coherent device and memory-expansion fabrics, bringing cache/memory semantics into the device threat model.

For anti-cheat, the interesting part is not confidential-computing terminology. It is that future external-cheat hardware can move closer to coherent attach, programmable switches, memory pooling, and trusted-device reassignment. A DMA card that merely spoofs an NVMe endpoint is today's problem. Tomorrow's high-end attacker may target the boundary between a remapping-capable device, a PCIe switch, CXL memory, and a platform that trusts IDE/TDISP state more than the anti-cheat can independently verify.

The 2025 PCI-SIG IDE vulnerability disclosure is the warning sign. PCI-SIG disclosed IDE TLP reordering vulnerabilities affecting PCIe Base Specification Revision 5.0 and onward, including cases where packet reordering, delayed posted redirection, or completion timeout redirection can violate the confidentiality or integrity goals of IDE/TDISP under certain conditions. Intel's Delayed Posted Redirection advisory describes a TDISP/IDE gap in which posted requests can be delayed by a malicious programmable PCIe switch until a trusted device interface is rebound to another trusted domain; Intel's mitigation guidance centers on IDE key refresh during reassignment and avoiding programmable PCIe switches in affected trusted deployments.

**Cheat relevance.** A consumer gaming rig will not normally expose full TDISP/CXL trust-domain plumbing to a game. But high-end external-cheat markets follow enterprise hardware downward. The risk pattern to track is:

1. PCIe devices whose identity and DMA behavior look legitimate at enumeration time but whose path includes a programmable switch, retimer, bridge, or CXL component with non-trivial security state.
2. Devices that pass ordinary Kernel DMA Protection checks but have unexpected IDE/SPDM/TDISP capability state, missing measurements, stale firmware, or ambiguous assignment history.
3. CXL memory expanders or coherent devices that change the meaning of "system memory" for on-device scans, crash forensics, and DMA policy.
4. Tournament or lab environments that use docks, capture rigs, high-speed storage, or developer hardware that accidentally expands the trusted device set.

**Detection and policy.** Anti-cheat should not try to reimplement PCIe security standards in a game client. The practical program is:

1. Extend PCIe inventory to capture link path, switch topology, retimers, bridges, DOE/SPDM capability presence, IDE capability state, CXL class/subclass indicators, firmware versions, and driver ownership.
2. Maintain a strict policy for ranked or tournament modes: no unknown programmable switches, no unexplained CXL devices, no development boards, and no hot-added high-risk DMA-capable devices.
3. Prefer platform attestation over local heuristics where possible. If a platform can quote IOMMU, Secure Boot, VBS/HVCI, driver blocklist, and device-security state, use that as the coarse gate before local behavioral scoring.
4. Treat IDE/TDISP as *additional evidence*, not magic. A device advertising a security capability is not automatically benign; the whole path and reassignment history matter.
5. Capture forensic snapshots when policy fails: PCI config space, ACPI/IOMMU tables, driver stack, firmware versions, BDF topology, and Windows device-install history.

False positives will be support-heavy. Developers, streamers, external GPU users, high-speed storage users, capture-card setups, and enterprise laptops with docks can all look strange. This is why the enforcement layer must be mode-specific and explainable: a tournament workstation can enforce a narrow hardware profile; consumer ranked play needs progressive trust scoring and a repair path.

### 13.6 External-Channel Deep-Dive Matrix: Host Evidence, Behavioral Evidence, Policy Evidence

External channels cannot be handled like local malware. The protected host may never execute cheat code. Evidence must be split into host-visible artifacts, server-side behavior, and explicit hardware policy.

**DMA cards (§13.1).** Host-visible evidence includes PCIe topology, BDF path, class/subclass, config-space capabilities, BAR layout, MSI/MSI-X shape, ACS/IOMMU grouping, hotplug history, driver stack, firmware version, and device-install records. Behavioral evidence includes impossible game knowledge without local memory-access traces. Policy evidence includes Kernel DMA Protection, IOMMU state, DMAr-compatible drivers, and mode-specific hardware allowlists. A suspicious DMA device with weak behavioral evidence should trigger degraded trust or additional verification; suspicious device plus impossible knowledge is a strong package.

**VMI/VIC (§13.2).** Host evidence may be absent. Look for virtualization/attestation inconsistencies, capture devices, unusual display paths, and input return channels. Server-side behavior is primary: target acquisition through occlusion, reaction timing below human distribution, radar-like decision quality, and stable performance across visibility changes. Tournament policy should control machine image, hypervisor state, capture path, and peripheral set.

**KMBox/Arduino HID (§13.3).** Host evidence is descriptor and input behavior. Record VID/PID, serial, report descriptor, polling rate, HID usage pages, physical topology, firmware strings, and report timing. Behavioral evidence includes aim curves, micro-corrections, click timing, recoil patterns, and target transitions. Do not ban on generic microcontroller VID alone; many accessibility and hobby devices exist. Ban-quality cases need descriptor mismatch plus behavioral anomaly plus role mismatch.

**External capture (§13.4).** Host evidence is display topology: EDID, duplicate/mirror outputs, capture-card-like sinks, output timing, and changes around gameplay. Behavioral evidence is vision-assisted play: reaction after pixel visibility, repeated target lock under visual-only conditions, and low dependency on memory-derived information. Policy evidence is tournament hardware layout and broadcast/capture exception handling.

**PCIe IDE/SPDM/TDISP/CXL (§13.5).** Host evidence should evolve beyond "device present" into security-state inventory: DOE/SPDM capability, IDE state, CXL class, switch/retimer topology, firmware versions, and reassignment history where exposed. Behavioral evidence may lag because these are infrastructure features, not direct cheat behaviors. Policy evidence is strict: unknown programmable switches, unexplained CXL memory devices, and development boards should not be allowed in high-trust modes until the platform can attest their state.

---

## 14. 2024-2026 Trends and Research Updates

Channels do not stand still. Microsoft hardens surfaces, defenders widen coverage, and attackers move into surfaces the defender has not yet inventoried. The most relevant shifts since v5 shipped are:

### 14.1 Riot Vanguard PCIe and DMAr Enforcement

v5 noted Riot Vanguard adding PCIe and DMA-focused detection in 2024. Current public Riot support material from January 23, 2026 confirms Vanguard uses DMA Remapping to isolate PCIe devices and blocks VALORANT launch when storage drivers are not DMAr-compatible. Operationally:

- DMA defense is moving from passive PCIe inventory to active IOMMU / DMAr policy enforcement.
- Storage and PCIe driver compatibility now matters for anti-cheat launch policy, not just for detection.
- Anti-cheat products need a clear recovery and user-support path because legitimate OEM drivers can fail DMAr requirements, and a hard block without recourse generates support-channel volume that exceeds the cheat-reduction benefit.

### 14.2 Microsoft Kernel DMA Protection and IOMMU Direction

Microsoft documentation confirms Kernel DMA Protection uses the system IOMMU to block or isolate DMA-capable peripherals, and that supporting systems enable it automatically. Microsoft also documents GPU IOMMU DMA remapping as introduced in Windows 11 22H2 (WDDM 3.0), with later WDDM 3.x systems carrying the practical policy target (§9.7). The implication for anti-cheat:

- IOMMU / DMAr should be treated as a competitive-mode policy control, not only as a detection signal.
- Windows 10 compatibility remains weaker for some graphics remapping scenarios; Windows 11 is the durable target.
- Driver DMAr compatibility should be surfaced clearly to users before enforcement, with explicit BIOS/OEM update guidance: the alternative is unfixable support tickets.

### 14.3 HVCI, kCFG, and the Vulnerable Driver Blocklist

Microsoft's current guidance states that Memory Integrity (HVCI) runs kernel-mode code integrity in a VBS-isolated environment, requires executable kernel pages to pass code integrity, and prevents executable pages from being writable. The vulnerable driver blocklist is enabled by default on Windows 11 2022 Update and later and is enforced when HVCI, Smart App Control, or S mode is active.

Anti-cheat impact:

- BYOVD loading remains a moving target: the blocklist lags new vulnerable-driver disclosures, and cheat ecosystems track disclosures faster than the blocklist tracks them.
- HVCI eliminates unsigned and writable-executable kernel payload options but does *not* close `.data` pointer abuse, legitimate callback abuse, or signed-but-malicious driver loading.
- Anti-cheat policy should combine Secure Boot, TPM 2.0, HVCI, and IOMMU rather than relying on any single switch. The right framing is "stack four independent platform controls" rather than "enable one big setting."

### 14.4 KernelCallbackTable Detection Has Matured

MITRE ATT&CK DET0577, last revised May 12, 2026, documents detection for `KernelCallbackTable` hijacking through unexpected PEB modification followed by invocation through Windows message callbacks. The technique is no longer obscure.

Anti-cheat impact:

- `KernelCallbackTable` (§8.5) is no longer a P2 research-only check. Game-process PEB callback-table validation belongs in the P0 or P1 GUI-process integrity layer.
- Detection should correlate PEB modification, table entries outside `user32`, suspicious GUI message dispatch, and post-change code execution: single-source signals over-trigger.

### 14.5 AltSyscall and Windows 11 Syscall Provider Evolution

Public Windows 11 AltSyscall research shows the older `PsAltSystemCallHandlers` model is not the full story on newer Windows 11 builds. Newer builds involve syscall-provider dispatch state and more complex per-process / per-thread routing.

Anti-cheat impact:

- AltSyscall detection must be build-specific. A detector written against the Windows 10 model misses newer Windows 11 routing.
- Validate provider dispatch context and per-thread syscall-provider state, not only one global handler pointer.
- HVCI may prevent writes to some service-descriptor structures, but legitimate syscall-provider mechanisms still need inventory.

### 14.6 Academic 2025 Cheat and Covert-Channel Research

Recent research reshapes the defensive roadmap:

- **VIC** (arXiv:2502.12322) formalizes virtual-machine introspection cheats and reports working radar, wall-hack, and trigger-bot prototypes against multiple games and anti-cheats. The structural lesson is that on-device detection cannot close L6.
- **AntiCheatPT** (arXiv:2508.06348) reports a transformer model for Counter-Strike 2 behavioral cheat detection, with 89.17% accuracy and 93.36% AUC on its test set. This is evidence that server-side behavioral models are reaching production-grade thresholds for some classes of cheat.
- **Page-fault covert-channel research** (arXiv:2509.20398) demonstrates timer-free, hardware-agnostic covert communication with under 4% bit error rate. Page-fault telemetry should be retained as hunting data, not just transient signal.
- **GPU-based host memory integrity validation** (IEEE CoG 2025 preprint) proposes monitoring protected game objects from GPU execution to resist kernel-level tampering: directly relevant to §9 and worth tracking for future anti-DMA and anti-kernel-memory-editing designs.

Together: server-side and behavior-side detection is mandatory for hardware-external and VMI cases, page-fault and exception telemetry should be retained beyond live use, and GPU-assisted integrity is a credible future surface.

### 14.7 UnknownCheats Field-Observation Pass

A June 2026 pass over UnknownCheats forum indexes, search-indexed thread titles/snippets, and related public projects that cite those discussions shows a consistent market pattern in game-cheat development: attackers are no longer arguing only about "IOCTL vs. shared memory." The more relevant question is which legitimate OS path can be turned into a trigger or rendezvous while the payload moves elsewhere. That market signal also maps cleanly to signed-driver malware and rootkit tradecraft.

The additions from this pass are:

1. *"Data ptr called function" as a named attacker workflow.* UC-linked material explicitly popularizes callable `.data` pointer communication, including Win32k and HAL/nt examples. The document now treats this as a generic callable-writable-pointer class rather than a single `HalPrivateDispatchTable` IOC (§7.1, §7.2).
2. *Hookable function pointers for UM-KM on modern Windows.* Forum thread titles and public repos point to attackers searching for low-noise pointers in ntoskrnl, HAL, Win32k, dxgkrnl, and existing drivers. The defensive answer is function-entry validation, chain walking, and trigger-path attribution, not only module-range checks (§6.4, §7.1, §9.6).
3. *Shared buffer with system thread.* The common "shared buffer" pattern is deeper than a named section. It can be a user allocation pinned by an MDL, polled by a system thread, and synchronized by sequence counters or address waits. The document now separates section-backed sharing from MDL-backed private-buffer mailboxes (§8.1, §8.8, §10.11).
4. *Recommended communication method churn.* UC discussions show attackers comparing IOCTLs, sockets, hooked functions, shared buffers, and less-watched callbacks based on what anti-cheats inspect this month. The right detector is therefore surface-complete inventory plus cross-view correlation, not a static list of "bad" IPC APIs (§15).
5. *Vulnerable-driver primitive catalogs.* UC's vulnerable-driver megathread style includes map/unmap physical memory, read/write physical memory, and IOCTL notes. These are not a communication protocol by themselves; they are bootstrap primitives that install the real channel, patch the pointer, or create the MDL mailbox (§8.8, §13.1).
6. *Input-return path migration.* Cheat forums and adjacent 2026 posts emphasize driver-level mouse injection through Mouclass-style callbacks rather than only VHF or user-mode `SendInput`. The document now treats class-service callback hijack as a distinct input/control surface (§4.7).
7. *Syscall trigger hygiene.* A 2025 UC tutorial captures the mainstreaming of direct/indirect syscall wrappers, `win32u.dll` stubs, and call-stack/return-address shaping. This is not a standalone KM-UM channel, but it hardens the UM trigger side of `.data`, Win32k, and syscall-provider hooks (§10.8).
8. *Hypervisor trigger keys.* UC index evidence around Voyager, `vmexit_key`, CPUID/RDTS, and VM-detection threads supports documenting CPUID/VMCALL/MSR-style hypercall mailboxes as L4 trigger surfaces whose local evidence is weak unless paired with attestation or behavior (§11.1).

The defensive program should treat these forum terms as *vocabulary drift*, not as authoritative implementation detail. Titles and snippets are enough to show where attacker attention is moving, but production detection must still validate against Windows build behavior, WDK contracts, symbols, and clean baselines.

### 14.8 Black Hat 2016-2026 Windows Research Pass

A 2016-2026 Black Hat pass adds one useful correction to this document's framing: the best channel ideas rarely arrive as "game cheat IPC." They arrive as Windows internals research on rootkits, IPC, path parsing, virtualization, update trust, or kernel object ownership. The defensive task is to translate those primitives into evidence that works for anti-cheat, EDR, and incident-response workflows.

The concrete additions from this pass are:

1. *ALPC/RPC research turns service plumbing into channel evidence.* REcon 2008, HITB 2014, PacSec 2017, DEF CON 32, and ALPChecker-style work all point to the same defensive model: ALPC/RPC must be reduced to endpoint graph, interface UUID, opnum distribution, message attributes, security/QoS, handle/view transfer, and cross-view consistency (§2.2, §2.12).
2. *WNF is a state system, not a notification footnote.* Black Hat USA 2018 WNF research supports treating WNF as a kernel-backed state, payload, lifetime, and security-descriptor surface (§3.5), with permanent-state and payload-parser evidence rather than only subscription presence.
3. *AFD socket channels can live below normal network telemetry.* Black Hat USA 2020 rootkit material documents per-`FILE_OBJECT` `DeviceObject` redirection for AFD-backed sockets. The document now separates this from global `DriverObject->MajorFunction` patching and requires socket file-object/device-object validation (§6.1, §6.5).
4. *Anonymous pipes matter when the pipe has no name.* The same rootkit material shows kernel-created or brokered user-mode processes using unnamed pipes and redirected standard handles. The named-pipe section now includes inherited-handle and standard-handle evidence, not only `\Device\NamedPipe` namespace inventory (§2.11).
5. *Path identity must be multi-view.* Black Hat Asia 2024 MagicDot research demonstrates that DOS-to-NT path conversion, trailing dots/spaces, short names, and tool-specific path views can create rootkit-like concealment and process identity confusion. The symbolic-link section now requires raw path, NT path, handle-final path, file ID, short-name, and section-file-object comparison (§2.3).
6. *Thread pools can launder the user-mode execution edge.* Black Hat Europe 2023 Pool Party research supports treating WorkerFactory, I/O completion, ALPC, JOB, WAIT, and TIMER work items as thread-pool wake sources that can consume a hidden mailbox without creating an obvious remote thread (§10.12).
7. *Hyper-V channels are not only hypercalls.* Black Hat USA 2018 Hyper-V architecture research points defenders toward VMBus, synthetic devices, MMIO, I/O-port interception, root-partition services, and VM worker mappings as potential L4 communication surfaces (§11.1).
8. *Downgrade attacks change trust floors.* Black Hat USA 2024 Windows Downdate research shows that "fully patched" can be an unreliable assumption when update state, VBS state, kernel components, or recovery tooling can be rolled back or made to appear current. For anti-cheat, this is not a direct KM-UM channel; it is a baseline-trust problem. The detector must record kernel, hypervisor, VBS, AFD, dxgkrnl, win32k, and security-component versions from multiple views and treat impossible version combinations as platform-integrity findings.
9. *Legitimate subsystem ownership is the hard question.* Across these talks, the recurring pattern is object ownership mismatch: a path that opens to a different object, a socket whose file object routes to a different device object, a WNF state whose lifetime/security descriptor does not fit its owner, a thread-pool callback whose owner does not fit the process role, a virtualization channel whose root-side service is outside the guest's visibility, or an update component whose reported version does not match measured state.

This changes the evidence model: store raw and normalized identities, validate object relationships rather than only names, record per-handle routing for high-risk object types, and make build/version provenance part of the detection record. That model is more expensive than IOC matching, but it catches the technique family instead of only last month's string.

### 14.9 Additional Web-Document Gap Pass

A broader June 2026 pass over Microsoft documentation and recent defender writeups identified five missing or under-integrated families that were not adequately represented as standalone communication-channel evidence:

1. *Cloud Files / ProjFS provider callbacks.* Microsoft documents Cloud Files `CfConnectSyncRoot` as a bidirectional provider/filter channel and ProjFS as a callback-driven virtualization provider model. Recent defender research on ProjFS canaries reinforces the detection value of provider callbacks, triggering process identity, reparse tags, and virtualization roots. The document now treats these as provider-backed callback endpoints, not just file-system paths (§4.9).
2. *ACPI control-method evaluation.* Microsoft documents ACPI method-evaluation IOCTLs handled by `Acpi.sys`, including support for KMDF/WDM and UMDF callers. This adds a firmware-adjacent mailbox shape that is distinct from firmware-table provider hijacking: method name, input package, output package, target PDO, and OEM service/proxy ownership (§12.5).
3. *KTM / TxF / Transacted Registry.* Microsoft documents KTM transactions, transacted registry APIs, kernel-mode transacted registry routines, and `CreateFileTransacted` dirty/committed views. This adds a rollback-friendly staging surface where a callback, minifilter, or mapped-section path can consume data before the final committed state disappears (§12.6).
4. *Kernel-resident license/config egress.* Field observation shows modern cheat drivers sometimes fetch license state and user configuration directly from external servers, and malware/rootkits have long used the same pattern for C2, proxy state, and module retrieval. WSK already made loopback a P0 surface; §4.4 now also treats kernel-originated internet egress, REST-like HTTP over WSK, UM-resolver/KM-connector splits, and static HTTP/JSON request-builder artifacts as first-pass telemetry.
5. *Signed-driver rootkit analogues.* Netfilter/Retliften and FiveSys are especially useful analogues because they intersect signed kernel drivers, gaming or online-gamer distribution, remote C2/proxy/config behavior, root-certificate/proxy-state mutation, and local registry/storage side effects. Group-IB's signed-driver research and 2025 ToneShell reporting broaden the same lesson: external egress by a privileged driver should be correlated with post-response local state mutation, not treated as ordinary web traffic.

The provider and persistence additions in this pass are intentionally rated mostly as P2 rather than P0/P1 because they are less field-common than ALPC, sections, registry callbacks, WSK loopback, or dispatch-pointer abuse. The kernel-egress item is the exception: it stays on the §4.4 P0 network-ownership path because a non-network driver contacting remote infrastructure during protected workload runtime is high-value telemetry. The signed-driver cases are not separate techniques; they are evidence models for correlating driver egress with trust-store, proxy, registry, local-disk, and injection side effects.

### 14.10 Presented Case-to-Channel Map

This map keeps the case studies from becoming loose citations. Each row translates a public presentation or field case into the communication primitive and the evidence fields that matter for anti-cheat, EDR, or incident response.

| Case | Communication primitive | Evidence translation | Sections |
|---|---|---|---|
| REcon 2008 LPC/ALPC interfaces | LPC/ALPC endpoint as security boundary | Port owner, accepted client identity, message class, token/security context, server policy | §2.2 |
| HITB 2014 ALPC Fuzzing Toolkit | Raw ALPC and RPC/DCOM over ALPC | Per-process destination ports, connection graph, message cadence, raw custom endpoint behavior | §2.2 |
| PacSec 2017 ALPC-RPC | RPC interface over ALPC | Interface UUID/version, opnum, NDR payload shape, endpoint string, impersonation behavior | §2.2, §2.12 |
| DEF CON 32 ALPC/RPC security-feature abuse | ALPC/RPC security metadata | Auth level, impersonation level, QoS, security callback, direct-event/completion behavior | §2.2, §2.12 |
| ALPChecker / HITB 2023 / arXiv 2024 | ALPC spoofing and blinding | Cross-view mismatch between namespace, handle table, ETW, communication ports, side objects | §2.2 |
| Black Hat USA 2018 WNF | WNF state as communication framework | State name, scope/lifetime, security descriptor, version, publisher/subscriber, payload size | §3.5 |
| Black Hat USA 2020 Windows rootkits | Anonymous pipe broker and AFD file-object route swap | Standard-handle pipe graph, helper lifetime, socket `FILE_OBJECT->DeviceObject`, endpoint tuple | §2.11, §6.1 |
| Black Hat Europe 2023 Pool Party | Thread-pool work items as wake edge | WorkerFactory handle, completion queue/key, TP_ALPC/TP_JOB/TP_WAIT source, post-wake mailbox read | §10.12 |
| Black Hat Asia 2024 MagicDot | Path identity confusion for rendezvous | Raw path, normalized NT path, handle-final path, file ID, section path, symlink target | §2.3 |
| Black Hat USA 2018 Hyper-V architecture | Root-partition / VMBus / synthetic-device channel | VMBus channel, synthetic-device ring, MMIO/port access, VM worker/root-side service identity | §11.1 |
| Netfilter / Retliften | Signed driver remote authority and proxy state | Driver egress, HTTP/root-cert/proxy writes, trust-store mutation, network stack interception | §4.4, §12.1 |
| FiveSys and companion drivers | Proxy/PAC/download/injection control plane | PAC-serving component, proxy domain list, downloader, kernel-assisted user-mode staging | §4.4, §5.4 |
| Mustang Panda / ToneShell signed rootkit reports | Signed kernel loader plus fake-TLS C2 | Driver/minifilter owner, injected process, TCP/443 protocol compliance, pipe/file command side effects | §4.4, §5.4 |
| Group-IB signed-driver ecosystem | Loader/proxy/registry/disk/network task mix | C2 retrieval, registry/local-disk staging, proxy behavior, memory injection, signed-driver provenance | §4.4, §12.1 |

---

## 15. Detection Engineering Program

The chapters above describe the *what* of detection. This chapter is the *how*: the operational structure that turns the catalog into a production detector. The concrete examples still lean anti-cheat because anti-cheat has to make hard decisions on live consumer endpoints, but the same baseline and correlation model applies to EDR and rootkit investigation.

### 15.1 Baseline First, Then Hunt

The single most common reason a kernel detector regresses is "the legitimate population shifted and the detector did not." A production detector must build *clean baselines* for at least:

- Driver objects and dispatch tables.
- Callback arrays and callback registrations.
- `HalPrivateDispatchTable` and other high-risk `.data` pointers.
- Ob object-type procedure pointers (with cookie correction, §7.4).
- Protected process PEB fields, ApiSet schema pointer, and `KernelCallbackTable`.
- Sections, ALPC ports, WNF subscriptions, named objects, and loopback sockets.
- Minifilters, filter communication ports, and device symbolic links.
- Cloud Files sync roots, ProjFS virtualization roots, reparse tags, and provider-backed file-system callback ownership.
- MDL-backed user buffers, long-lived locked private pages, and direct-I/O MDL ownership.
- Thread-pool worker factories, I/O completion queues, timer queues, and callback target ownership for protected-workload-adjacent processes.
- Transaction object activity, transacted registry/file handles, ACPI method-evaluation request ownership, and firmware-adjacent provider paths.
- HID/VHF devices, Mouclass/Kbdclass filter stacks, and class-service callback targets.
- D3DKMT allocations, vendor-utility processes, capture/duplication clients (§9).

Without baselines, every detection becomes noisy. Baselines must be per-build, per-vendor-driver-version, and per-product configuration: a single "all clean" baseline is a constant source of false positives across the support matrix.

### 15.2 Cross-View Validation

Single-source checks are easy to bypass. Robust checks compare multiple independent views of the same fact:

- Process list vs. `PspCidTable` vs. ETW process lifecycle.
- Module list vs. VADs vs. image-load callbacks.
- Handle table vs. object callbacks vs. access-denied patterns.
- Shared memory objects vs. VADs vs. handle ownership.
- Locked user pages / MDLs vs. VADs vs. owning driver role.
- GUI callback pointers vs. `user32!apfnDispatch` clean baseline.
- D3DKMT allocations vs. vendor KMD allocation ledger vs. expected overlay clients.

Each individual view has known evasion techniques; the *combination* rarely does, because the cheat would need to lie consistently across views that have no shared write surface.

### 15.3 Prioritization

The catalog at the start of this document is too big to action all at once. The defensible priority order:

| ID | Technique | Layer | Frequency | Detection Difficulty | Priority |
|----|-----------|-------|-----------|---------------------|----------|
| §3.1 | Firmware provider hijack | L3 | Very high | Medium | P0 |
| §6.1 | IRP MajorFunction patch | L2-L3 | Very high | Medium | P0 |
| §7.2 | HalPrivateDispatchTable | L3 | Very high | Medium | P0 |
| §8.1 | Kernel-created section | L2 | High | Medium | P0 |
| §8.5 | KernelCallbackTable | L3 | High | Medium | P0 |
| §4.4 | WSK loopback / external egress | L2 | Very high | Low-medium | P0 |
| §2.2 | ALPC private / section-view channels | L2 | Very high | Low-medium | P0 |
| §6.1 | AFD file-object `DeviceObject` swap variant | L3 | Medium-high | Medium-high | P0 |
| §13.1 | DMA cards | L5 | High in FPS | Very high | P0 policy |
| §2.11 | Named pipes | L1-L2 | High | Low-medium | P1 |
| §2.11 | Anonymous pipe / standard-handle broker variant | L1-L2 | Medium | Medium | P1 |
| §2.12 | Local RPC / COM endpoints | L1-L2 | Medium | Medium | P1 |
| §4.6 | WFP callouts | L2 | Medium-high in network tools | Medium | P1 |
| §4.7 | Virtual HID / class-input callbacks | L2 / L5 | Medium in input-assisted stacks | Medium | P1 + behavior |
| §10.7 | Process Instrumentation Callback | L3 | Medium | Low | P1 |
| §10.8 | AltSyscall | L3-L4 | Low-medium | Very high | P1 |
| §10.2 | APC queue + alertable wait | L3 | Medium | Medium | P1 |
| §10.5 | VEH exception trigger chain | L3 | Medium | Medium | P1 |
| §10.12 | Thread-pool / WorkerFactory trigger laundering | L2-L3 | Medium | Medium-high | P1 |
| §7.4 | ObTypeIndexTable hijack | L3 | Medium | Medium | P1 |
| §5.2 | CmRegisterCallback | L2 | High | Medium | P1 |
| §5.2 | Undocumented registry value-type command channel | L2 | Medium-high | Medium | P1 |
| §5.2 | Registry callback-context gadget masking | L3 | Medium | Medium-high | P1 |
| §8.8 | MDL-backed user-buffer mailbox | L2-L3 | Medium-high | Medium | P1 |
| §3.5 | WNF | L3 | Medium-high | Very high | P1 |
| §4.1 | FltCreateCommunicationPort | L2 | Medium | Low | P1 |
| §3.3 | NtQuerySystemInformation manipulation | L3 | Medium | Medium | P1 |
| §9.2 | D3DKMT shared resources | L2-L3 | Medium | High | P1 |
| §9.5 | Adapter-local GPU memory | L3 | Low-medium | Very high | P1 |
| §2.3 | MagicDot-style path identity confusion | L1-L3 | Medium | Medium | P1 |
| §4.8 | eBPF for Windows maps / rings | L2 | Low today | Medium | P2 |
| §4.9 | Cloud Files / ProjFS provider callbacks | L1-L2 | Low-medium | Medium | P2 |
| §8.9 | Windows I/O rings | L2-L3 | Low-medium | Medium | P2 |
| §10.11 | WaitOnAddress rendezvous | L2-L3 | Medium | High | P2 |
| §10.3 | Hardware breakpoint trigger | L3 | Low-medium | Medium | P2 |
| §12.2 | UEFI runtime variables | L3 / L5 | Low-medium | Medium | P2 |
| §12.3 | TPM NV indices | L5 | Low today | High | P2 |
| §12.4 | CLFS streams | L2-L3 | Low-medium | Medium | P2 |
| §12.5 | ACPI control-method evaluation | L2-L5 | Low | Medium-high | P2 |
| §12.6 | KTM / TxF / Transacted Registry | L1-L3 | Low-medium | Medium | P2 |
| §7.3 | SeSiCallback | L3 | Medium | Medium | P2 |
| §7.1 | Generic `.data` pointer | L3 | Medium | High | P2 |
| §7.5 | ApiSetSchema | L3 | Low | Medium | P2 |
| §10.1 | Trapped UM thread | L3-L4 | Low | Very high | P2 |
| §8.6 | GdiSharedHandleTable | L3 | Low | High | P3 |
| §2.1 | Mailslot | L1-L2 | Low | Low | P3 |
| §10.10 | NtRegisterThreadTerminatePort | L3 | Very low | Medium | P3 |
| §3.9 | Process Mitigation Policy | L3 | Very low | Medium | P3 |
| §11.1 | EPT MMIO | L4 | Low | Nearly impossible | Policy |
| §11.1 | Hyper-V VMBus / synthetic-device channel variant | L4 | Low | Nearly impossible | Policy |
| §13.2 | VMI / VIC | L6 | Very low | Nearly impossible | Policy |
| §13.3 | KMBox / HID emulator | L5 | Medium in HW-assisted | Medium-high | Policy + behavior |
| §13.4 | External capture card vision | L6 | Rising in vision-assisted | Nearly impossible locally | Server-side policy |
| §13.5 | PCIe IDE / SPDM / TDISP / CXL | L5 | Emerging | Very high | Policy |

The priority axis is *value-to-defender per unit of engineering investment*. A P0 detection has high frequency in the wild, medium detection cost, and a clear evidence package. A P3 detection has low frequency, low evidence quality, or unusually fragile implementation: worth knowing about, not worth shipping in the first production pass.

### 15.4 First Production Pass Checklist

For a first production pass, ship:

1. Driver-dispatch-pointer validation for all loaded drivers, including internal-device-control stack-proxy attribution and high-risk per-handle `FILE_OBJECT->DeviceObject` validation for AFD sockets (§6.1, §6.2, §6.4).
2. Shared section, suspicious VAD, MDL-backed user-buffer, and locked-page inventory for the protected process and helper processes (§8.1, §8.8).
3. IPC endpoint ownership correlation: ALPC connection/communication ports, ALPC section/view and handle-passing side objects, named pipes, anonymous pipe handle graphs, RPC endpoints, COM local servers, named objects, WNF, and Filter Manager ports (§2, §3.5, §4.1).
4. WSK loopback, TCP loopback, and kernel-originated external egress ownership correlation (§4.4).
5. Firmware-provider and suspicious system-information-path monitoring, including `NtSetSystemInformation` / `ZwSetSystemInformation` class-75 provider-registration telemetry (§3.1, §3.3).
6. `KernelCallbackTable` pointer and entry validation (§8.5).
7. `HalPrivateDispatchTable` high-risk slot validation with chain walking (§7.2 + §6.4).
8. Callback inventory for Ob, registry, process / thread, and image-load callbacks, including raw registry value-type telemetry for `RegNtPreSetValueKey` / `RegNtSetValueKey`, function-entry validation, register-indirect gadget classification, and callback-context pointer classification (§5.1, §5.2, §5.3).
9. WFP provider / sublayer / callout inventory, virtual HID stack inventory, and Mouclass/Kbdclass callback-target validation for network-heavy or input-heavy products (§4.6, §4.7).
10. PCIe and DMA policy checks if the protected workload is high-risk, extended to IDE / SPDM / TDISP / CXL capability state where the platform exposes it (§13.1, §13.5, with the companion PCIe document).
11. GPU surface inventory at protected workload launch: loaded GPU KMD, vendor-utility processes, capture/duplication clients (§9).
12. Multi-view path identity capture for high-risk processes, sections, symbolic links, and device paths: raw path, NT path, handle-final path, file ID, short-name expansion, signer, and section-file object (§2.3).
13. Observe-only execution-flow telemetry for APC delivery, VEH chain changes, debug-register state, page-guard exception cadence, and thread-pool worker/callback wakeups before turning any §10 signal into a block-grade verdict.
14. Observe-only provider/persistence telemetry for Cloud Files / ProjFS callbacks, transacted registry/file handles, KTM commit/rollback outcomes, and ACPI method-evaluation requests (§4.9, §12.5, §12.6).

### 15.5 False-Positive Control

Every block-grade detection must carry, at minimum:

- Owning module path.
- Signer and certificate chain.
- Load time.
- Object name or pointer address.
- Process context.
- Call cadence or trigger pattern.
- Known-good vendor classification.
- Windows build and symbol profile.

Do not ban on "unknown" alone. Ban-quality cases require *either* a direct integrity violation (modified code page, modified `.data` pointer with no documented registration path) *or* multiple correlated suspicious signals across independent views (§15.2). The economics are unforgiving: a single false-positive ban consumes more support-team time than a hundred true positives.

A contain-before-verdict pattern works well in anti-cheat: when a detector fires, *degrade* the cheat's effectiveness (clear an MSI provisioning, re-protect a region, force a section unmap) without committing to a ban. In EDR or incident response, the same idea becomes containment before attribution: reduce capability, preserve evidence, and wait for corroboration before destructive cleanup.

---

## 16. Synthesis: Realistic Limits

The practical limit is simple: defenders cannot rely on IOCTL inspection or suspicious device names. Mature kernel-assisted threats move through legitimate OS mechanisms: sections backed by `dxgkrnl`, callbacks registered through documented APIs, fences indistinguishable from frame-pacing primitives, escape paths that look exactly like vendor utilities. The defender's wins come from:

- *Owner attribution*: every artifact must be traceable to a signed, expected module.
- *Pointer integrity*: every callback, dispatch entry, and escape handler must land at a documented function inside an expected module.
- *Object inventory*: every namespace entry, every section, every port, every fence must have a known legitimate origin.
- *Process behavior*: telemetry must reveal command cadence and trigger patterns, not merely API presence.
- *Version-aware baselines*: every check must adapt to the build it runs on, with build-specific offset maps and symbol coverage.

Where the surface lives below the kernel (§11) or outside the host entirely (§13), software detection alone *cannot* close the gap. The required moves are platform attestation (TPM-anchored measured boot, DRTM, VBS state proven via Quote), IOMMU enforcement (Kernel DMA Protection, GPU IOMMU DMA remapping, and PCIe IDE / SPDM / TDISP visibility where platform support exists), workload-specific policy, and behavior-side detection that operates independently of on-device telemetry.

The next-revision watch list:

1. Windows 11 25H2 and 26H1 changes in syscall routing, kCFG, callback hardening, and security-baseline defaults. Microsoft positions 26H1 as a new-device release rather than a broad in-place feature update, so treat it as a build-delta watch item rather than a normal fleet migration target.
2. Expansion of PatchGuard coverage over object-type procedure tables (§7.4).
3. Wider anti-cheat adoption of `KernelCallbackTable` and ApiSet integrity checks (§8.5, §7.5).
4. PCIe and DMA enumeration changes in major anti-cheat products (§13.1, §13.5).
5. GPU surface defense: D3DKMT inventory, vendor escape attribution, and Windows 11 22H2+ GPU IOMMU DMA remapping policy (§9).
6. ARM64 Windows game support and the resulting differences in syscall, callback, and pointer-integrity behavior.
7. WFP, virtual HID, class-input callbacks, eBPF for Windows, and provider-backed file-system adoption in consumer security products and game-side dependencies (§4.6-§4.9).
8. MDL-backed mailbox, Windows I/O ring, CLFS, KTM/TxF transactions, ACPI control-method evaluation, and address-wait synchronization telemetry as quiet queue / persistence surfaces (§8.8, §8.9, §10.11, §12.4-§12.6).
9. PCIe IDE TLP reordering fixes, SPDM measurement exposure, TDISP reassignment semantics, and CXL security-state reporting as these enterprise features move toward client-visible platforms (§13.5).

---

## Corrections Carried Forward (v5 -> v6 -> v7 -> v8)

This document is the v8 revision in the series. Each revision corrected statements from the previous. The corrections that must survive into future revisions are consolidated here.

**v6 (over v5).**

1. Firmware information class numbers must not be hard-coded from a single source: they are 75 (set) and 76 (query), and v5's single fixed value assumption was wrong (now fully resolved in §3.1).
2. `xKdEnumerateDebuggingDevices` is a historical slot name, not necessarily the current function name in the slot (§7.2).
3. WNF is not invisible to modern EDR; arbitrary state names remain weakly covered (§3.5).
4. `ObRegisterCallbacks` supports only `PsProcessType`, `PsThreadType`, and (on Windows 10 1607+) `ExDesktopObjectType` (§5.3).
5. `PspCidTable` entry encoding is handle-table encoding, not `EX_FAST_REF` (§8.4).
6. `KiPageFault` direct hooks are PG-Conflict; VEH-plus-guard-page is the practical version (§10.4).
7. MSR candidates must be separated by PatchGuard risk; `IA32_LSTAR` is PG-Conflict (§11.3).
8. Notify slot counts are 8 on older systems and 64 on later systems: see v7 correction below for the precise boundary.
9. `GdiSharedHandleTable` is less useful after Windows 10 1607 due to cross-process sanitization (§8.6).

**v7 (over v6).**

1. `SystemRegisterFirmwareTableInformationHandler` is treated as `75` (`0x4B`) and `SystemFirmwareTableInformation` as `76` (`0x4C`) in the current Windows 10/11 reverse-engineering view. v6's hedging about `75`, `76`, or `77` conflated set and query paths, but detectors should still build-validate this private system-information route (§3.1).
2. `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, and `PspLoadImageNotifyRoutine` expanded from 8 to 64 slots in *Windows 8* (build 9200), not Windows 10 1507 (build 10240). v6 had this off by one major version. Detection code that uses 10240 as the cutoff undercounts callbacks on Windows 8 and 8.1 (§5.1).
3. On Windows 8 and later, `_HANDLE_TABLE_ENTRY` uses a bitfield-packed encoding with `ObjectPointerBits` occupying the upper 44 bits. The correct decoder is `((LowValue >> 20) << 4) | 0xFFFF000000000000`. The v6 `Object & ~3ULL` applies only to pre-Windows-8 builds (§8.4).
4. `_OBJECT_HEADER->TypeIndex` is obfuscated on Windows 10 and later. Detection code must XOR with `nt!ObHeaderCookie` and the second byte of the object header address before indexing `ObTypeIndexTable`. v6 omitted this entirely and would have produced silent false negatives or bugchecks (§7.4).
5. `PROCESS_MITIGATION_DEP_POLICY` is 8 bytes. `PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY` and `PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY` are 4 bytes each. v6 had these inverted (§3.9).

**v8 (over v7).**

1. v7 preserved the Part 8 → Part 10 numbering gap from v5/v6. v8 fills it with §9 (GPU, DXGK, and D3DKMT Surfaces): the surface the previous revisions identified as a future-work candidate but did not document. v8's section numbering is contiguous.
2. v7 retained the catalog-style template (Channel Mechanics / KM Side / UM Side / Why Cheats Use It / Detection / False Positives) for every technique. v8 replaces the template with topic-specific narrative subsections, bold leading phrases, and inline detection-engineering judgment, matching the style of the companion PCIe DMA document.
3. v8 reframes the §15 priority table to use v8 section IDs and re-rates §8.5 (`KernelCallbackTable`) as P0: v7 still showed it as P0 but treated v6's P2 framing as an acknowledgement note; v8 removes the historical framing and treats the P0 rating as the current position. MITRE ATT&CK DET0577 (revised May 2026) provides the operational justification.

### v8 Additional Notes

These are not strictly corrections but operationally relevant detail that v7 made explicit and v8 carries forward:

- `KernelCallbackTable` entries are slots in `user32!apfnDispatch`. The internal table is `apfnDispatch`; modern Windows 11 builds expose more than 100 entries. Hashing the entire array against a clean baseline is more robust than checking only the canonical `__fn*` slots (§8.5).
- `PAGE_GUARD` is one-shot. When an access faults on a guard page, the OS clears `PAGE_GUARD` before raising `STATUS_GUARD_PAGE_VIOLATION`. A covert channel must explicitly re-arm the page with `VirtualProtect(addr, size, oldProt | PAGE_GUARD, &oldProt)` inside the handler (§10.4, VEH plus PAGE_GUARD variant).
- WNF state-name decoding is private implementation detail. Public reversing documents XOR-style decoding with the historical key `0x41C64E6DA3BC0074` on older Windows 10 builds, but detectors should use a build-validated decoder rather than assuming a stable constant (§3.5).
- `HalPrivateDispatchTable` validation must walk the dispatch chain, not just the immediate slot target: the multi-stage chain pattern (§6.4) lands the first hop inside a legitimate module while ultimately reaching attacker-controlled code.
- The web-research expansion adds named pipes, ALPC state-machine and section-view channel detail, local RPC / COM, WFP callouts, VHF, eBPF for Windows, Cloud Files / ProjFS providers, MDL-backed mailboxes, I/O rings, `WaitOnAddress`, CLFS, ACPI method evaluation, KTM / TxF / Transacted Registry, and PCIe IDE / SPDM / TDISP / CXL boundary drift (§2.2, §2.11, §2.12, §4.6-§4.9, §8.8, §8.9, §10.11, §12.4-§12.6, §13.5).
- The depth expansion adds per-section deep-dive matrices for IPC state machines, system-reflection query protocols, official KM-UM mediation surfaces, callback order/intent, driver dispatch ownership, writable `.data` control pointers, memory payload channels, GPU/D3DKMT ownership, execution-flow triggers, CPU/hypervisor attestation boundaries, persistence artifacts, and external-channel evidence (§2.13, §3.10, §4.10, §5.8, §6.5, §7.6, §8.10, §9.9, §10.13, §11.5, §12.7, §13.6).
- The registry / firmware callback expansion adds two field-observed patterns: firmware-table provider registration through `NtSetSystemInformation` / `ZwSetSystemInformation(SystemRegisterFirmwareTableInformationHandler)` as a request/reply channel (§3.1), including the current-build weakness where the supplied `DriverObject` behaves more like a provider owner key than a strong handler-ownership proof; and registry callback command dispatch through undocumented value types plus callback-context gadget masking such as trusted-image `jmp rcx` dispatch (§5.2).
- The individual-depth expansion further thickens previously short sections: private namespaces, hidden windows, clipboard listener windows, global atoms, job completion ports, minifilter ports, PnP device interfaces, WMI blocks, WSK loopback/external egress, NLS-backed shared pages, Po/PnP callbacks, bugcheck callbacks, bound callbacks, Fast I/O, driver object extensions, SeSi callbacks, APCs, hardware breakpoints, VEH chains, NMI/IPI, AltSyscall, syscall tracing stack replacement, UEFI variables, TPM NV indices, VMI/VIC, and external capture-card vision.
- The Black Hat 2016-2026 expansion adds WNF state-system framing, MagicDot-style path identity confusion, anonymous pipe / standard-handle broker evidence, AFD socket `FILE_OBJECT->DeviceObject` swap detection, thread-pool / WorkerFactory trigger laundering, Hyper-V VMBus / synthetic-device channel framing, and Windows Downdate trust-floor implications (§2.3, §2.11, §3.5, §6.1, §10.12, §11.1, §14.8).
- The additional web-document gap pass adds provider-backed file-system callback channels, ACPI control-method evaluation, KTM / TxF / Transacted Registry rollback staging, kernel-resident WSK egress for license/config fetch, and signed-driver rootkit analogues such as Netfilter/Retliften and FiveSys. Provider/persistence additions are P2 observe-only; WSK egress stays in the §4.4 P0 network-ownership path (§4.4, §4.9, §12.5, §12.6, §14.9).
- The presented-case expansion maps REcon/HITB/PacSec/DEF CON ALPC-RPC work, Black Hat WNF/rootkit/PoolParty/MagicDot/Hyper-V talks, and signed-driver field cases to concrete communication primitives and evidence fields (§2.2, §2.3, §2.11, §2.12, §3.5, §4.4, §6.1, §10.12, §11.1, §14.10).
- The review-mode correction pass fixes over-specific or overstated claims: WNF decoding is build-private rather than a stable per-boot-XOR contract; GPU IOMMU DMA remapping is a WDDM memory-management / trust-posture signal rather than a standalone cheat detector; `WaitOnAddress` wake is same-process only; `PFNFTH` uses the WDK-documented `__cdecl` convention; and firmware-table class numbers should be build-validated even when using the current 75/76 mapping.

---

## References

### Primary Microsoft Documentation

- Microsoft Learn, *Mailslots*: https://learn.microsoft.com/en-us/windows/win32/ipc/mailslots
- Microsoft Learn, *About Mailslots*: https://learn.microsoft.com/en-us/windows/win32/ipc/about-mailslots
- Microsoft Learn, *CreateMailslotW*: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createmailslotw
- Microsoft Learn, *Named Pipes*: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes
- Microsoft Learn, *Object Names*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-names
- Microsoft Learn, *Object Namespaces*: https://learn.microsoft.com/en-us/windows/win32/sync/object-namespaces
- Microsoft Learn, *CreatePrivateNamespace*: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprivatenamespacea
- Microsoft Learn, *ClosePrivateNamespace*: https://learn.microsoft.com/en-us/windows/win32/api/namespaceapi/nf-namespaceapi-closeprivatenamespace
- Microsoft Learn, *Window Properties*: https://learn.microsoft.com/en-us/windows/win32/winmsg/window-properties
- Microsoft Learn, *FindWindowExW*: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowexw
- Microsoft Learn, *RegisterWindowMessageW*: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerwindowmessagew
- Microsoft Learn, *Clipboard Formats*: https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats
- Microsoft Learn, *RegisterClipboardFormat*: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerclipboardformata
- Microsoft Learn, *AddClipboardFormatListener*: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-addclipboardformatlistener
- Microsoft Learn, *About Atom Tables*: https://learn.microsoft.com/en-us/windows/win32/dataxchg/about-atom-tables
- Microsoft Learn, *GlobalAddAtomW*: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-globaladdatomw
- Microsoft Learn, *JOBOBJECT_ASSOCIATE_COMPLETION_PORT*: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_associate_completion_port
- Microsoft Learn, *ALPC class* (ETW): https://learn.microsoft.com/en-us/windows/win32/etw/alpc
- Microsoft Learn, *Event* (Windows Performance Recorder ALPC kernel event names): https://learn.microsoft.com/en-us/windows-hardware/test/wpt/event
- Microsoft Learn, *Stack* (Windows Performance Recorder ALPC stack events): https://learn.microsoft.com/en-us/windows-hardware/test/wpt/stack-wpa
- Microsoft Learn, *!lpc* (WinDbg, LPC emulated in ALPC note): https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-lpc
- Microsoft WDK 10.0.26100.0 `evntrace.h` and `ntstatus.h`, `EVENT_TRACE_FLAG_ALPC`, `SYSTEM_ALPC_KW_GENERAL`, and ALPC status definitions.
- Microsoft Learn, *How RPC Works*: https://learn.microsoft.com/en-us/windows/win32/rpc/how-rpc-works
- Microsoft Learn, *Protocol Sequence Constants*: https://learn.microsoft.com/en-us/windows/win32/rpc/protocol-sequence-constants
- Microsoft Learn, *String Binding*: https://learn.microsoft.com/en-us/windows/win32/rpc/string-binding
- Microsoft Learn, *ncalrpc attribute*: https://learn.microsoft.com/en-us/windows/win32/midl/ncalrpc
- Microsoft Learn, *Specifying Endpoints* (RPC): https://learn.microsoft.com/en-us/windows/win32/rpc/specifying-endpoints
- Microsoft Learn, *RpcEpRegister*: https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcepregister
- Microsoft Learn, *RpcServerRegisterIfEx*: https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-rpcserverregisterifex
- Microsoft Learn, *Client Impersonation* (RPC): https://learn.microsoft.com/en-us/windows/win32/rpc/client-impersonation
- Microsoft Learn, *Quality of Service* (RPC): https://learn.microsoft.com/en-us/windows/win32/rpc/quality-of-service
- Microsoft Learn, *MS-RPCE Authentication Levels*: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/425a7c53-c33a-4868-8e5b-2a850d40dc73
- Microsoft Windows SDK 10.0.26100.0 `shared\rpcdce.h`, `RPC_IF_*` interface registration flags.
- Microsoft Learn, *LocalServer32* (COM local servers): https://learn.microsoft.com/en-us/windows/win32/com/localserver32
- Microsoft Learn, *Kernel DMA Protection*: https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt
- Microsoft Learn, *IOMMU DMA remapping*: https://learn.microsoft.com/en-us/windows-hardware/drivers/display/iommu-dma-remapping
- Microsoft Learn, *Windows 11 release information*: https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
- Microsoft Learn, *About Event Tracing for Drivers*: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/about-event-tracing-for-drivers
- Microsoft Learn, *Microsoft vulnerable driver blocklist*: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Microsoft Learn, *Memory integrity / HVCI enablement*: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement
- Microsoft Learn, *SetProcessMitigationPolicy*: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessmitigationpolicy
- Microsoft Learn, *GetSystemFirmwareTable*: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
- Microsoft Learn, *EnumSystemFirmwareTables*: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-enumsystemfirmwaretables
- Microsoft WDK 10.0.26100.0 `ntddk.h`, `SYSTEM_FIRMWARE_TABLE_INFORMATION` and `SYSTEM_FIRMWARE_TABLE_HANDLER` definitions.
- NtDoc / phnt-derived `SYSTEM_INFORMATION_CLASS`, `SystemRegisterFirmwareTableInformationHandler` and `SystemFirmwareTableInformation`: https://ntdoc.m417z.com/system_information_class
- Microsoft Learn, *FltCreateCommunicationPort*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatecommunicationport
- Microsoft Learn, *FltEnumerateFilters*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltenumeratefilters
- Microsoft Learn, *CfConnectSyncRoot* (Cloud Files API): https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfconnectsyncroot
- Microsoft Learn, *CF_CALLBACK_INFO*: https://learn.microsoft.com/en-us/windows/win32/api/cfapi/ns-cfapi-cf_callback_info
- Microsoft Learn, *Projected File System Virtualization Instance Lifecycle*: https://learn.microsoft.com/en-us/windows/win32/projfs/virtualization-instance-lifecycle
- Microsoft Learn, *PRJ_CALLBACK_DATA*: https://learn.microsoft.com/en-us/windows/win32/api/projectedfslib/ns-projectedfslib-prj_callback_data
- Microsoft Learn, *IoRegisterDeviceInterface*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregisterdeviceinterface
- Microsoft Learn, *IoSetDeviceInterfaceState*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetdeviceinterfacestate
- Microsoft Learn, *IoWMIRegistrationControl*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiregistrationcontrol
- Microsoft Learn, *Winsock Kernel Architecture*: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/winsock-kernel-architecture
- Microsoft Learn, *WSK WskSocket*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_socket
- Microsoft Learn, *PFN_WSK_SOCKET_CONNECT*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wsk/nc-wsk-pfn_wsk_socket_connect
- Microsoft Learn, *Schannel* (user-mode TLS security package context): https://learn.microsoft.com/en-us/windows/win32/com/schannel
- Microsoft Learn, *Windows Filtering Platform*: https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page
- Microsoft Learn, *Introduction to Windows Filtering Platform Callout Drivers*: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-windows-filtering-platform-callout-drivers
- Microsoft Learn, *Registering Callouts with the Filter Engine*: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/registering-callouts-with-the-filter-engine
- Microsoft Learn, *Write a HID source driver by using Virtual HID Framework (VHF)*: https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/virtual-hid-framework--vhf-
- Microsoft Learn, *VhfCreate*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/vhf/nf-vhf-vhfcreate
- Microsoft Learn, *VhfStart*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/vhf/nf-vhf-vhfstart
- Microsoft Learn, *ExSetFirmwareEnvironmentVariable*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exsetfirmwareenvironmentvariable
- Microsoft Learn, *GetFirmwareEnvironmentVariableExW*: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexw
- Microsoft Learn, *SetFirmwareEnvironmentVariableExW*: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexw
- Microsoft Learn, *Tbsip_Submit_Command*: https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsip_submit_command
- Microsoft Learn, *GetProcessMitigationPolicy*: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy
- Microsoft Learn, *Using Kernel Mode Performance Counters*: https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/using-kernel-mode-performance-counters
- Microsoft Learn, *RegSetValueExW*: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw
- Microsoft Learn, *Registry Value Types*: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
- Microsoft Learn, *REG_SET_VALUE_KEY_INFORMATION*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_reg_set_value_key_information
- Microsoft Learn, *ZwSetValueKey*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwsetvaluekey
- Microsoft Learn, *EX_CALLBACK_FUNCTION*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-ex_callback_function
- Microsoft Learn, *Filtering Registry Calls*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/filtering-registry-calls
- Microsoft Learn, *Registering for Notifications* (registry callbacks): https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/registering-for-notifications
- Microsoft Learn, *CmRegisterCallbackEx*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex
- Microsoft Learn, *PsSetCreateProcessNotifyRoutineEx*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- Microsoft Learn, *PsSetCreateThreadNotifyRoutine*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine
- Microsoft Learn, *PsSetLoadImageNotifyRoutine*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine
- Microsoft Learn, *ObRegisterCallbacks*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks
- Microsoft Learn, *PoRegisterPowerSettingCallback*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-poregisterpowersettingcallback
- Microsoft Learn, *KeRegisterBugCheckReasonCallback*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisterbugcheckreasoncallback
- Microsoft Learn, *DRIVER_OBJECT*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object
- Microsoft Learn, *IRP_MJ_INTERNAL_DEVICE_CONTROL*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-internal-device-control
- Microsoft Learn, *_IRP* (`MdlAddress`, direct I/O, and IOCTL buffer description): https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp
- Microsoft Learn, *MmProbeAndLockPages*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages
- Microsoft Learn, *MmMapLockedPagesSpecifyCache*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmaplockedpagesspecifycache
- Microsoft Learn, *IoAllocateDriverObjectExtension*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocatedriverobjectextension
- Microsoft Learn, *PSERVICE_CALLBACK_ROUTINE* (Kbdclass/Mouclass service callback): https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/kbdmou/nc-kbdmou-pservice_callback_routine
- Microsoft Learn, *IOCTL_INTERNAL_I8042_HOOK_MOUSE*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdd8042/ni-ntdd8042-ioctl_internal_i8042_hook_mouse
- Microsoft Learn, *Managing Memory Sections*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-memory-sections
- Microsoft Learn, *ZwMapViewOfSection*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
- Microsoft Learn, *CreateIoRing*: https://learn.microsoft.com/en-us/windows/win32/api/ioringapi/nf-ioringapi-createioring
- Microsoft Learn, *QueueUserAPC*: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
- Microsoft Learn, *AddVectoredExceptionHandler*: https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler
- Microsoft Learn, *WaitOnAddress*: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress
- Microsoft Learn, *WakeByAddressSingle*: https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-wakebyaddresssingle
- Microsoft Learn, *Introduction to the Common Log File System*: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system
- Microsoft Learn, *Creating a Log File* (CLFS): https://learn.microsoft.com/en-us/previous-versions/windows/desktop/clfs/creating-a-log-file
- Microsoft Learn, *Evaluating ACPI Control Methods Synchronously*: https://learn.microsoft.com/en-us/windows-hardware/drivers/acpi/evaluating-acpi-control-methods-synchronously
- Microsoft Learn, *Working With Transactions* (KTM): https://learn.microsoft.com/en-us/windows/win32/ktm/programming-model
- Microsoft Learn, *CreateFileTransactedA*: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiletransacteda
- Microsoft Learn, *RegCreateKeyTransactedA*: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeytransacteda
- Microsoft Learn, *ZwCreateKeyTransacted*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekeytransacted
- Microsoft Learn, *D3DKMTShareObjects*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtshareobjects
- Microsoft Learn, *D3DKMTQueryAdapterInfo*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/ns-d3dkmthk-_d3dkmt_queryadapterinfo
- Microsoft Learn, *D3DKMTOpenResourceFromNtHandle*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtopenresourcefromnthandle
- Microsoft Learn, *D3DKMTCreateSynchronizationObject2*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtcreatesynchronizationobject2
- Microsoft Learn, *D3DKMT_ESCAPE*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/ns-d3dkmthk-_d3dkmt_escape
- Microsoft Learn, *DXGKDDI_ESCAPE*: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmddi/nc-d3dkmddi-dxgkddi_escape

### MITRE ATT&CK

- T1574.013, KernelCallbackTable Hijacking.
- DET0577, KernelCallbackTable detection strategy (last revised May 2026): https://attack.mitre.org/detectionstrategies/DET0577/

### Industry

- Riot Support, *VAN: Incompatible OEM Driver*: https://support-valorant.riotgames.com/hc/en-us/articles/47638826320147-VAN-Incompatible-OEM-Driver
- Microsoft, *eBPF for Windows*: https://microsoft.github.io/ebpf-for-windows/
- Microsoft Security Intelligence, *Trojan:Win64/Retliften* (Netfilter malicious driver): https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin64%2FRetliften
- G DATA, *Microsoft signed a malicious Netfilter rootkit*: https://www.gdatasoftware.com/blog/microsoft-signed-a-malicious-netfilter-rootkit
- Bitdefender Labs, *Digitally-Signed Rootkits are Back: A Look at FiveSys and Companions*: https://www.bitdefender.com/en-us/blog/labs/digitally-signed-rootkitsare-back-a-look-atfivesys-and-companions
- Bitdefender DracoTeam, *Digitally-Signed Rootkits are Back: A Look at FiveSys and Companions* (whitepaper): https://download.bitdefender.com/resources/files/News/CaseStudies/study/405/Bitdefender-DT-Whitepaper-Fivesys-creat5699-en-EN.pdf
- Group-IB, *Exploiting Trust: How Signed Drivers Fuel Modern Kernel Level Attacks on Windows*: https://www.group-ib.com/blog/kernel-driver-threats/
- Microsoft Security Intelligence, *Win32/Rustock threat description*: https://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Win32%2FRustock
- PCI-SIG, *PCIe IDE Standard Vulnerabilities*: https://pcisig.com/PCIeIDEStandardVulnerabilities
- PCI-SIG, *IDE TLP Reordering Enhancements*: https://pcisig.com/PCIExpress/ECN/Base/IDE_TLP_Reordering_Enhancements/Published
- Intel, *Delayed Posted Redirection / CVE-2025-9614 / INTEL-SA-01409*: https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/delayed-posted-redirection.html
- DMTF, *SPDM*: https://www.dmtf.org/standards/spdm
- Compute Express Link Consortium, *CXL Specification*: https://computeexpresslink.org/cxl-specification/
- Compute Express Link Consortium, *Integrity and Data Encryption (IDE) Trends and Verification Challenges in CXL*: https://computeexpresslink.org/blog/integrity-and-data-encryption-ide-trends-and-verification-challenges-in-cxl-compute-express-link-2797/

### Black Hat 2016-2026

- Black Hat USA 2018 / InfoconDB, *The Windows Notification Facility: Peeling the Onion of the Most Undocumented Kernel Attack Surface Yet*: https://infocondb.org/con/black-hat/black-hat-usa-2018/the-windows-notification-facility-peeling-the-onion-of-the-most-undocumented-kernel-attack-surface-yet
- Black Hat USA 2018, *A Dive in to Hyper-V Architecture & Vulnerabilities*: https://i.blackhat.com/us-18/Wed-August-8/us-18-Joly-Bialek-A-Dive-in-to-Hyper-V-Architecture-and-Vulnerabilities.pdf
- Black Hat USA 2020, Bill Demirkapi, *Demystifying Modern Windows Rootkits*: https://i.blackhat.com/USA-20/Wednesday/us-20-Demirkapi-Demystifying-Modern-Windows-Rootkits.pdf
- Black Hat Europe 2023 / SafeBreach Labs, Alon Leviev, *The Pool Party You Will Never Forget: New Process Injection Techniques Using Windows Thread Pools*: https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/
- Black Hat Asia 2024, Or Yair, *MagicDot: A Hacker's Magic Show of Disappearing Dots and Spaces*: https://i.blackhat.com/Asia-24/Presentations/Asia-24-Yair-magicdot-a-hackers-magic-show-of-disappearing-dots-and-spaces.pdf
- SafeBreach Labs, Alon Leviev, *Windows Downdate: Downgrade Attacks Using Windows Updates* (presented at Black Hat USA 2024): https://www.safebreach.com/blog/downgrade-attacks-using-windows-updates/
- The Hacker News, *Mustang Panda Uses Signed Kernel-Mode Rootkit to Load TONESHELL Backdoor* (summarizes Kaspersky 2025 reporting): https://thehackernews.com/2025/12/mustang-panda-uses-signed-kernel-driver.html

### Cheat-Forum Field Reports and Offensive Research

- UnknownCheats, *Anti-Cheat Bypass forum index page 138* (thread-index evidence for recommended communication methods, hookable UM-KM function pointers, shared-buffer/system-thread communication, vulnerable-driver map/unmap primitives, Voyager / vmexit discussion): https://www.unknowncheats.me/forum/anti-cheat-bypass/index138.html
- UnknownCheats, *An Introduction to Syscalls: Bypassing Anti-Cheat Hooks [User-Mode]*: https://www.unknowncheats.me/forum/anti-cheat-bypass/704470-introduction-syscalls-bypassing-anti-cheat-hooks-user-mode.html
- UnknownCheats, *Driver communication using data ptr called function*: https://www.unknowncheats.me/forum/anti-cheat-bypass/425352-driver-communication-using-data-ptr-called-function.html
- UnknownCheats, *Data ptr*: https://www.unknowncheats.me/forum/anti-cheat-bypass/503521-data-ptr.html
- UnknownCheats, *Simple IDA Python script for .data ptr*: https://www.unknowncheats.me/forum/general-programming-and-reversing/582086-simple-ida-python-script-data-ptr.html
- IDontCode / _xeroxz, *NtWin32k* (UC-linked Win32k `.data` pointer swap reference): https://git.back.engineering/IDontCode/NtWin32k
- memN0ps, *Rusty Bootkit: Windows UEFI Bootkit in Rust (RedLotus)* (summarizes UC-linked `.data` pointer communication references and boot-time mapper context): https://memn0ps.github.io/rusty-windows-uefi-bootkit/
- secret.club, *Hooking the graphics kernel subsystem*: https://secret.club/2019/10/18/kernel_gdi_hook.html
- secret.club, *Bypassing kernel function pointer integrity checks*: https://secret.club/2019/11/06/kernel-code-alignment.html
- REcon 2008, Thomas Garnier, *Windows privilege escalation through LPC & ALPC interfaces* (speaker/material listing): https://recon.cx/2008/speakers.html
- HITBSecConf 2014 Malaysia, Ben Nagy, *ALPC Fuzzing Toolkit*: https://archive.conference.hitb.org/hitbsecconf2014kul/sessions/alpc-fuzzing-toolkit/
- Clément Rouault and Thomas Imbert, *A view into ALPC-RPC* (PacSec 2017): https://hakril.net/slides/A_view_into_ALPC_RPC_pacsec_2017.pdf
- Csandker, *Offensive Windows IPC Internals 2: RPC*: https://csandker.io/2021/02/21/Offensive-Windows-IPC-2-RPC.html
- Csandker, *Offensive Windows IPC Internals 3: ALPC*: https://csandker.io/2022/05/24/Offensive-Windows-IPC-3-ALPC.html
- WangJunJie Zhang and YiSheng He, *Defeating magic by magic: Using ALPC security features to compromise RPC services* (DEF CON 32, 2024 listing): https://infocondb.org/con/def-con/def-con-32/defeating-magic-by-magicusing-alpc-security-features-to-compromise-rpc-services
- HITBSecConf 2023 HKT, Kropova and Korkin, *ALPChecker: Detecting Spoofing and Blinding Attacks*: https://conference.hitb.org/hitbsecconf2023hkt/materials/D1%20COMMSEC%20-%20ALPChecker%20%E2%80%93%20Detecting%20Spoofing%20and%20Blinding%20Attacks%20-%20Anastasiia%20Kropova%20%26%20Igor%20Korkin.pdf
- InfoCheats, *Windows 11: UM-KM Communication Framework via Win32k Syscall Hook* (adjacent cheat-forum field report; use as vocabulary signal, not authoritative Windows documentation): https://infocheats.net/threads/windows-11-um-km-communication-framework-via-win32k-syscall-hook-c-c.12546/
- InfoCheats, *Apex Legends Mouse Input Injection via MouClass Callback* (adjacent cheat-forum field report; use as vocabulary signal, not authoritative Windows documentation): https://infocheats.net/threads/apex-legends-mouse-input-injection-via-mouclass-callback.12729/

### Research

- iamelli0t.github.io, *CVE-2021-1732 win32kfull callback OOB*: KernelCallbackTable PoC.
- Unit 42, *Inside Win32k Exploitation* Part 1 and Part 2: `KeUserModeCallback` structure.
- Core Security, *Analysis of CVE-2022-21882*: KernelCallbackTable hooking pattern.
- rce4fun.blogspot.com, *OkayToCloseProcedure callback kernel hook*: ObTypeIndexTable method hooking.
- rayanfam.com, *Reversing Windows Internals Part 1*: ObTypeIndexTable indexing with `ObHeaderCookie` XOR.
- researchgate.net, *Lazarus & BYOVD: evil to the Windows core*: `PsProcessType` callback abuse.
- captmeelo.com, *Adventures with KernelCallbackTable Injection*.
- bsodtutorials.wordpress.com, *Object Headers, Handles and Types*: `TypeIndex` XOR.
- 0xflux, *Alt Syscalls for Windows 11*: https://fluxsec.red/alt-syscalls-for-windows-11
- Kropova and Korkin, *ALPC Is In Danger: ALPChecker Detects Spoofing and Blinding* (arXiv:2401.01376): https://arxiv.org/abs/2401.01376
- Trail of Bits, *Introducing Windows Notification Facility's WNF Code Integrity*: https://blog.trailofbits.com/2023/05/15/introducing-windows-notification-facilitys-wnf-code-integrity/
- Huntress, *The Phantom File System: Inside the Windows ProjFS*: https://www.huntress.com/blog/windows-projected-file-system-mechanics
- TrainSec, *NTFS Transactions in Windows: Kernel Transaction Manager, CreateFileTransacted, and Process Doppelganging*: https://trainsec.net/library/windows-internals/ntfs-transactions-in-windows-kernel-transaction-manager-createfiletransacted-and-process-doppelganging/

### Academic 2025

- arXiv:2502.12322, *VIC: Evasive Video Game Cheating via Virtual Machine Introspection*: https://arxiv.org/abs/2502.12322
- arXiv:2508.06348, *AntiCheatPT*: https://arxiv.org/abs/2508.06348
- arXiv:2509.20398, *Exploiting Page Faults for Covert Communication*: https://arxiv.org/abs/2509.20398
- arXiv:2408.00500, *If It Looks Like a Rootkit and Deceives Like a Rootkit*: https://arxiv.org/abs/2408.00500
- IEEE CoG 2025 preprint, *Detecting Memory Editing Cheats by Validating Host Memory Integrity from GPU*: https://www.soramichi.jp/pdf/CoG2025.pdf

### Companion Document

- [About PCIe DMA Cheats: Protocol, IOMMU, Hardware, and Detection](https://kernullist.github.io/kernullist-blog/posts/pcie-dma-cheats/): protocol-level DMA card detection, IOMMU enforcement architecture, attestation, and forensic capture.
