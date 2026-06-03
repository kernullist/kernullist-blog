---
title: "About Kernel Segment Heap"
date: 2026-05-19 00:00:00 +0900
categories: [Windows Internals, Kernel Security]
tags: [windows, kernel, heap, pool, exploitation, anti-cheat, windbg]
---

> **Target audience**: Windows kernel security researchers, anti-cheat developers, kernel driver developers
>
> **Reference environment**: Windows 10 19H1 (1903) ~ Windows 11 (x64)
>
> **Sources**: BlackHat USA 2016/2021, SSTIC 2020, Microsoft MSRC, BlueFrost Security, Angelboy (scwuaptx)

---

## 1. Background and Introduction Timeline

### 1.1 Timeline

```
Windows NT ~ 1809   : Legacy NT Pool Manager (ExAllocatePoolWithTag)
Windows 10 19H1     : Kernel Segment Heap introduced (March 2019, build 1903)
                      └─ User-mode Segment Heap ported to the kernel
Windows 10 2004     : ExAllocatePool2 / ExAllocatePool3 added
                      └─ ExAllocatePoolWithTag officially deprecated
Windows 10 20H2~    : Dynamic KDP (Kernel Data Protection) stabilized
Windows 11          : VBS/HVCI enabled by default; Secure Pool usage expanded
```

> **Common misconception**: Many sources claim "the Segment Heap was introduced in Windows 10 2004," but the kernel segment heap was actually introduced in **19H1 (1903)**. Windows 10 2004 is the release that added the **new Pool APIs** built on top of the segment heap.

### 1.2 Motivation

Limitations of the legacy NT Pool Manager:

- Every chunk had a **plaintext inline header** in front of it, making metadata corruption trivial.
- Allocation sizes and positions were predictable, making **pool spray** attacks straightforward.
- Allocated memory was **not zero-initialized by default**, frequently leading to uninitialized memory disclosure vulnerabilities.

---

## 2. Legacy NT Pool Structure

### 2.1 `_POOL_HEADER` (before 19H1)

```
┌──────────┬────────────────┬─────────┬───────────────────────────┐
│  Offset  │  Field         │  Size   │  Description              │
├──────────┼────────────────┼─────────┼───────────────────────────┤
│  0x00    │  PoolIndex     │  1 B    │  Pool descriptor index    │
│  0x01    │  PreviousSize  │  1 B    │  Previous chunk size      │
│  0x02    │  PoolType      │  1 B    │  Pool type (Paged, etc.)  │
│  0x03    │  BlockSize     │  1 B    │  Current chunk size (>>4) │
│  0x04    │  PoolTag       │  4 B    │  4-byte ASCII tag         │
│  0x08    │  ProcessBilled │  8 B    │  KPROCESS pointer         │
│          │  (union)       │         │  (valid only with PoolQuota) │
└──────────┴────────────────┴─────────┴───────────────────────────┘
  Total size: 16 bytes (x64)
```

Memory layout:

```
[POOL_HEADER 16B][user data ...][POOL_HEADER 16B][user data ...]
      ↑ plaintext, predictable        ↑ adjacent chunk header → overwritable
```

### 2.2 Security Weaknesses of the Legacy Structure

| Technique | Description |
|-----------|-------------|
| **Pool Walking** | Traverse adjacent chunks linearly by following `BlockSize` in the inline header to locate kernel objects |
| **Pool Overflow** | Corrupt an adjacent chunk's `_POOL_HEADER` to gain an arbitrary write primitive on `free` |
| **PoolIndex Overwrite** | Craft a malicious `PoolIndex` to trigger an OOB dereference into the pool descriptor array |
| **ProcessBilled Overwrite** | With the `PoolQuota` flag set, dereference `ProcessBilled` during the free path → arbitrary address dereference primitive |

> **Windows 8 partial mitigation**: `ExpPoolQuotaCookie` was introduced to XOR-encode the `ProcessBilled` pointer:
> `ProcessBilled = KPROCESS_PTR ^ ExpPoolQuotaCookie ^ CHUNK_ADDR`
>
> However, the fundamental issue of a plaintext `_POOL_HEADER` remained until 19H1.

---

## 3. Segment Heap Architecture Overview

### 3.1 Core Structure: `_SEGMENT_HEAP`

Each pool type (NonPagedNx, Paged, PagedSession, etc.) is managed by its own independent `_SEGMENT_HEAP` instance.

```
_SEGMENT_HEAP (kernel offsets, based on 20H2)
┌──────────┬──────────────────────────────────────────────────────────┐
│  0x000   │  EnvHandle (10 B)   — heap environment handle            │
│  0x010   │  Signature (4 B)    — always 0xDDEEDDEE                  │
│  0x028   │  UserContext (8 B)                                        │
│  0x048   │  AllocatedBase (8 B) — LFH structure allocation base     │
│  0x058   │  SegContexts[2] (0x180 B) — segment context array        │
│  0x100   │  VsContext (0xC0 B)  — VS allocator context              │
│  0x280   │  LfhContext (0x4C0 B) — LFH allocator context            │
│  higher  │  LargeAllocMetadata  — large allocation metadata         │
│  higher  │  LargeReservedPages / LargeCommittedPages                 │
└──────────┴──────────────────────────────────────────────────────────┘
```

### 3.2 `_SEGMENT_HEAP` Instances Per Pool Type

```
nt!PoolVector (HEAP_POOL_NODES)
├── NonPagedPool (NP)       → _SEGMENT_HEAP instance #1
├── NonPagedPoolNx (NPNx)   → _SEGMENT_HEAP instance #2   ← primary target
├── PagedPool (PP)          → _SEGMENT_HEAP instance #3
├── PagedPoolSession        → _SEGMENT_HEAP stored in current thread
└── (other special pools)
```

### 3.3 Allocation Routing Flow

```
ExAllocatePoolWithTag / ExAllocatePool2 / ExAllocatePool3
        │
        ▼
  ExAllocateHeapPool (internal to ntoskrnl)
        │
        ├─ size ≤ 0x200 AND LFH activated  ──▶  kLFH
        │   └─ RtlpHpLfhContextAllocate
        │
        ├─ 0x1e1 ≤ size ≤ 0xfe0            ──▶  VS Allocator
        │   └─ RtlpHpVsContextAllocateInternal
        │
        ├─ page-aligned size (0x20000~0x7f0000) ──▶ Segment Allocator
        │   └─ RtlpHpSegAlloc
        │
        └─ large allocation (> 0x7f0000)   ──▶  Large Allocator
            └─ RtlpHpLargeAlloc
```

---

## 4. The Four Allocation Paths

### 4.1 kLFH (Low Fragmentation Heap)

| Property | Details |
|----------|---------|
| **Size range** | ≤ 0x200 bytes (512 B), when LFH is activated for that size class |
| **Activation condition** | Automatically activated after **18 consecutive allocations** of the same size |
| **Key function** | `RtlpHpLfhContextAllocate` |
| **Chunk header** | `_POOL_HEADER` (16 B, still present) |
| **Metadata location** | `_HEAP_LFH_SUBSEGMENT` structure (isolated, not inline) |
| **Bucket count** | 129 (`Buckets[129]`) |

**LFH bucket structure**:

```
_HEAP_LFH_CONTEXT
└── Buckets[129]
     ├── Bucket #0:  size 1~8 B
     ├── Bucket #1:  size 9~16 B
     ├── ...
     └── Bucket #128: size ~0x1FF0B
         (each bucket has AffinitySlots → _HEAP_LFH_SUBSEGMENT)
```

**kLFH security properties**:

- Block placement within a subsegment is **randomized**, making adjacent chunk prediction difficult.
- The next allocation position is managed through `_HEAP_LFH_SUBSEGMENT.FreeHint`, which is encoded with `LfhKey`.
- Even if an adjacent chunk overflows, it is difficult to directly corrupt the management structure (`_HEAP_LFH_CONTEXT`).

---

### 4.2 VS Allocator (Variable Size)

| Property | Details |
|----------|---------|
| **Size range** | (a) ≤ 0x1e0 && LFH inactive; (b) 0x1e1~0xfe0; (c) 0x1001~0xffff && non-page-aligned |
| **Key function** | `RtlpHpVsContextAllocateInternal` |
| **Chunk header** | `_HEAP_VS_CHUNK_HEADER` (16 B, **HeapKey XOR encoded**) |
| **Free chunk management** | Red-Black Tree (`FreeChunkTree`) |
| **Allocation algorithm** | Best-fit |

**VS chunk header structure**:

```
_HEAP_VS_CHUNK_HEADER (allocated state)
┌──────────────────────────────────────────────────────────────┐
│  Sizes (8 B)  — XOR encoded: HeaderBits ^ self_addr ^ HeapKey │
│    ├─ UnsafeSize      : chunk size / 16                       │
│    ├─ UnsafePrevSize  : previous chunk size / 16              │
│    ├─ MemoryCost      : number of pages occupied              │
│    └─ UnusedBytes     : whether unused bytes exist            │
│  EncodedSegmentPageOffset (1 B)                               │
│    — (self_addr ^ self ^ HeapKey) & 0xFF                      │
│    — page distance to the start of the VS subsegment          │
└──────────────────────────────────────────────────────────────┘
```

Memory layout:

```
[_HEAP_VS_CHUNK_HEADER 16B][_POOL_HEADER 16B][user data ...]
       ↑ HeapKey XOR         ↑ PoolTag etc. still present
```

**VS subsegment structure**:

```
_HEAP_VS_SUBSEGMENT
├── ListEntry      — subsegment linked list
├── CommitBitmap   — page commit state bitmap
├── CommitLock     — lock used during commit
├── Size (2 B)     — subsegment size (>> 4)
└── Signature (15 bit) + FullCommit (1 bit) — integrity check
```

---

### 4.3 Segment Allocator (Backend)

| Property | Details |
|----------|---------|
| **Size range #1** | 0x20000 < size ≤ 0x7f000 (128 KB ~ 508 KB) |
| **Size range #2** | 0x7f000 < size ≤ 0x7f0000 (508 KB ~ ~7 GB) |
| **Core structure** | `_HEAP_PAGE_SEGMENT` + 256 page descriptors |
| **Segment mask** | `0xFFFFFFFFFFF00000` |

> Unlike the user-mode segment heap which uses a single Segment Allocation Context, **the kernel segment heap uses two independent SegContexts depending on the size range**.

Page segment signature encoding:

```
_HEAP_SEG_CONTEXT signature verification:
(page_segment) ^ (page_segment->Signature) ^ 0xA2E64EADA2E64EAD ^ RtlpHpHeapGlobals.HeapKey
```

---

### 4.4 Large Allocator

| Property | Details |
|----------|---------|
| **Size range** | > 0x7f0000 (typically page-aligned large allocations) |
| **Key function** | `RtlpHpLargeAlloc` |
| **Metadata** | `_SEGMENT_HEAP.LargeAllocMetadata` |
| **Tracking structure** | `BigPagePoolTable` (PoolTrackTable) |

---

## 5. Header Structure Changes

### 5.1 Header Combination Per Allocation Path

```
┌───────────────┬────────────────────────────────────────────────────────────┐
│  Path         │  Memory layout (chunk start → user data)                   │
├───────────────┼────────────────────────────────────────────────────────────┤
│  kLFH         │  [_POOL_HEADER 16B] [data]                                 │
│  VS           │  [_HEAP_VS_CHUNK_HEADER 16B] [_POOL_HEADER 16B] [data]     │
│  Segment      │  [_HEAP_PAGE_SEGMENT header] ... [page descriptors]        │
│  Large        │  Metadata recorded in BigPagePoolTable; no inline header   │
│  CacheAligned │  [_POOL_HEADER #1] ... [_POOL_HEADER #2 (CacheAligned)] [data] │
└───────────────┴────────────────────────────────────────────────────────────┘
```

### 5.2 Residual Role of `_POOL_HEADER` Under Segment Heap

`_POOL_HEADER` was not fully removed after the segment heap was introduced. It continues to be used for the following purposes:

| Field | Status under Segment Heap |
|-------|--------------------------|
| `PoolTag` | Still recorded (for debugging/tracing) |
| `PoolType` | Recorded, but not used for allocator selection in the free path |
| `BlockSize` | Unused in the VS path; still present in kLFH |
| `PreviousSize` | **Unused, set to 0** |
| `PoolIndex` | **Unused, set to 0** |
| `ProcessBilled` | Valid only with the PoolQuota flag (encoded with `ExpPoolQuotaCookie`) |

---

## 6. Pointer Encoding Mechanisms

### 6.1 Global Key Structure: `_RTLP_HP_HEAP_GLOBALS`

```c
// Generated randomly at boot time; global in ntoskrnl
_RTLP_HP_HEAP_GLOBALS  (nt!RtlpHpHeapGlobals)
{
    UINT64 HeapKey;   // Used for VS Allocator and Segment Allocator header encoding
    UINT64 LfhKey;    // Used for LFH callback pointer encoding
}
```

### 6.2 Encoding Formulas Per Component

**VS chunk header — Sizes field**:

```
encoded value = vs_chunk_header->Sizes.HeaderBits
              = (real Sizes value) ^ (address of vs_chunk_header) ^ RtlpHpHeapGlobals.HeapKey
```

**VS chunk — EncodedSegmentPageOffset**:

```
encoded value = vs_chunk_header->EncodedSegmentPageOffset
              = ((real page distance) ^ vs_chunk_header ^ RtlpHpHeapGlobals.HeapKey) & 0xFF
```

**Segment context signature**:

```
check value = page_segment ^ page_segment->Signature ^ 0xA2E64EADA2E64EAD ^ HeapKey
```

**LFH callback function pointer**:

```
encoded pointer = real function address ^ HeapKey ^ address of LfhContext
```

**ProcessBilled (POOL_HEADER, Windows 8+)**:

```
encoded value = KPROCESS_PTR ^ ExpPoolQuotaCookie ^ CHUNK_ADDR
```

### 6.3 Implications for Attackers

To forge an encoded header with a simple overwrite, an attacker must:

1. First leak the address and contents of `RtlpHpHeapGlobals` (i.e., `HeapKey` and `LfhKey`).
2. Know the chunk's own virtual address (self-referential XOR).
3. Failing encoding validation immediately triggers **BugCheck 0x139** (`KERNEL_SECURITY_CHECK_FAILURE`) or **BugCheck 0x13A** (`KERNEL_MODE_HEAP_CORRUPTION`).

---

## 7. Dynamic Lookaside and Delay Free

### 7.1 Dynamic Lookaside

The kernel segment heap operates a dynamic lookaside list based on `_RTL_DYNAMIC_LOOKASIDE` / `_RTL_LOOKASIDE` structures as its primary allocation cache.

```
_HEAP_VS_CONTEXT
└── Lookaside buckets (_RTL_DYNAMIC_LOOKASIDE)
     ├── Per-size singly-linked lists
     ├── Depth (2 B)     — current list depth
     └── NextEntry (8 B) — pointer to the next cached chunk
```

**Rebalancing behavior**:

- Every 3 scans by the Balance Set Manager, each lookaside bucket is rebalanced.
- If new allocation count < 25, Depth decreases by 10.
- If miss ratio ≥ 0.5%, Depth increases; if < 0.5%, Depth decreases by 1.
- Depth range: **minimum 4 ~ MaximumDepth** (determined dynamically).

### 7.2 Delay Free

```
VS Allocator free path:
        │
        ├─ size < 1 KB AND Config.Flags bit 4 == 1
        │       │
        │       ▼
        │  Stored temporarily in DelayFreeContext list
        │       │
        │       └─ Batch freed (real free) after 32 entries accumulate
        │
        └─ Otherwise: inserted immediately into FreeChunkTree
```

**Security implication**: Delay free has the side effect of disrupting the attack timing of immediately reusing a freed chunk right after triggering a UAF (Use-After-Free) vulnerability.

---

## 8. New Pool APIs: `ExAllocatePool2` / `ExAllocatePool3`

### 8.1 API Evolution

```
ExAllocatePool                (legacy, no tag)
ExAllocatePoolWithTag         (pre-19H1 standard, deprecated in 2004)
ExAllocatePoolWithTagPriority (priority support)
ExAllocatePoolWithQuotaTag    (quota tracking)
        │
        ▼  Windows 10 2004 and later
ExAllocatePool2               (general case, zero-initialized by default)
ExAllocatePool3               (extended parameters, priority + Secure Pool)
```

### 8.2 `ExAllocatePool2`

```c
PVOID ExAllocatePool2(
    POOL_FLAGS Flags,       // Uses POOL_FLAGS instead of POOL_TYPE
    SIZE_T     NumberOfBytes,
    ULONG      Tag
);
```

Key changes:

- **Zero-initialized by default**: no need to call `RtlZeroMemory` separately.
- **Returns NULL on failure by default** (`POOL_FLAG_RAISE_ON_FAILURE` converts to an exception).
- `POOL_FLAG_USE_QUOTA` integrates the legacy `PoolQuota` functionality.

```c
// Migration example
// Before: ExAllocatePoolWithTag(NonPagedPoolNx, size, 'Exm0') + RtlZeroMemory(...)
// After:  ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, size, 'Exm0')
```

### 8.3 `ExAllocatePool3`

```c
PVOID ExAllocatePool3(
    POOL_FLAGS              Flags,
    SIZE_T                  NumberOfBytes,
    ULONG                   Tag,
    PCPOOL_EXTENDED_PARAMETER ExtendedParameters,
    ULONG                   Count
);
```

**`POOL_EXTENDED_PARAMETER_TYPE` values**:

| Value | Description |
|-------|-------------|
| `PoolExtendedParameterPriority` | Specify allocation priority (e.g., `HighPoolPriority`) |
| `PoolExtendedParameterSecurePool` | Allocate in KDP Secure Pool (VTL0 write-protected memory) |

```c
// Priority example
POOL_EXTENDED_PARAMETER params = {0};
params.Type     = PoolExtendedParameterPriority;
params.Priority = HighPoolPriority;
PVOID alloc = ExAllocatePool3(POOL_FLAG_NON_PAGED, size, 'Tag1', &params, 1);

// Secure Pool example (KDP)
POOL_EXTENDED_PARAMS_SECURE_POOL sp = {0};
sp.Cookie           = 0xDEADBEEF;
sp.SecurePoolFlags  = SECURE_POOL_FLAGS_FREEABLE | SECURE_POOL_FLAGS_MODIFIABLE;
sp.SecurePoolHandle = g_SecurePoolHandle;
sp.Buffer           = &initialData;
params.Type             = PoolExtendedParameterSecurePool;
params.SecurePoolParams = &sp;
PVOID secureAlloc = ExAllocatePool3(POOL_FLAG_NON_PAGED, size, 'Sec1', &params, 1);
```

### 8.4 Down-level Compatibility Wrapper

For drivers that must support OS versions prior to 2004:

```c
// At the top of the driver header
#define POOL_ZERO_DOWN_LEVEL_SUPPORT

// In DriverEntry
ExInitializeDriverRuntime(DriversRuntimeInitSupportFlags);

// ExAllocatePool2 can then be used
// (internally falls back to alloc + memset on older OS versions)
```

---

## 9. Kernel Data Protection (KDP) and Secure Pool

### 9.1 Overview

KDP is a platform security technology that leverages the Segment Heap's Secure Pool feature, allowing drivers to allocate **read-only kernel memory that cannot be modified from VTL0**.

### 9.2 Virtual Address Space Layout

```
NT kernel virtual address space (512 GB Secure Pool region)
┌─────────────────────────────────────────────────────────────┐
│         Full kernel VA space (256 PML4 entries)              │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Dedicated 512 GB Secure Pool region (1 PML4 entry)  │   │
│  │  Base address: randomized at boot                    │   │
│  │  Managed by: Secure Kernel (VTL1)                    │   │
│  │  VTL0 writes: blocked via NAR (Node Address Range)   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 9.3 Secure Pool Initialization Flow

```
NT Memory Manager boot Phase 1
        │
        ├─ Randomly calculate 512 GB Secure Pool virtual address
        │
        ├─ Issue INITIALIZE_SECURE_POOL Secure Call → Secure Kernel
        │
        └─ Secure Kernel:
              ├─ Create NAR on the 512 GB region (prevent VTL0 writes)
              └─ Initialize NTE (Node Table Entry) for that region
```

### 9.4 Anti-Cheat Usage Example

```c
// 1. Create Secure Pool context (in DriverEntry)
ExCreatePool(POOL_FLAG_NON_PAGED, tag, &securePoolHandle);

// 2. Allocate detection rule table in Secure Pool (with writable init data)
POOL_EXTENDED_PARAMS_SECURE_POOL sp = {
    .Cookie           = MY_COOKIE,
    .SecurePoolHandle = securePoolHandle,
    .Buffer           = &detectionRuleTable,  // initial data
    .SecurePoolFlags  = SECURE_POOL_FLAGS_FREEABLE
    // MODIFIABLE flag omitted → write-protected after init
};
g_DetectionRules = ExAllocatePool3(POOL_FLAG_NON_PAGED, sizeof(detectionRuleTable),
                                   'DRul', &extParams, 1);

// 3. g_DetectionRules is now immutable — no VTL0 code can modify it (hypervisor-enforced)
```

---

## 10. Security Research Perspective: Evolution of Attack Techniques

### 10.1 Increased Difficulty of Pool Overflow Attacks

| Technique | NT Pool (pre-19H1) | Segment Heap (19H1+) |
|-----------|:-----------------:|:-------------------:|
| Adjacent header overwrite | ✅ Easy | ❌ Blocked by encoding |
| Pool Walking | ✅ Possible | ❌ Impossible due to metadata isolation |
| ProcessBilled overwrite | ⚠️ Requires Win8+ cookie | ⚠️ Requires cookie + HeapKey |
| kLFH pool spray | ⚠️ Predictable | ⚠️ Possible but requires precise control |
| VS FreeChunkTree corruption | N/A | ⚠️ Requires HeapKey bypass |
| Large chunk BigPool tracking | PoC exists | PoC exists (PoolTrackTable) |

### 10.2 Modern kLFH Exploit Pattern

Core requirements for exploiting kLFH pool overflows in the segment heap era:

```
1. Find a target object of the same size as the vulnerable object.
   └─ Must land in the same kLFH bucket — size match is mandatory.

2. The target object must contain exploitable members (pointer, function table).

3. The target object allocation must be triggerable repeatedly from user mode.

4. The vulnerable and target objects must reside in the same pool type.
   └─ NonPagedPoolNx and PagedPool use separate _SEGMENT_HEAP instances.
```

### 10.3 Mandatory Recovery After VS Chunk Overflow

Fields that must be restored after manipulating a VS chunk to avoid a BugCheck:

```c
// Ghost chunk recovery after overflow (HEVD-style)
// Restore the encoded fields of _HEAP_VS_CHUNK_HEADER
ghost_chunk->Sizes.HeaderBits =
    (real_sizes_value) ^ (ULONG_PTR)ghost_chunk ^ RtlpHpHeapGlobals_HeapKey;

ghost_chunk->EncodedSegmentPageOffset =
    ((real_page_offset) ^ (ULONG_PTR)ghost_chunk ^ RtlpHpHeapGlobals_HeapKey) & 0xFF;

// Failure to restore → BugCheck 0x13A (KERNEL_MODE_HEAP_CORRUPTION)
```

### 10.4 Required Pre-Exploit Leak Values

Values that must be obtained before a modern kernel heap exploit:

| Symbol | Purpose | How to Obtain |
|--------|---------|---------------|
| `nt!RtlpHpHeapGlobals` | HeapKey, LfhKey | Binary pattern parsing of `ExFreePoolWithTag` |
| `nt!ExpPoolQuotaCookie` | Decode ProcessBilled | Pattern parsing of `ExAllocatePoolWithQuotaTag` |
| `nt!PsInitialSystemProcess` | EPROCESS chain traversal | ntoskrnl import analysis |
| Chunk's own virtual address | Self-referential XOR | Requires an info-leak primitive |

---

## 11. Anti-Cheat Developer Perspective

### 11.1 The End of Pool Walking and Modern Alternatives

**Legacy method** (pre-19H1):

```c
// Follow BlockSize in inline header to traverse linearly → no longer works
PPOOL_HEADER header = (PPOOL_HEADER)startAddr;
while (header->BlockSize != 0) {
    if (header->PoolTag == TARGET_TAG) { /* ... */ }
    header += header->BlockSize;  // ❌ Invalid under the segment heap
}
```

**Modern alternatives**:

```
BigPool detection (Large Alloc path):
    Reference nt!PoolBigPageTable (or nt!PoolTrackTable)
    └─ Traverse BigPagePoolTable entries

Small allocation detection:
    _SEGMENT_HEAP → VsContext → SubsegmentList traversal
    _SEGMENT_HEAP → LfhContext → Buckets[] → AffinitySlots → Subsegments traversal

Searching by PoolTag:
    WinDbg: !poolfind <Tag> / !poolused
    Kernel code: access path is limited without private symbols
               → Indirect tracking via public APIs such as PsGetCurrentProcess
```

### 11.2 Driver Development Migration Checklist

```
□ ExAllocatePoolWithTag         → Replace with ExAllocatePool2
□ ExAllocatePool (without tag)  → Remove or replace with ExAllocatePool2
□ ExAllocatePoolWithTagPriority → ExAllocatePool3 + PoolExtendedParameterPriority
□ ExAllocatePoolWithQuotaTag    → ExAllocatePool2 + POOL_FLAG_USE_QUOTA
□ RtlZeroMemory after each alloc → Remove (ExAllocatePool2 zero-initializes automatically)
□ Review POOL_FLAG_RAISE_ON_FAILURE (NULL check vs. exception handling)
□ Critical data needing read-only protection → Consider ExAllocatePool3 + Secure Pool
```

### 11.3 BugCheck Code Reference

| BugCheck Code | Name | Segment Heap Trigger |
|:---:|---|---|
| `0x139` | `KERNEL_SECURITY_CHECK_FAILURE` | VS/LFH header integrity check failure |
| `0x13A` | `KERNEL_MODE_HEAP_CORRUPTION` | Heap metadata corruption detected |
| `0xC5` | `DRIVER_CORRUPTED_EXPOOL` | Pool accessed at incorrect IRQL |
| `0x19` | `BAD_POOL_HEADER` | `_POOL_HEADER` validation failure (LFH path) |

---

## 12. WinDbg Analysis Commands

```windbg
// View kernel segment heap global structure
dt nt!_RTLP_HP_HEAP_GLOBALS nt!RtlpHpHeapGlobals

// Check _SEGMENT_HEAP for NonPagedPoolNx
// (PoolVector has no public symbols; requires ntoskrnl offset analysis)

// Dump pool info at a specific address
!pool <address>

// Search for all allocations with a specific PoolTag
!poolfind <Tag> [pool_type]
// e.g.: !poolfind Proc 3

// Statistics by PoolTag
!poolused [flags]
// e.g.: !poolused 2    (sorted by NonPagedPool usage)

// Parse _SEGMENT_HEAP structures directly
dt nt!_SEGMENT_HEAP <address>
dt nt!_HEAP_VS_CHUNK_HEADER <address>
dt nt!_HEAP_LFH_CONTEXT <address>

// Decode a VS chunk header (HeapKey required)
// HeaderBits_raw = poi(<chunk_addr>)
// real Sizes = HeaderBits_raw ^ <chunk_addr> ^ HeapKey

// Traverse BigPool table
dt nt!_POOL_TRACKER_BIG_PAGES nt!PoolBigPageTable
```

---

## 13. Version History Summary

| Windows Version | Key Changes |
|-----------------|-------------|
| Windows 7 | Legacy NT Pool Manager; Lookaside List, ListHeads |
| Windows 8 | `ExpPoolQuotaCookie` introduced (ProcessBilled encoding) |
| Windows 10 RS5 (1809) | Preparation stage for Segment Heap; some internal changes |
| **Windows 10 19H1 (1903)** | **Kernel Segment Heap officially introduced** (kLFH, VS, Segment, Large) |
| Windows 10 2004 | `ExAllocatePool2`, `ExAllocatePool3` added; `ExAllocatePoolWithTag` deprecated |
| Windows 10 20H2 | Dynamic KDP stabilized; Secure Pool usage expanded |
| Windows 11 | VBS/HVCI enabled by default; `ExAllocatePoolWithTag` deprecation warnings strengthened |

---

## 14. References

| Resource | Author / Publisher | Link |
|----------|--------------------|------|
| Windows 10 Segment Heap Internals | Mark Vincent Yason (IBM X-Force), BlackHat USA 2016 | [PDF](https://blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf) |
| Windows Heap-Backed Pool: The Good, The Bad, and The Encoded | Yarden Shafir, BlackHat USA 2021 | [Slides](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Windows-Heap-Backed-Pool-The-Good-The-Bad-And-The-Encoded.pdf) |
| Scoop the Windows 10 Pool | Corentin Bayet, Paul Fariello (SSTIC 2020) | [PDF](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/pool_overflow_exploitation_since_windows_10_19h1/SSTIC2020-Article-pool_overflow_exploitation_since_windows_10_19h1-bayet_fariello.pdf) |
| Windows Kernel Heap: Segment Heap in Windows Kernel Part 1 | Angelboy (scwuaptx) | [Speaker Deck](https://speakerdeck.com/scwuaptx/windows-kernel-heap-segment-heap-in-windows-kernel-part-1) |
| Windows Segment Heap: Attacking the VS Allocator | BlueFrost Security | [Blog](https://labs.bluefrostsecurity.de/blog.html/2022/08/16/windows-segment-heap-attacking-the-vs-allocator/) |
| Solving Uninitialized Kernel Pool Memory on Windows | Microsoft MSRC | [Blog](https://msrc-blog.microsoft.com/2020/07/02/solving-uninitialized-kernel-pool-memory-on-windows/) |
| Introducing Kernel Data Protection | Microsoft Security | [Blog](https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/) |
| Secure Pool Internals: Dynamic KDP Behind The Hood | Windows Internals (Alex Ionescu et al.) | [Blog](https://windows-internals.com/secure-pool/) |
| Updating Deprecated ExAllocatePool Calls | Microsoft Docs | [Learn](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/updating-deprecated-exallocatepool-calls) |
| Swimming In The Kernel Pool (Part 1 & 2) | Connor McGarr | [Blog](https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/) |
| Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion PoC | Synacktiv | [GitHub](https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion) |
| Exploiting CNG.sys IOCTL Pool Overflow | PixiePoint Security | [Blog](https://www.pixiepointsecurity.com/blog/nday-cve-2020-17087/) |
