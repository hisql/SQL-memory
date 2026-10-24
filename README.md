# SQL-memory

x64 external memory access for windows, done on direct syscalls. no `OpenProcess` / `ReadProcessMemory` calls in the import table, no debug-everything flags, the whole io path goes through ntdll syscall stubs that get resolved at runtime.

kept as a standalone base layer of the Regal project (same code lives over there under `src/ext/mem`), split out here so the memory layer can be tested and extended on its own.

## layout

```
SQL-memory/
├── SQL-memory.sln
├── SQL-memory.vcxproj          vs2022 project, x64, masm wired in
└── src/
    ├── main.cpp                small demo, attaches notepad and dumps module info
    ├── util.h                  console helpers (keep window open on exit)
    ├── memory/
    │   ├── memory.h            Memory class + Cached<T> + misc helpers
    │   ├── memory.cpp          attach, io, pe parsing, module walking
    │   ├── region.h            Region - full snapshot of a remote range in local memory
    │   └── simd.h              sse2/avx2 pattern scanning over a snapshot
    ├── syscalls/
    │   ├── syscalls.h
    │   ├── syscalls.cpp        ssn resolution from clean ntdll exports
    │   └── syscall.asm         the actual syscall stubs (masm)
    └── offsets.h               roblox offsets, carried for when this feeds the sdk
```

## how it works

### syscall ids

every ntdll export is a tiny stub. on a clean build it looks like

```
mov r10, rcx        4C 8B D1
mov eax, <ssn>      B8 xx xx xx xx
syscall             0F 05
```

at init the resolver doesn't call anything, it reads the export bytes itself:

1. `GetProcAddress` gives the stub base
2. the page is validated with `VirtualQuery` before a single byte gets read (committed, not `PAGE_NOACCESS`, and at least 40 bytes readable)
3. if edr planted an `E9` jmp, the displacement is followed and the new page validated too
4. if it's an `FF 25 [rip+disp32]` indirect jump, the pointer slot is validated first, then the jump target is, then that page gets validated
5. the `mov eax, imm32` right after `4C 8B D1` is the syscall number, just memcpy'd out

clean stubs are scanned in place, hooked ones get walked first - either way the id lands in a `DWORD` held by the asm module.

### the syscall path

[syscall.asm](src/syscalls/syscall.asm) holds hand written stubs for the six used ntdll functions:

```
Luck_NtReadVirtualMemory
Luck_NtWriteVirtualMemory
Luck_NtOpenProcess
Luck_NtClose
Luck_NtProtectVirtualMemory
Luck_NtCreateThreadEx
```

each one is literally `mov r10, rcx; mov eax, <id>; syscall` - the numbers get patched in at runtime by the resolver, and `PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION` is all this layer ever asks for. nothing usermode-visible is called on the io path.

### the Memory class

```cpp
Memory proc;

if (!proc.Attach("RobloxPlayerBeta.exe"))
    return 1;

uintptr_t base = proc.GetBase();
uint64_t  size = proc.ModuleSize(base);

// typed read / write, falls back on failure instead of faulting
float health = proc.Read<float>(addr);
proc.Write<bool>(flagsAddr, true);

// pointer chain
uint64_t local = proc.Chain<uint64_t>(base, { datamodelOff, playerOff, localOff });

// bulk move
std::vector<uint8_t> buf(size);
proc.ReadChunked(base, buf.data(), buf.size());   // 64k chunks, zero fills bad regions
```

notes on behavior:

- reads accept `STATUS_PARTIAL_COPY` and return how much was actually read - one call never dies because it crossed into an unmapped page
- read/write templates are `__forceinline`, so the hot path is one syscall, zero overhead
- module size parses `SizeOfImage` straight out of the PE headers in memory, and falls back to walking committed `MEM_IMAGE` regions if the headers are weirdly mapped

### Region (snapshot reads)

for pattern scanning, hitting the target once and working locally beats a spread of remote reads:

```cpp
Regal::Region text(&proc, textBase, textSize);

// struct read out of the snapshot, bounds checked
Primitive prim{};
text.Get(offset, prim);

// value or fallback
int id = text.GetOr<int>(off, 0);

// full pattern scan, sse2 accelerated (avx2 when compiled with /arch:AVX2)
uint64_t hit = text.FindPattern(
    (const uint8_t*)"\x48\x8B\x05\x00\x00\x00\x00",
    "xxx????", 7).value_or(0);
```

`Find` runs `memchr` on the anchor byte, `FindPatternSimd` runs the first fixed pattern byte through `pcmpeqb`/`movemask` lane-at-a-time, and anything shorter than 16 bytes just falls through to the plain scalar scan.

## build

vs2022, x64 only (Win32 is excluded since the asm is 64 bit):

```
msbuild SQL-memory.vcxproj -p:Configuration=Release -p:Platform=x64
```

output is `build\SQL-memory.exe`. make sure notepad.exe is running if you want the demo to actually attach, otherwise it complains and waits for enter so the console doesn't insta-close.

## adding to another project

the mem layer has no deps outside the crt + windows headers. drop in

- `src/memory/*` (three headers + one cpp)
- `src/syscalls/*` (header, cpp, and the asm - only x64)
- a masm target (`<MASM Include="...syscall.asm" />`) in the vcxproj

and call `Syscalls::Init()` once before the first `Memory::Attach`. if the ids don't resolve, `Ready()` returns false and nothing else gets touched.
