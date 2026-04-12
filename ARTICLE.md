# NoRWX: Executing Code Without Executable Memory

## Running x86-64, x86-32, and ARM64 Shellcode from Read/Write Pages Using Hardware Breakpoints and Vectored Exception Handling

---

Modern operating systems enforce a simple rule: memory that is writable should not be executable, and memory that is executable should not be writable. This is the foundation of Data Execution Prevention (DEP) and W^X policies. To run dynamically loaded code, you typically call `VirtualAlloc` with `PAGE_EXECUTE_READWRITE`, or flip permissions with `VirtualProtect` -- both of which are well-known to security products and heavily monitored.

**NoRWX** takes a different path entirely. It executes position-independent code from memory that is *never* marked executable -- no `VirtualProtect`, no `VirtualAlloc` with execute permissions. Instead, it uses a combination of **hardware breakpoints** (debug registers DR0-DR7) and **Vectored Exception Handling (VEH)** to intercept every instruction fetch and emulate it in software.

This article walks through the architecture, the instruction emulation engine, cross-architecture support, and the engineering challenges behind the project.

---

## The Core Idea

The technique rests on a straightforward observation: if you can trap every attempt to execute an instruction and emulate it instead, the code bytes themselves never need to be in executable memory.

Here is the execution flow:

1. **Store shellcode in RW memory.** The code blob sits in a `PAGE_READWRITE` region -- a normal byte array, indistinguishable from data.

2. **Set a hardware breakpoint.** Using debug register DR0, point at the first byte of the code blob. Configure DR7 to enable execution breakpoints.

3. **Register a Vectored Exception Handler.** Windows VEH gives us first-chance exception handling -- before any structured exception handler sees it.

4. **Trigger the breakpoint.** Cast the buffer pointer to a function pointer and call it. The CPU faults immediately because the memory is not executable.

5. **Emulate in the handler.** The VEH callback receives the full thread `CONTEXT` -- all registers, flags, and the instruction pointer. It reads the instruction bytes from the RW buffer, decodes and executes the instruction by updating the `CONTEXT` in place, advances RIP, and returns `EXCEPTION_CONTINUE_EXECUTION`.

6. **Repeat.** The hardware breakpoint fires again at the new RIP, and the cycle continues until the emulated code returns.

```
CPU attempts fetch at DR0 address
        |
        v
EXCEPTION_SINGLE_STEP fired
        |
        v
VEH reads CONTEXT (RIP, registers, flags)
        |
        v
Read instruction bytes from RW memory at RIP
        |
        v
Decode & emulate instruction (update CONTEXT)
        |
        v
Advance RIP, reinstall breakpoint
        |
        v
EXCEPTION_CONTINUE_EXECUTION --> CPU resumes --> breakpoint fires again
```

The result: code executes instruction-by-instruction without the memory page ever being marked executable.

---

## The Instruction Emulator

At the heart of NoRWX is a software CPU emulator that handles real x86-64 machine code. This is not a simplified VM with custom bytecode -- it decodes actual Intel/AMD instructions, including prefixes, ModRM bytes, SIB addressing, and immediate operands.

### Decoding Pipeline

Every instruction goes through a multi-stage decode:

**Legacy Prefixes** -- The decoder consumes prefix bytes (segment overrides `0x26/0x2E/0x36/0x3E/0x64/0x65`, operand size `0x66`, address size `0x67`, REP/REPNE `0xF2/0xF3`) before reaching the opcode.

**REX Prefix** -- In 64-bit mode, bytes `0x40-0x4F` encode the REX prefix. Its four bits control 64-bit operand size (W), register extensions (R, X, B) that expand the register file from 8 to 16 general-purpose registers.

**ModRM + SIB** -- The ModRM byte encodes the addressing mode, source/destination registers, and whether a SIB byte follows. The SIB byte adds scaled-index addressing (`base + index * scale + displacement`). Together, these handle the full range of x86 memory addressing modes, including RIP-relative addressing in 64-bit mode.

**Effective Address Resolution:**
```
if (rm & 7) == 4:       SIB byte follows
if mod == 00 && rm == 5: RIP-relative (x64)
otherwise:               base_register + displacement
```

### Flag Calculation

x86 flag computation is notoriously detailed. The emulator computes all six arithmetic flags for every relevant instruction:

- **CF** (Carry): unsigned overflow/borrow
- **OF** (Overflow): signed overflow -- both operands same sign, result opposite
- **ZF** (Zero): result is zero
- **SF** (Sign): MSB of result
- **AF** (Auxiliary Carry): carry from bit 3 to bit 4
- **PF** (Parity): even parity of the result's low byte

Logic operations (AND, OR, XOR, TEST) clear CF and OF, setting only ZF, SF, and PF. INC/DEC preserve CF. Each instruction family has its own flag semantics, and getting them wrong breaks conditional branches downstream.

### Instruction Coverage

The emulator supports over 100 x86-64 instructions organized into modular handlers:

| Category | Instructions |
|----------|-------------|
| **Arithmetic** | ADD, ADC, SUB, SBB, INC, DEC, MUL, IMUL, DIV, IDIV, NEG, CMP, shifts (SAL/SAR/SHL/SHR/ROL/ROR) |
| **Logic** | AND, OR, XOR, TEST |
| **Data Movement** | MOV (all encodings), LEA, MOVZX, MOVSX, MOVSXD, XCHG, CMOVcc |
| **Stack** | PUSH, POP, ENTER, LEAVE |
| **Control Flow** | CALL, RET, JMP, all 16 Jcc variants, LOOP/LOOPE/LOOPNE, INT3 |
| **String Ops** | REP MOVS/LODS/STOS/CMPS/SCAS (byte/word/dword/qword) |
| **SSE/SSE2** | 60+ instructions -- MOVAPS, XORPS, ADDPS, MULPS, CVTSI2SD, COMISS, LDMXCSR, etc. |
| **Misc** | NOP, LAHF/SAHF, PUSHF/POPF, CLC/STC/CMC, CLD/STD, CBW/CWDE/CDQE, CWD/CDQ/CQO |

This is enough to run real-world position-independent code compiled from C, including shellcode that resolves APIs dynamically by walking the PEB.

---

## Handling External API Calls

Emulated shellcode is not useful if it cannot call Windows APIs. NoRWX handles this transparently:

When a `CALL` instruction targets an address **outside** the RW code region, the emulator knows execution is leaving emulated territory. At this point:

1. The target address (the API function) is extracted from the new RIP.
2. The return address is read from the top of the stack (RSP).
3. Arguments are extracted following the x64 calling convention -- RCX, RDX, R8, R9 for the first four, plus up to 8 more from the stack (supporting 12-argument APIs like `NtDeviceIoControlFile`).
4. The API is called **directly** via a function pointer from managed code.
5. The return value is written to RAX.
6. RIP is set to the return address, and emulation continues.

Because the emulated code runs in the same thread and process context, all Windows APIs behave natively -- handle tables, TEB/PEB, heap allocators, everything works as expected.

---

## Multi-Architecture Support

NoRWX is not limited to x86-64. It supports three architectures:

### x86-64 (Primary)

The flagship target. Execution happens on a **new thread** with a `stackalloc`'d 1 MB stack to isolate the emulated code's stack from the .NET runtime's. The VEH sets DR0 on the new thread's context and catches `EXCEPTION_SINGLE_STEP`.

### x86-32 (i386)

32-bit emulation runs on the **current thread** with a pre-allocated, zero-initialized stack. The key differences: no REX prefix (bytes `0x40-0x47` are INC/DEC rather than REX), arguments pass on the stack (cdecl/stdcall), and 8-bit register encoding includes AH/CH/DH/BH at indices 4-7 (without REX to disambiguate).

### ARM64 (AArch64)

ARM64 support brings a fundamentally different ISA -- fixed 4-byte instructions, 31 general-purpose registers, a dedicated zero register (XZR/WZR), and condition flags in CPSR rather than EFLAGS.

The ARM64 emulator handles:
- **Data processing** (immediate and register forms): ADD, SUB, ORR, EOR, AND, MOV variants, shifts
- **Load/Store**: LDR, STR, LDP, STP with various addressing modes
- **Branching**: B, BL, BR, BLR, CBZ, CBNZ, B.cond

A critical ARM64 detail: register X18 serves as the **TEB pointer** on Windows ARM64. The emulator saves it on first entry and restores it before any API call to avoid corrupting the thread environment. Additionally, a **separate 1 MB stack** is allocated because the native process stack is shared with the .NET runtime and gets corrupted during emulation.

Two modes are supported:
- **Native ARM64**: Running on actual ARM64 hardware with `CONTEXT_ARM64`.
- **Prism emulation**: Running on an x64 process under Windows' Prism translation layer, where ARM64 registers are mapped to x64 CONTEXT fields (Rax -> X0, Rcx -> X1, etc.) with X16-X30 backed by static fields.

---

## The C Port

Alongside the primary C# implementation, NoRWX includes a **pure C port** -- approximately 6,600 lines of code that mirror the C# architecture one-to-one:

| C# | C |
|----|---|
| `EmulatorX64.cs` | `emulator.c` |
| `InstructionDecoder.cs` | `decoder.c` |
| `FlagsCalculator.cs` | `flags.c` |
| `Handlers/*.cs` | `handlers/*.c` |
| `VectoredExceptionHandler.cs` | `veh.c` |

The C port trades .NET's type safety and garbage collection for minimal dependencies (just `windows.h` and `stdlib`), no managed-to-unmanaged transition overhead, and the ability to compile as a standalone executable or DLL. It currently supports x64 and x86-32.

---

## Stack Isolation

A subtle but critical engineering decision: emulated code needs its own stack.

On x64, when the VEH fires, the current stack belongs to the .NET runtime (or the C runtime, in the C port). If emulated code pushes values, calls functions, or sets up stack frames on this stack, it will corrupt the runtime's state. NoRWX solves this by:

1. **Creating a new thread** specifically for emulated execution.
2. Using `stackalloc` to allocate a **1 MB buffer** on that thread.
3. On the first VEH entry, **redirecting RSP** to point into this buffer.

The emulated code sees a clean, dedicated stack. The runtime's stack is untouched.

On ARM64, the problem is even more acute because the .NET runtime actively uses the native stack during exception handling. A completely separate heap-allocated buffer serves as the ARM64 emulated stack.

---

## Testing

The project includes a comprehensive xUnit test suite with 14 test files covering:

- Every instruction category (arithmetic, logic, movement, stack, control flow)
- All 16 condition codes for Jcc/CMOVcc/SETcc
- ModRM and SIB addressing modes, including RIP-relative
- REX prefix encoding (R8-R15 register access)
- Operand size variants (8, 16, 32, 64-bit)
- REP-prefixed string operations
- Edge cases (zero-length REP, boundary conditions, flag preservation)
- ARM64-specific tests (branch, data processing, load/store)

Tests work by constructing a `CONTEXT` struct, writing instruction bytes into a buffer, calling the emulator, and asserting the resulting register and flag state.

---

## Sample Shellcode

The `samples/` directory contains precompiled position-independent code blobs for all three architectures:

- **HelloWorld.bin** (1 KB) -- minimal x64 test payload
- **windows-x86_64.bin** (99 KB) -- full x64 PIC with syscall capability
- **windows-i386.bin** (102 KB) -- 32-bit PIC
- **windows-aarch64.bin** (86 KB) -- ARM64 PIC

The sample source (`samples/main.c`) demonstrates PEB walking to enumerate loaded modules, export table parsing via `IMAGE_EXPORT_DIRECTORY`, and dynamic API resolution at runtime -- standard techniques for position-independent Windows shellcode.

---

## Detection Considerations

NoRWX is a **research proof-of-concept**, not a stealth tool. Several aspects make it detectable:

- **Hardware breakpoint usage**: DR0-DR7 modifications are visible to anti-cheat and EDR tools that monitor debug registers.
- **VEH registration patterns**: The exception handler's behavior (repeated context modification, register state changes) can be fingerprinted.
- **Timing anomalies**: Instruction-by-instruction emulation is orders of magnitude slower than native execution, creating detectable timing signatures.
- **Exception frequency**: Thousands of single-step exceptions per second is anomalous and observable through ETW (Event Tracing for Windows).

---

## Summary

NoRWX demonstrates that the boundary between "data" and "code" is enforced by the CPU's memory protection, not by the bytes themselves. By intercepting execution at the hardware level and emulating instructions in software, it runs real machine code from memory that was never executable.

The project's value is educational: it is a working reference for x86-64/x86-32/ARM64 instruction decoding, flag computation, addressing mode resolution, and Windows exception handling internals. The dual C#/C implementations, comprehensive test suite, and multi-architecture support make it a thorough exploration of CPU emulation within the constraints of the Windows memory model.

**Project**: [github.com/mrzaxaryan/NoRWX](https://github.com/mrzaxaryan/NoRWX)

---

*NoRWX is intended for security research and education only. Always test in isolated environments and follow responsible disclosure practices.*
