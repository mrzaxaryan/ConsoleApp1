# NoRWX

**Proof-of-Concept** that runs position-independent (PIC) x86-64 machine code that lives entirely in **read/write (RW-only)** memory — without ever marking it executable.  
No `VirtualProtect` / `VirtualAlloc` calls to gain `PAGE_EXECUTE*` are required.

---

## Overview

Modern OSes and platform protections normally prevent executing code from RW-only pages. **NoRWX** demonstrates how to run PIC machine code stored in RW memory by combining:

- a **vectored exception handler (VEH)**, and  
- a **hardware breakpoint (DR0 / DR7)**

The hardware breakpoint traps instruction fetches. The VEH reads instruction bytes from the RW blob and passes them to an emulator that decodes and executes them logically (by updating the trapped thread’s `CONTEXT` registers). Execution proceeds by advancing `RIP` and re-installing the hardware breakpoint on the next instruction — the memory never needs to be marked executable.

---

## How it works (step-by-step)

1. Store the PIC code blob in RW memory (heap, static buffer, etc.).
2. Set a hardware breakpoint on the blob’s entry address using DR0 / DR7.
3. Register an exception handler.
4. When the CPU hits the breakpoint (`EXCEPTION_SINGLE_STEP`):
   - The VEH reads the trapped thread’s `CONTEXT` (registers, flags, `RIP`).
   - The VEH reads the instruction bytes from the RW blob.
   - The VEH calls the emulator to emulate the instruction.
   - The emulator decodes and executes the instruction logically (modifying registers/memory) so WinAPI calls work.
   - The VEH re-installs the hardware breakpoint at the new `RIP` and resumes the thread.
5. Repeat until the emulated code returns or exits the region.

> **Execution flow remains inside RW memory; instruction semantics are reproduced in software.**

---

## API calls & environment sharing

When emulated instructions need OS APIs, the emulator checks if `RIP` is outside the RW executing memory and, if so, sets a breakpoint on `RSP` (which holds the return address).  
When the external function returns, the breakpoint fires and execution continues.

The emulator also handles the `GS`/TEB context, so emulated code shares the host thread’s TEB and PEB.  
Emulated instructions therefore run under the same thread/process environment (handles, loader data, stack), allowing WinAPI to behave as it would in native execution — even though the code resides in non-executable memory.

---

## Important detection & ethics note

This is **research-only**.  
It does **not** guarantee stealth — security products may detect unusual hardware breakpoint usage, VEH patterns, or the emulator’s behavior.

**Do not** use this technique to evade detection, run untrusted code on systems you don’t own, or break laws or policies.  
Always test in **isolated, offline VMs** and follow **responsible disclosure** and **research ethics**.
