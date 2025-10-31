# NoRWX

Proof-of-Concept that runs position independent x86-64 machine code that lives entirely in read/write (RW-only) memory — without ever marking it executable.  
No VirtualProtect and VirtualAlloc are used.

---

## Overview

NoRWX demonstrates how to run PIC stored in RW memory by combining:

- a vectored exception handler (VEH)
- a hardware breakpoint (DR0 / DR7)

The hardware breakpoint traps instruction fetches. The VEH reads instruction bytes from the RW blob and passes them to the emulator that decodes and executes them logically (by updating the trapped thread’s CONTEXT registers). Execution proceeds by advancing RIP and re-installing the hardware breakpoint on the next instruction — the memory never needs to be marked executable.

---

## How it works (step-by-step)

1. Store the PIC code blob in RW memory.
2. Set a hardware breakpoint on the blob’s entry address using DR0 / DR7.
3. Register an exception handler.
4. When the CPU hits the breakpoint (EXCEPTION_SINGLE_STEP):
   - The VEH reads the trapped thread’s CONTEXT (registers, flags, RIP).
   - The VEH reads the instruction bytes from the RW blob.
   - The VEH calls the emulator to emulate the instruction.
   - The emulator decodes and executes the instruction logically (modifying registers/memory).
   - The VEH re-installs the hardware breakpoint at the new RIP and resumes the thread.
5. Repeat until the emulated code returns or exits the region.

---

## API calls & environment sharing

When emulated instructions call OS APIs, the emulator checks whether RIP is outside RW memory; if so, it sets a breakpoint on the return address stored in RSP. After the external function returns, the breakpoint fires and execution continues.

Emulated instructions therefore run under the same thread/process environment (handles, loader data, stack), allowing WinAPI to behave as it would in native execution.

---

## Important detection & ethics note

This is research-only.  
It does not guarantee stealth — security products may detect unusual hardware breakpoint usage, VEH patterns, or the emulator’s behavior.

Do not use this technique to evade detection, run untrusted code on systems you don’t own, or break laws or policies.  
Always test in isolated, offline VMs and follow responsible disclosure and research ethics.
