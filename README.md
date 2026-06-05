# NoRWX: Run x86-64 Position-Independent Code in RW Memory (No Execute)

![C#](https://img.shields.io/badge/C%23-239120?style=for-the-badge&logo=csharp&logoColor=white)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![x86_64](https://img.shields.io/badge/x86__64-red?style=for-the-badge)
![Security Research](https://img.shields.io/badge/Security-Research-critical?style=for-the-badge)
![Proof of Concept](https://img.shields.io/badge/Proof%20of-Concept-blueviolet?style=for-the-badge)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

[GitHub Project](https://github.com/mrzaxaryan/NoRWX)

---

## Table of Contents
- [Overview](#overview)
- [How It Works](#how-it-works)
- [Main Components](#main-components)
  - [Emulator](#emulator)
  - [Vectored Exception Handler](#vectored-exception-handler)
  - [Program Entry](#program-entry)
- [Usage Example](#usage-example)
- [API Calls & Environment Sharing](#api-calls--environment-sharing)
- [Detection & Ethics Note](#detection--ethics-note)
- [References](#references)

---

## Overview

NoRWX is a proof-of-concept for running position-independent x86-64 machine code entirely from read/write (RW-only) memory, without ever marking it executable. This is achieved without using `VirtualProtect` or `VirtualAlloc`.

---

## How It Works

1. Store the PIC code blob in RW memory.
2. Set a hardware breakpoint on the blob’s entry address using DR0 / DR7.
3. Register a vectored exception handler (VEH).
4. On breakpoint (EXCEPTION_SINGLE_STEP):
   - VEH reads the trapped thread’s CONTEXT (registers, flags, RIP).
   - VEH reads instruction bytes from the RW blob.
   - VEH calls the emulator to decode and execute the instruction logically.
   - VEH re-installs the hardware breakpoint at the new RIP and resumes the thread.
5. Repeat until the emulated code returns or exits the region.

---

## Main Components

### Emulator
- Decodes and executes x86-64 instructions logically by updating thread CONTEXT.
- Supports arithmetic, logic, control flow, stack, and miscellaneous operations.
- Logs instruction execution and register changes for debugging.

### Vectored Exception Handler
- Installs a VEH to handle hardware breakpoints.
- Sets and resets hardware breakpoints using thread context.
- Handles instruction emulation and breakpoint reinstallation.

### Program Entry
- Loads a binary code blob (e.g., `HelloWorld.bin`).
- Initializes the VEH and runs the code blob in RW memory.
- Cleans up after execution.

---

## Building from Command Line

```bash
dotnet build NoRWX -c Debug -r win-x64 --self-contained
```

---

## Usage Example

```csharp
byte[] binaryHelloWorld = File.ReadAllBytes("HelloWorld.bin");
Run(binaryHelloWorld);

static void Run(byte[] buffer)
{
    fixed (byte* pBuffer = buffer)
    {
        VectoredExceptionHandler.Initialize((nint)pBuffer, (nuint)buffer.Length);
        ((delegate* unmanaged<void>)pBuffer)();
        VectoredExceptionHandler.Uninitialize();
    }
}
```

---

## API Calls & Environment Sharing

- When emulated instructions call OS APIs, the emulator checks if RIP is outside RW memory.
- Sets a breakpoint on the return address in RSP for external calls.
- Ensures emulated code runs under the same thread/process environment, allowing WinAPI calls to behave natively.

---

## Detection & Ethics Note

**Research-only.**
- This technique does not guarantee stealth. Security products may detect hardware breakpoint usage, VEH patterns, or emulator behavior.
- Do not use to evade detection, run untrusted code, or break laws/policies.
- Always test in isolated, offline VMs and follow responsible disclosure and research ethics.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for the full responsible use policy.

---

## References
- [NoRWX GitHub](https://github.com/mrzaxaryan/NoRWX)
- [Vectored Exception Handling (Microsoft Docs)](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [x86-64 Instruction Set Reference](https://www.felixcloutier.com/x86/)
