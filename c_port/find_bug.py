# Look at the shellcode binary for the ReadShell handler
# Find the pattern after "Command written to shell" where pipe output is read
import sys

with open("windows-x86_64-nosyscall.bin", "rb") as f:
    data = f.read()

# Search for "ReadShell" or "read" related strings
targets = [b"ReadShell", b"read_shell", b"pipe", b"shell", b"ReadFile"]
for t in targets:
    idx = data.find(t)
    if idx >= 0:
        print(f"Found '{t.decode(errors='replace')}' at offset 0x{idx:x}")

# Search for the "Command written to shell" string
idx = data.find(b"Command written")
if idx >= 0:
    print(f"Found 'Command written' at offset 0x{idx:x}")

# Look for NtReadFile syscall stub pattern (4C 8B D1 B8 xx 00 00 00 0F 05)
# Or direct ntdll call patterns
