# file_to_carray_pretty.py
import sys
import os

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <file.bin>")
    sys.exit(1)

filename = sys.argv[1]

if not os.path.exists(filename):
    print(f"File not found: {filename}")
    sys.exit(1)

with open(filename, "rb") as f:
    data = f.read()

print(f"// File: {filename}, size: {len(data)} bytes\n")
print("byte[] code = {")
for i in range(0, len(data), 16):
    chunk = data[i:i+16]
    line = ", ".join(f"0x{b:02X}" for b in chunk)
    print(f"    {line},")
print("};")
