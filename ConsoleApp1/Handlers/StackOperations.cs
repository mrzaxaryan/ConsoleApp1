using static ConsoleApp1.RWXless;

namespace ConsoleApp1.Handlers;

public static unsafe class StackOperations
{
    public static bool Handle(byte opcode, CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        switch (opcode)
        {
            // PUSH RAX–RDI
            case >= 0x50 and <= 0x57:
                {
                    int reg = opcode - 0x50; // 0..7
                    ulong value = *(&ctx->Rax + reg);
                    if (reg == 4) value = ctx->Rsp; // special rule
                    return Push(ctx, value, $"R{reg}", Log);
                }

            // POP RAX–RDI
            case >= 0x58 and <= 0x5F:
                {
                    int reg = opcode - 0x58;
                    return Pop(ctx, reg, Log);
                }

            // PUSH R8–R15 (REX.B=1)
            case 0x41 when *(address + 1) is >= 0x50 and <= 0x57:
                {
                    int reg = (*(address + 1)) - 0x50 + 8;
                    ulong value = *(&ctx->Rax + reg);
                    return Push(ctx, value, $"R{reg}", Log, instrLen: 2);
                }

            // POP R8–R15 (REX.B=1)
            case 0x41 when *(address + 1) is >= 0x58 and <= 0x5F:
                {
                    int reg = (*(address + 1)) - 0x58 + 8;
                    return Pop(ctx, reg, Log, instrLen: 2);
                }

            // --- PUSH imm8 (6A ib) ---
            case 0x6A:
                {
                    sbyte imm8 = *(sbyte*)(address + 1);
                    ulong value = (ulong)(long)imm8; // sign-extend
                    ctx->Rsp -= 8;
                    *(ulong*)ctx->Rsp = value;
                    Log($"PUSH imm8 (0x{(byte)imm8:X2}) => 0x{value:X}", 2);
                    ctx->Rip += 2;
                    return true;
                }

            // --- PUSH imm32 (68 id) ---
            case 0x68:
                {
                    uint imm32 = *(uint*)(address + 1);
                    ulong value = imm32; // zero-extend
                    ctx->Rsp -= 8;
                    *(ulong*)ctx->Rsp = value;
                    Log($"PUSH imm32 (0x{imm32:X8})", 5);
                    ctx->Rip += 5;
                    return true;
                }

            // --- PUSH r/m64 (FF /6) ---
            case 0xFF:
                {
                    byte modrm = *(address + 1);
                    int regop = (modrm >> 3) & 0x7;

                    if (regop == 6)
                    {
                        ulong value = ReadRm64(ctx, address + 1, out int len);
                        ctx->Rsp -= 8;
                        *(ulong*)ctx->Rsp = value;
                        Log($"PUSH r/m64 (0x{value:X})", len + 1);
                        ctx->Rip += (ulong)(len + 1);
                        return true;
                    }
                    return false;
                }

            // --- POP r/m64 (8F /0) ---
            case 0x8F:
                {
                    byte modrm = *(address + 1);
                    int regop = (modrm >> 3) & 0x7;

                    if (regop == 0)
                    {
                        ulong value = *(ulong*)ctx->Rsp;
                        ctx->Rsp += 8;
                        WriteRm64(ctx, address + 1, value, out int len);
                        Log($"POP r/m64 => 0x{value:X}", len + 1);
                        ctx->Rip += (ulong)(len + 1);
                        return true;
                    }
                    return false;
                }

            default:
                return false;
        }
    }

    // --- Generic PUSH helper ---
    private static bool Push(CONTEXT* ctx, ulong value, string name, Action<string, int> Log, int instrLen = 1)
    {
        ctx->Rsp -= 8;
        *(ulong*)ctx->Rsp = value;
        Log($"PUSH {name} (0x{value:X})", instrLen);
        ctx->Rip += (ulong)instrLen;
        return true;
    }

    // --- Generic POP helper ---
    private static bool Pop(CONTEXT* ctx, int reg, Action<string, int> Log, int instrLen = 1)
    {
        ulong val = *(ulong*)ctx->Rsp;
        ctx->Rsp += 8;
        *(&ctx->Rax + reg) = val;
        Log($"POP R{reg} => 0x{val:X}", instrLen);
        ctx->Rip += (ulong)instrLen;
        return true;
    }

    // --- Memory helper stubs (to be filled in or linked) ---
    private static ulong ReadRm64(CONTEXT* ctx, byte* modrmPtr, out int len)
    {
        // TODO: integrate your ModRM decoding here
        // for now assume simple [RAX]
        len = 1;
        return *(ulong*)ctx->Rax;
    }

    private static void WriteRm64(CONTEXT* ctx, byte* modrmPtr, ulong value, out int len)
    {
        // TODO: integrate your ModRM decoding here
        // for now assume simple [RAX]
        len = 1;
        *(ulong*)ctx->Rax = value;
    }
}
