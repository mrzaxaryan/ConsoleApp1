using static NoRWX.Emulator;

namespace NoRWX.Handlers;

public static unsafe class Miscellaneous
{
    public static unsafe bool HandleCmpEvGv8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 38 /r  → CMP r/m8, r8  (Ev - Gv)
        int offs = 1;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7;  // source r8
        int rm = modrm & 7;         // dest r/m8

        ulong* R = &ctx->Rax;
        byte right = (byte)R[reg];
        byte left;
        string leftDesc;

        if (mod == 0b11)
        {
            left = (byte)R[rm];
            leftDesc = $"R{rm}b";
        }
        else
        {
            ulong addr = ResolveEA_NoRex_BaseDispOrRip(ctx, ip, ref offs, mod, rm, out leftDesc);
            left = *(byte*)addr;
        }

        byte res = (byte)(left - right);

        bool cf = left < right;
        bool pf = (0x6996 >> (res & 0xF) & 1) != 0;
        bool af = ((left ^ right ^ res) & 0x10) != 0;
        bool zf = res == 0;
        bool sf = (res & 0x80) != 0;
        bool of = ((left ^ right) & (left ^ res) & 0x80) != 0;

        ctx->EFlags = (uint)(
            ctx->EFlags & ~0x8D5 |
            (cf ? 0x1u : 0u) |
            (pf ? 0x4u : 0u) |
            (af ? 0x10u : 0u) |
            (zf ? 0x40u : 0u) |
            (sf ? 0x80u : 0u) |
            (of ? 0x800u : 0u)
        );

        Log($"CMP {leftDesc}, R{reg}b => result=0x{res:X2} "
            + $"[ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)} CF={(cf ? 1 : 0)} "
            + $"OF={(of ? 1 : 0)} PF={(pf ? 1 : 0)} AF={(af ? 1 : 0)}]", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    public static unsafe bool HandleCmpGvEv8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 3A /r  → CMP r8, r/m8  (Gv - Ev)
        int offs = 1;                          // at ModRM
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7;            // Gv (destination)
        int rm = modrm & 7;                   // Ev (source)

        ulong* R = &ctx->Rax;
        byte left = (byte)R[reg];             // low 8 bits
        byte right;
        string rightDesc;

        if (mod == 0b11)
        {
            right = (byte)R[rm];
            rightDesc = $"R{rm}b";
        }
        else
        {
            ulong addr = ResolveEA_NoRex_BaseDispOrRip(ctx, ip, ref offs, mod, rm, out rightDesc);
            right = *(byte*)addr;
        }

        byte res = (byte)(left - right);

        bool cf = left < right;
        bool pf = (0x6996 >> (res & 0xF) & 1) != 0;
        bool af = ((left ^ right ^ res) & 0x10) != 0;
        bool zf = res == 0;
        bool sf = (res & 0x80) != 0;
        bool of = ((left ^ right) & (left ^ res) & 0x80) != 0;

        ctx->EFlags = (uint)(
            ctx->EFlags & ~0x8D5 |
            (cf ? 0x1u : 0u) |
            (pf ? 0x4u : 0u) |
            (af ? 0x10u : 0u) |
            (zf ? 0x40u : 0u) |
            (sf ? 0x80u : 0u) |
            (of ? 0x800u : 0u)
        );

        Log($"CMP R{reg}b, {rightDesc} => result=0x{res:X2} [ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)} CF={(cf ? 1 : 0)} OF={(of ? 1 : 0)} PF={(pf ? 1 : 0)} AF={(af ? 1 : 0)}]", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    public static unsafe bool HandleMovRm8R8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 88 /r → MOV r/m8, r8
        int offs = 1;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7; // source r8
        int rm = modrm & 7;       // dest r/m8

        ulong* R = &ctx->Rax;
        byte value = (byte)R[reg];

        string dstDesc;
        if (mod == 0b11)
        {
            byte* dst = (byte*)(R + rm);
            *dst = value;
            dstDesc = $"R{rm}b";
        }
        else
        {
            ulong addr = ResolveEA_NoRex_BaseDispOrRip(ctx, ip, ref offs, mod, rm, out dstDesc);
            *(byte*)addr = value;
        }

        Log($"MOV {dstDesc}, R{reg}b => 0x{value:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }

    public static unsafe bool HandleMovR8Rm8(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 8A /r → MOV r8, r/m8
        int offs = 1;
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7; // dest r8
        int rm = modrm & 7;       // source r/m8

        ulong* R = &ctx->Rax;
        byte value;

        string srcDesc;
        if (mod == 0b11)
        {
            value = (byte)R[rm];
            srcDesc = $"R{rm}b";
        }
        else
        {
            ulong addr = ResolveEA_NoRex_BaseDispOrRip(ctx, ip, ref offs, mod, rm, out srcDesc);
            value = *(byte*)addr;
        }

        R[reg] = R[reg] & ~0xFFUL | value;
        Log($"MOV R{reg}b, {srcDesc} => 0x{value:X2}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe bool HandleCmpEvGv32(CONTEXT* ctx, byte* ip, Action<string, int> Log)
    {
        // 39 /r  → CMP r/m32, r32  (Ev - Gv)
        int offs = 1;                          // at ModRM
        byte modrm = ip[offs++];
        byte mod = (byte)(modrm >> 6 & 3);
        int reg = modrm >> 3 & 7;            // Gv
        int rm = modrm & 7;           // Ev

        uint right = GetReg32_NoRex(ctx, reg);
        string rightDesc = Reg32Name(reg);

        uint left; string leftDesc;

        if (mod == 0b11)
        {
            left = GetReg32_NoRex(ctx, rm);
            leftDesc = Reg32Name(rm);
        }
        else
        {
            ulong addr = ResolveEA_NoRex_BaseDispOrRip(ctx, ip, ref offs, mod, rm, out leftDesc);
            left = *(uint*)addr;
        }

        uint res = left - right;
        ctx->EFlags = UpdateFlags_Sub32(ctx->EFlags, left, right, res);

        Log($"CMP {leftDesc}, {rightDesc} => result=0x{res:X8}", offs);
        ctx->Rip += (ulong)offs;
        return true;
    }
    public static unsafe ulong ResolveEA_NoRex_BaseDispOrRip(CONTEXT* ctx, byte* ip, ref int offs, byte mod, int rm, out string desc)
    {
        // mod=00 & rm=101 → RIP+disp32
        if (mod == 0b00 && rm == 0b101)
        {
            int disp32 = *(int*)(ip + offs); offs += 4;
            ulong addr = ctx->Rip + (ulong)offs + (ulong)disp32;
            desc = $"[RIP+0x{disp32:X}]";
            return addr;
        }

        ulong baseAddr = GetReg64_NoRex(ctx, rm);
        if (mod == 0b01)
        {
            sbyte d8 = *(sbyte*)(ip + offs); offs += 1;
            desc = $"[{Reg64Name_NoRex(rm)}{(d8 >= 0 ? "+" : "")}{d8}]";
            return baseAddr + (ulong)d8;
        }
        else if (mod == 0b10)
        {
            int d32 = *(int*)(ip + offs); offs += 4;
            desc = $"[{Reg64Name_NoRex(rm)}+0x{d32:X}]";
            return baseAddr + (ulong)d32;
        }
        desc = $"[{Reg64Name_NoRex(rm)}]";
        return baseAddr;
    }

    public static unsafe uint GetReg32_NoRex(CONTEXT* c, int r) => (r & 7) switch
    {
        0 => (uint)(c->Rax & 0xFFFFFFFF),
        1 => (uint)(c->Rcx & 0xFFFFFFFF),
        2 => (uint)(c->Rdx & 0xFFFFFFFF),
        3 => (uint)(c->Rbx & 0xFFFFFFFF),
        4 => (uint)(c->Rsp & 0xFFFFFFFF),
        5 => (uint)(c->Rbp & 0xFFFFFFFF),
        6 => (uint)(c->Rsi & 0xFFFFFFFF),
        7 => (uint)(c->Rdi & 0xFFFFFFFF),
        _ => 0
    };
    public static unsafe ulong GetReg64_NoRex(CONTEXT* c, int r) => (r & 7) switch
    {
        0 => c->Rax,
        1 => c->Rcx,
        2 => c->Rdx,
        3 => c->Rbx,
        4 => c->Rsp,
        5 => c->Rbp,
        6 => c->Rsi,
        7 => c->Rdi,
        _ => 0
    };
    public static string Reg64Name_NoRex(int r) => (r & 7) switch
    {
        0 => "RAX",
        1 => "RCX",
        2 => "RDX",
        3 => "RBX",
        4 => "RSP",
        5 => "RBP",
        6 => "RSI",
        7 => "RDI",
        _ => "R?"
    };
    public static string Reg32Name(int r) => (r & 7) switch
    {
        0 => "EAX",
        1 => "ECX",
        2 => "EDX",
        3 => "EBX",
        4 => "ESP",
        5 => "EBP",
        6 => "ESI",
        7 => "EDI",
        _ => "E?"
    };

    public static uint UpdateFlags_Sub32(uint oldFlags, uint a, uint b, uint r)
    {
        uint f = oldFlags & ~0x8D5u;                   // clear OF,SF,ZF,AF,PF,CF
        if (b > a) f |= 0x1;                           // CF
        if (r == 0) f |= 1u << 6;                      // ZF
        if ((r & 0x8000_0000u) != 0) f |= 1u << 7;     // SF
        if (((a ^ b) & (a ^ r) & 0x8000_0000u) != 0) f |= 1u << 11; // OF
        if (((a ^ b ^ r) & 0x10u) != 0) f |= 1u << 4;               // AF
        byte low = (byte)r; low ^= (byte)(low >> 4); low &= 0xF;
        if ((0x6996 >> low & 1) != 0) f |= 1u << 2;  // PF
        return f;
    }

    public static bool HandleNop(CONTEXT* ctx, Action<string, int> Log)
    {
        Log("NOP", 1);
        ctx->Rip += 1;
        return true;
    }
    public static bool HandleCmpAlImm8(CONTEXT* ctx, byte* address, Action<string, int> Log)
    {
        byte imm8 = *(address + 1);
        byte al = (byte)(ctx->Rax & 0xFF);
        byte result = (byte)(al - imm8);

        bool cf = al < imm8;
        bool pf = (0x6996 >> (result & 0xFF) & 1) != 0;
        bool af = ((al ^ imm8 ^ result) & 0x10) != 0;
        bool zf = result == 0;
        bool sf = (result & 0x80) != 0;
        bool of = ((al ^ imm8) & (al ^ result) & 0x80) != 0;

        ctx->EFlags = (uint)(
            ctx->EFlags & ~0x8D5 |
            (cf ? 0x1u : 0u) |
            (pf ? 0x4u : 0u) |
            (af ? 0x10u : 0u) |
            (zf ? 0x40u : 0u) |
            (sf ? 0x80u : 0u) |
            (of ? 0x800u : 0u)
        );

        Log($"CMP AL, 0x{imm8:X2} => AL=0x{al:X2} result=0x{result:X2} [ZF={(zf ? 1 : 0)} SF={(sf ? 1 : 0)} CF={(cf ? 1 : 0)} OF={(of ? 1 : 0)} PF={(pf ? 1 : 0)} AF={(af ? 1 : 0)}]", 2);

        ctx->Rip += 2;
        return true;
    }

}