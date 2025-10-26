public static class X64Opcodes
{
    public const byte ADD_RM8_R8 = 0x00;
    public const byte JBE_SHORT = 0x76;
    public const byte NOP = 0x90;
    public const byte LEAVE = 0xC9;
    public const byte RET = 0xC3;
    public const byte PUSH_RBP = 0x55;
    public const byte MOV_RM8_IMM8 = 0xC6;
    public const byte MOV_R64_RM64 = 0x8B;
    public const byte ADD_R32_RM32 = 0x03;
    public const byte FF_GROUP = 0xFF;
    public const byte JB_SHORT = 0x72;
    public const byte REX_PREFIX = 0x48;
    public const byte REX_B_GROUP = 0x41;
    public const byte MOV_RM32_IMM32 = 0xC7;
    public const byte PUSH_RDI = 0x57;
    public const byte PUSH_RSI = 0x56;
    public const byte PUSH_RBX = 0x53;
    public const byte MOV_RM64_R64 = 0x89;
    public const byte JMP_SHORT = 0xEB;
    public const byte POP_RBP = 0x5D;
    public const byte JMP = 0xE9;
    public const byte CALL = 0xE8;
    public const byte TWO_BYTE = 0x0F;
    public const byte CMP_AL_IMM8 = 0x3C;
    public const byte JNE_SHORT = 0x75;
    // ...add more as needed
}

