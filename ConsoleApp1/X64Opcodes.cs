public static class X64Opcodes
{
    // Prefixes
    public const byte REX_PREFIX = 0x48;
    public const byte REX_B_GROUP = 0x41;
    public const byte REX_R_GROUP = 0x4C;
    public const byte REX_W_GROUP = 0x49;
    public const byte GS_PREFIX = 0x65;
    public const byte OPSIZE_PREFIX = 0x66;
    public const byte TWO_BYTE = 0x0F;

    // Stack
    public const byte PUSH_RAX = 0x50;
    public const byte PUSH_RCX = 0x51;
    public const byte PUSH_RDX = 0x52;
    public const byte PUSH_RBX = 0x53;
    public const byte PUSH_RSP = 0x54;
    public const byte PUSH_RBP = 0x55;
    public const byte PUSH_RSI = 0x56;
    public const byte PUSH_RDI = 0x57;

    public const byte POP_RAX = 0x58;
    public const byte POP_RCX = 0x59;
    public const byte POP_RDX = 0x5A;
    public const byte POP_RBX = 0x5B;
    public const byte POP_RSP = 0x5C;
    public const byte POP_RBP = 0x5D;
    public const byte POP_RSI = 0x5E;
    public const byte POP_RDI = 0x5F;

    // MOV
    public const byte MOV_RM8_IMM8 = 0xC6;
    public const byte MOV_RM32_IMM32 = 0xC7;
    public const byte MOV_RM64_R64 = 0x89;
    public const byte MOV_R32_RM32 = 0x8B;
    public const byte MOV_RAX_IMM64 = 0xB8;
    public const byte MOV_RCX_IMM64 = 0xB9;
    public const byte MOV_RDX_IMM64 = 0xBA;
    public const byte MOV_RBX_IMM64 = 0xBB;
    public const byte MOV_RSP_IMM64 = 0xBC;
    public const byte MOV_RBP_IMM64 = 0xBD;
    public const byte MOV_RSI_IMM64 = 0xBE;
    public const byte MOV_RDI_IMM64 = 0xBF;
    public const byte MOVZX_GvEw = 0xB7; // under 0F prefix
    public const byte MOVZX_R32_RM8 = 0xB6; // under 0F prefix

    // Arithmetic / logic
    public const byte ADD_RM8_R8 = 0x00;
    public const byte ADD_R32_RM32 = 0x03;
    public const byte XOR_R32_RM32 = 0x33;
    public const byte TEST_RM8_R8 = 0x84;
    public const byte TEST_RM32_R32 = 0x85;
    public const byte INCDEC_RM8 = 0xFE;
    public const byte GRP1_EdIb = 0x83;

    // Control flow
    public const byte CALL = 0xE8;
    public const byte RET = 0xC3;
    public const byte LEAVE = 0xC9;
    public const byte JMP_NEAR = 0xE9;
    public const byte JMP_SHORT = 0xEB;

    // Conditional jumps
    public const byte JO_SHORT = 0x70;
    public const byte JNO_SHORT = 0x71;
    public const byte JB_SHORT = 0x72;
    public const byte JAE_SHORT = 0x73;
    public const byte JE_SHORT = 0x74;
    public const byte JNE_SHORT = 0x75;
    public const byte JBE_SHORT = 0x76;
    public const byte JA_SHORT = 0x77;
    public const byte JS_SHORT = 0x78;
    public const byte JNS_SHORT = 0x79;
    public const byte JP_SHORT = 0x7A;
    public const byte JNP_SHORT = 0x7B;
    public const byte JL_SHORT = 0x7C;
    public const byte JGE_SHORT = 0x7D;
    public const byte JLE_SHORT = 0x7E;
    public const byte JG_SHORT = 0x7F;

    public const byte JE_NEAR = 0x84; // 0F 84
    public const byte JNE_NEAR = 0x85; // 0F 85

    // Misc
    public const byte NOP = 0x90;
    public const byte CMP_AL_IMM8 = 0x3C;
    public const byte SETE = 0x94; // 0F 94
}



