#include "veh.h"
#include "emulator.h"

void*  g_code_base;
size_t g_code_size;

static PVOID g_veh_handle;
static int rsp_shifted = 0;
void* g_emu_stack = NULL;
size_t g_emu_stack_size = 0;

static LONG CALLBACK exception_handler(EXCEPTION_POINTERS* ep)
{
    CONTEXT* ctx = ep->ContextRecord;
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code != EXCEPTION_ACCESS_VIOLATION && code != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    /* For execution AV, RIP usually points to our buffer; but for the first
       fault triggered by a CALL from thread start, RIP may be at the caller.
       Check ExceptionInformation[1] (fault address) as a fallback. */
    ULONG_PTR rip = ctx->Rip;
    if (!veh_in_region(rip) && code == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR fault = ep->ExceptionRecord->ExceptionInformation[1];
        if (veh_in_region(fault)) {
            ctx->Rip = fault;
            rip = fault;
        }
    }

    if (!veh_in_region(rip))
        return EXCEPTION_CONTINUE_SEARCH;

    /* On first entry, redirect RSP to a pre-allocated, zero-initialized stack.
       VirtualAlloc pages are guaranteed zero-filled, preventing residual data
       from corrupting 64-bit pointer args when shellcode uses 32-bit writes. */
    if (g_emu_stack && !rsp_shifted) {
        ctx->Rsp = (uint64_t)(uintptr_t)g_emu_stack + g_emu_stack_size - 0x100;
        ctx->Rsp &= ~0xFULL;
        rsp_shifted = 1;
    }

    /* Tight emulation loop. Each emulate_one updates ctx->Rip and registers.
       When RIP leaves our region (external API call), we handle it below. */
    for (;;) {
        while (veh_in_region(ctx->Rip)) {
            if (!emulate_one(ctx))
                return EXCEPTION_CONTINUE_SEARCH;
        }

        /* RIP left the code region -- Level 2 direct API call.
           Call the API from VEH context using a function pointer, preventing
           the native API from clobbering the emulated (shifted) stack. */
        uint64_t api_addr = ctx->Rip;
        uint64_t return_addr = *(uint64_t*)ctx->Rsp;

        if (!veh_in_region(return_addr))
            break; /* shellcode done */

        /* Read stack args 5-12 from emulated stack before popping. */
        uint64_t a5  = *(uint64_t*)(ctx->Rsp + 40);
        uint64_t a6  = *(uint64_t*)(ctx->Rsp + 48);
        uint64_t a7  = *(uint64_t*)(ctx->Rsp + 56);
        uint64_t a8  = *(uint64_t*)(ctx->Rsp + 64);
        uint64_t a9  = *(uint64_t*)(ctx->Rsp + 72);
        uint64_t a10 = *(uint64_t*)(ctx->Rsp + 80);
        uint64_t a11 = *(uint64_t*)(ctx->Rsp + 88);
        uint64_t a12 = *(uint64_t*)(ctx->Rsp + 96);

        ctx->Rsp += 8; /* pop return address */

        /* Call API with 12 args to cover large-signature Windows APIs. */
        typedef uint64_t (*api_fn_t)(uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);
        api_fn_t fn = (api_fn_t)api_addr;
        ctx->Rax = fn(ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9,
                      a5, a6, a7, a8, a9, a10, a11, a12);

        ctx->Rip = return_addr;
    }

    return EXCEPTION_CONTINUE_EXECUTION;
}

int veh_init(void* code_base, size_t code_size)
{
    g_code_base = code_base;
    g_code_size = code_size;
    g_veh_handle = AddVectoredExceptionHandler(1, exception_handler);
    return g_veh_handle != NULL;
}

void veh_uninit(void)
{
    if (g_veh_handle) {
        RemoveVectoredExceptionHandler(g_veh_handle);
        g_veh_handle = NULL;
    }
}
