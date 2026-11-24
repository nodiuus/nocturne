#include "vm_interpreter.hpp"
#include "common.hpp"
#include "junk.hpp"
#include "handler_impl.hpp"
#include "vm_utils.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <Windows.h>
#include <intrin.h>

#pragma section(".vmb$a", read, execute)
#pragma section(".vmb$code", read, execute)
#pragma section(".vmb$m", read, execute)
#pragma section(".vmb$z", read, execute)
#pragma comment(linker, "/SECTION:.vmb,ERW")

extern "C" {
extern __declspec(allocate(".vmb$a")) const uint8_t __vmb_blob_start = 0;
extern __declspec(allocate(".vmb$z")) const uint8_t __vmb_blob_end = 0;
}

#pragma code_seg(push, ".vmb$m")

extern "C" __declspec(allocate(".vmb$m")) __declspec(align(16)) const uint8_t vm_native_call_bridge_code[] = {
    0x48, 0x83, 0xEC, 0x38,                   // sub rsp, 0x38
    0x48, 0x89, 0x54, 0x24, 0x20,             // mov [rsp+0x20], rdx
    0x48, 0x89, 0x4C, 0x24, 0x28,             // mov [rsp+0x28], rcx
    0x48, 0x8B, 0x02,                         // mov rax, [rdx]
    0x48, 0x8B, 0x4A, 0x10,                   // mov rcx, [rdx+0x10]
    0x4C, 0x8B, 0x42, 0x40,                   // mov r8,  [rdx+0x40]
    0x4C, 0x8B, 0x4A, 0x48,                   // mov r9,  [rdx+0x48]
    0x4C, 0x8B, 0x52, 0x50,                   // mov r10, [rdx+0x50]
    0x4C, 0x8B, 0x5A, 0x58,                   // mov r11, [rdx+0x58]
    0x48, 0x8B, 0x52, 0x18,                   // mov rdx, [rdx+0x18]
    0xFF, 0x54, 0x24, 0x28,                   // call qword ptr [rsp+0x28]
    0x4C, 0x89, 0x5C, 0x24, 0x30,             // mov [rsp+0x30], r11
    0x4C, 0x8B, 0x5C, 0x24, 0x20,             // mov r11, [rsp+0x20]
    0x49, 0x89, 0x03,                         // mov [r11], rax
    0x49, 0x89, 0x4B, 0x10,                   // mov [r11+0x10], rcx
    0x49, 0x89, 0x53, 0x18,                   // mov [r11+0x18], rdx
    0x4D, 0x89, 0x43, 0x40,                   // mov [r11+0x40], r8
    0x4D, 0x89, 0x4B, 0x48,                   // mov [r11+0x48], r9
    0x4D, 0x89, 0x53, 0x50,                   // mov [r11+0x50], r10
    0x4C, 0x8B, 0x54, 0x24, 0x30,             // mov r10, [rsp+0x30]
    0x4D, 0x89, 0x53, 0x58,                   // mov [r11+0x58], r10
    0x48, 0x83, 0xC4, 0x38,                   // add rsp, 0x38
    0xC3                                      // ret
};

#ifdef vm_interpreter_trace
#include <cstdio>
#define vm_trace(...) std::printf(__VA_ARGS__)
#else
#define vm_trace(...) ((void)0)
#endif

template<bool enable>
vm_inline void vm_trace_helper(const char* fmt, ...) {
    if constexpr (enable) {
        va_list args;
        va_start(args, fmt);
        std::vprintf(fmt, args);
        va_end(args);
    }
}

using namespace vm_utils;
using byte_io::read_u64_le;
using byte_io::write_u64_le;

namespace {
    vm_inline uint64_t get_process_image_base_runtime() {
#if defined(_MSC_VER) && defined(_M_X64)
        uint64_t peb = __readgsqword(0x60);
        if (!peb) {
            return 0;
        }
        return *reinterpret_cast<uint64_t*>(peb + 0x10);
#else
        return 0;
#endif
    }

    vm_inline uint64_t get_containing_image_base_runtime(uint64_t address) {
#if defined(_MSC_VER) && defined(_M_X64)
        uint64_t peb = __readgsqword(0x60);
        if (!peb || !address) {
            return 0;
        }

        uint64_t ldr = *reinterpret_cast<uint64_t*>(peb + 0x18);
        if (!ldr) {
            return 0;
        }

        uint64_t list_head = ldr + 0x20;
        uint64_t link = *reinterpret_cast<uint64_t*>(list_head);
        for (uint32_t i = 0; i < 256 && link && link != list_head; ++i) {
            uint64_t entry = link - 0x10;
            uint64_t dll_base = *reinterpret_cast<uint64_t*>(entry + 0x30);
            uint32_t size_of_image = *reinterpret_cast<uint32_t*>(entry + 0x40);
            if (dll_base && size_of_image &&
                address >= dll_base &&
                address < (dll_base + static_cast<uint64_t>(size_of_image))) {
                return dll_base;
            }
            link = *reinterpret_cast<uint64_t*>(link);
        }
#else
        (void)address;
#endif
        return 0;
    }

    vm_inline uint64_t get_image_base_runtime() {
        uint64_t containing_base = get_containing_image_base_runtime(
            reinterpret_cast<uint64_t>(&__vmb_blob_start));
        if (containing_base) {
            return containing_base;
        }
        return get_process_image_base_runtime();
    }

    vm_inline uint32_t get_image_size_runtime(uint64_t image_base) {
        if (!image_base) {
            return 0;
        }

        const uint8_t* base = reinterpret_cast<const uint8_t*>(image_base);
        const uint16_t mz = *reinterpret_cast<const uint16_t*>(base);
        if (mz != IMAGE_DOS_SIGNATURE) {
            return 0;
        }

        const int32_t e_lfanew = *reinterpret_cast<const int32_t*>(base + 0x3C);
        if (e_lfanew <= 0) {
            return 0;
        }

        const uint32_t pe = *reinterpret_cast<const uint32_t*>(base + e_lfanew);
        if (pe != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        const uint16_t magic = *reinterpret_cast<const uint16_t*>(base + e_lfanew + 0x18);
        if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return 0;
        }

        return *reinterpret_cast<const uint32_t*>(base + e_lfanew + 0x18 + 0x38);
    }
}

vm_inline void vm_reset_state_internal(vm_state& vm) {
    byte_io::zero_u64_array(vm.regs, static_cast<uint32_t>(vm_register_count));
    vm.ip = 0;
    vm.halted = false;
    byte_io::zero_u8_array(vm.memory, vm.memory_size);
}

vm_inline void vm_initialize_state_internal(vm_state& vm, uint8_t* code_buffer, uint32_t code_capacity, uint8_t* memory_buffer, uint32_t memory_capacity) {
    vm.code = code_buffer;
    vm.code_capacity = code_capacity;
    vm.code_size = 0;
    vm.code_is_chunked = false;
    vm.chunked_code_blob = nullptr;
    vm.chunked_code_blob_size = 0;
    vm.chunk_count = 0;
    vm.memory = memory_buffer;
    vm.memory_size = memory_capacity;
    vm.image_base = 0;
    vm.image_size = 0;
    vm_reset_state_internal(vm);
}

template<bool trace_enabled>
static vm_inline void run_vm_logic(vm_state& vm, vm_flags& flags) {
    //vmenter
    generator<250>::generate_junk();

    if (!vm.code || vm.code_size == 0 || !vm.memory || vm.memory_size == 0) {
        return;
    }

    if (!vm.code_is_chunked) {
        configure_chunked_code(vm, vm.code, vm.code_size);
    }

    vm.ip = 0;
    vm.halted = false;

    if (VM_REG_INDEX_RSP < vm_register_count) {
        vm.regs[VM_REG_INDEX_RSP] = reinterpret_cast<uint64_t>(vm.memory) + vm.memory_size;
    }
    if (VM_REG_INDEX_RBP < vm_register_count) {
        vm.regs[VM_REG_INDEX_RBP] = vm.regs[VM_REG_INDEX_RSP];
    }

    int instruction_count = 0;
    constexpr int MAX_INSTRUCTIONS = 1000000; 
 
    generator<20>::generate_junk();
    while (!vm.halted && vm.ip < vm.code_size && instruction_count < MAX_INSTRUCTIONS) {
        generator<20>::generate_junk();
        uint8_t op = 0;

        if (!fetch_code_u8(vm, op)) {
            vm.halted = true;
            break;
        }

        ++instruction_count;

        switch (op) {
        case op_nop: 
            handlers::handle_nop(vm, flags);
            break;
        case op_mov_imm: 
            handlers::handle_mov_imm(vm, flags);
            break;
        case op_add: 
            handlers::handle_add(vm, flags);
            break;
        case op_sub:
            handlers::handle_sub(vm, flags);
            break;
        case op_mul:
            handlers::handle_mul(vm, flags);
            break;
        case op_div:
            handlers::handle_div(vm, flags);
            break;
        case op_x86_div:
            handlers::handle_x86_div(vm, flags);
            break;
        case op_load_mem:
            handlers::handle_load_mem(vm, flags);
            break;
        case op_store_mem:
            handlers::handle_store_mem(vm, flags);
            break;
        case op_mov_reg:
            handlers::handle_mov_reg(vm, flags);
            break;
        case op_and:
            handlers::handle_and(vm, flags);
            break;
        case op_or:
            handlers::handle_or(vm, flags);
            break;
        case op_xor:
            handlers::handle_xor(vm, flags);
            break;
        case op_not:
            handlers::handle_not(vm, flags);
            break;
        case op_shl:
            handlers::handle_shl(vm, flags);
            break;
        case op_shr:
            handlers::handle_shr(vm, flags);
            break;
        case op_sar:
            handlers::handle_sar(vm, flags);
            break;
        case op_jmp:
            handlers::handle_jmp(vm, flags);
            break;
        case op_jz:
            handlers::handle_jz(vm, flags);
            break;
        case op_cmp:
            handlers::handle_cmp(vm, flags);
            break;
        case op_jnz:
            handlers::handle_jnz(vm, flags);
            break;
        case op_jl:
            handlers::handle_jl(vm, flags);
            break;
        case op_jg:
            handlers::handle_jg(vm, flags);
            break;
        case op_jle:
            handlers::handle_jle(vm, flags);
            break;
        case op_jb:
            handlers::handle_jb(vm, flags);
            break;
        case op_jbe:
            handlers::handle_jbe(vm, flags);
            break;
        case op_jae:
            handlers::handle_jae(vm, flags);
            break;
        case op_ja:
            handlers::handle_ja(vm, flags);
            break;
        case op_jge:
            handlers::handle_jge(vm, flags);
            break;
        case op_call_native:
            handlers::handle_call_native(vm, flags);
            break;
        case op_store_mem8:
            handlers::handle_store_mem8(vm, flags);
            break;
        case op_store_mem_zero128:
            handlers::handle_store_mem_zero128(vm, flags);
            break;
        case op_call_native_indirect:
            handlers::handle_call_native_indirect(vm, flags);
            break;
        case op_call_native_mem:
            handlers::handle_call_native_mem(vm, flags);
            break;
        case op_cmpxchg_mem64:
            handlers::handle_cmpxchg_mem64(vm, flags);
            break;
        case op_call_native_reg:
            handlers::handle_call_native_reg(vm, flags);
            break;
        case op_xchg_mem64:
            handlers::handle_xchg_mem64(vm, flags);
            break;
        case op_push:
            handlers::handle_push(vm, flags);
            break;
        case op_pop:
            handlers::handle_pop(vm, flags);
            break;
        case op_call:
            handlers::handle_call(vm, flags);
            break;
        case op_rdtsc:
            handlers::handle_rdtsc(vm, flags);
			break;
        case op_cpuid:
            handlers::handle_cpuid(vm, flags);
            break;
        case op_stosb:
            handlers::handle_stosb(vm, flags);
            break;
        case op_rep_stosb:
            handlers::handle_rep_stosb(vm, flags);
            break;
        case op_loop:
            handlers::handle_loop(vm, flags);
            break;
        case op_loope:
            handlers::handle_loope(vm, flags);
            break;
        case op_loopne:
            handlers::handle_loopne(vm, flags);
            break;
        case op_ret:
            handlers::handle_ret(vm, flags);
            break;
        case op_halt:
            handlers::handle_halt(vm, flags);
            break;
        default:
            handlers::handle_invalid(vm, flags);
            break;
        }

        generator<10>::generate_junk();
    }

    if (instruction_count >= MAX_INSTRUCTIONS) {
        vm_trace_helper<trace_enabled>("*** EXECUTION STOPPED: instruction limit reached (%d) ***\n", MAX_INSTRUCTIONS);
    }
}

extern "C" void vm_initialize_state(vm_state& vm, uint8_t* code_buffer, uint32_t code_capacity, uint8_t* memory_buffer, uint32_t memory_capacity) {
    vm_initialize_state_internal(vm, code_buffer, code_capacity, memory_buffer, memory_capacity);
}

extern "C" void vm_reset_state(vm_state& vm) {
    vm_reset_state_internal(vm);
}

extern "C" __declspec(noinline) void run_advanced_vm(vm_state& vm) {
    vm_flags flags{};
#ifdef vm_interpreter_trace
    run_vm_logic<true>(vm, flags);
#else
    run_vm_logic<false>(vm, flags);
#endif
}

extern "C" __declspec(noinline) __declspec(safebuffers) void run_vm_from_blob(
    const uint8_t* bytecode,
    uint32_t size,
    uint8_t* vm_memory,
    uint64_t arg_rcx,
    uint64_t arg_rdx,
    uint64_t arg_r8,
    uint64_t arg_r9) {
    if (!bytecode || size == 0 || size > vm_max_code_size || !vm_memory) {
        return;
    }

    auto* vm = reinterpret_cast<vm_state*>(vm_memory);
    uint8_t* memory_base = vm_memory + sizeof(vm_state);

    vm_initialize_state_internal(*vm, const_cast<uint8_t*>(bytecode), size, memory_base, vm_memory_size);
    if (!configure_chunked_code(*vm, bytecode, size)) {
        vm->code = const_cast<uint8_t*>(bytecode);
        vm->code_capacity = size;
        vm->code_size = size;
        vm->code_is_chunked = false;
        vm->chunked_code_blob = nullptr;
        vm->chunked_code_blob_size = 0;
        vm->chunk_count = 0;
    }
    vm->image_base = get_image_base_runtime();
    vm->image_size = get_image_size_runtime(vm->image_base);
    if (vm_image_base_register < vm_register_count) {
        vm->regs[vm_image_base_register] = vm->image_base;
    }
    vm->regs[2] = arg_rcx;
    vm->regs[3] = arg_rdx;
    vm->regs[8] = arg_r8;
    vm->regs[9] = arg_r9;

    vm_flags flags {false}; // initialize all flags to false

    generator<150>::generate_junk();
    run_vm_logic<false>(*vm, flags);
}

#pragma code_seg(pop)
