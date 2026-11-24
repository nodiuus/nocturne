#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <random>

constexpr size_t vm_register_count = 32;
constexpr uint8_t vm_scratch_register = 31;
constexpr uint8_t vm_image_base_register = 29;
constexpr uint32_t vm_memory_size = 64 * 1024;
constexpr size_t vm_max_code_size = 1024 * 1024;
constexpr uint32_t vm_chunked_code_magic = 0x4B484356; // "VCHK"
constexpr uint32_t vm_chunked_code_version = 1;
constexpr uint32_t vm_chunked_code_header_size = 16;
constexpr uint32_t vm_chunked_code_descriptor_size = 12;

struct vm_state {
    uint64_t regs[vm_register_count];
    uint8_t* memory;
    uint32_t memory_size;
    uint8_t* code;
    uint32_t code_capacity;
    uint32_t code_size;
    uint32_t ip;
    bool     halted;
    uint64_t image_base;
    uint32_t image_size;
    bool     code_is_chunked;
    const uint8_t* chunked_code_blob;
    uint32_t chunked_code_blob_size;
    uint32_t chunk_count;
};

struct vm_flags {
    bool zf  = false; // zero flag
    bool pf  = false; // parity flag
    bool af  = false; // auxiliary flag
    bool of  = false; // overflow flag
    bool sf  = false; // sign flag
    bool df  = false; // direction flag
    bool cf  = false; // carry flag
    bool tf  = false; // trap flag
    bool ief = false; // interrupt-enable flag
};

enum opcode_t : uint8_t {
   op_nop = 0x00,
   op_mov_imm = 0x01,
   op_add = 0x02,
   op_sub = 0x03,
   op_mul = 0x04,
   op_div = 0x05,
   op_load_mem = 0x06,
   op_store_mem = 0x07,
   op_mov_reg = 0x08,
   op_and = 0x09,
   op_or = 0x0A,
   op_xor = 0x0B,
   op_not = 0x0C,
   op_shl = 0x0D,
   op_shr = 0x0E,
   op_sar = 0x0F,
   op_call_native = 0x18,
   op_store_mem8 = 0x19,
   op_store_mem_zero128 = 0x1A,
   op_call_native_indirect = 0x1B,
   op_call_native_mem = 0x1C,
   op_cmpxchg_mem64 = 0x1D,
   op_call_native_reg = 0x1E,
   op_xchg_mem64 = 0x1F,
   op_jmp = 0x10,
   op_jz = 0x11,
   op_cmp = 0x12,
   op_jnz = 0x13,
   op_jl = 0x14,
   op_jg = 0x15,
   op_jle = 0x16,
   op_jge = 0x17,
   op_print = 0x20,
   op_push = 0x30,
   op_pop = 0x31,
   op_loop = 0x32,
   op_loope = 0x33,
   op_loopne = 0x34,
   op_call = 0x40,
   op_ret = 0x41,
   op_cpuid = 0x42,
   op_rdtsc = 0x43,
   op_stosb = 0x44,
   op_rep_stosb = 0x45,
   op_x86_div = 0x46,
   op_jb = 0x47,
   op_jbe = 0x48,
   op_jae = 0x49,
   op_ja = 0x4a,
   op_halt = 0xFE,
   opcode_size,
};

enum div_source_t : uint8_t {
    div_register,
    div_high_byte,
    div_memory
};
