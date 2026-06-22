#pragma once

#include <cstdint>
#include <array>
#include <Zydis/Zydis.h>
#include "common.hpp"
#include "register_mapper.hpp"
#include "vm_builder.hpp"

class x86_translator {
private:
    register_mapper reg_mapper;
    vm_builder builder;
    ZydisDecoder decoder;
    uint64_t base_address;
    uint64_t image_base;
    uint32_t image_size;
    std::array<bool, 16> xmm_known_zero{};

public:
    x86_translator(vm_state& vm, uint64_t base_addr = 0x400000, uint64_t image_base_addr = 0, uint32_t image_size_bytes = 0);
    bool translate_function(const uint8_t* x86_code, size_t code_size);

private:
    void find_jump_targets(const uint8_t* x86_code, size_t code_size);
    bool translate_instruction(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    uint64_t alloc_internal_label();
    bool translate_mov(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_add(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_and(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_or(const ZydisDecodedOperand* operands);
    bool translate_xor(const ZydisDecodedOperand* operands);
    bool translate_not(const ZydisDecodedOperand* operands);
    bool translate_shift(const ZydisDecodedOperand* operands, uint8_t op);
    bool translate_test(const ZydisDecodedOperand* operands);
    bool translate_sub(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_imul(const ZydisDecodedOperand* operands);
    bool translate_mul(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_div(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_cmp(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_cmpxchg(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_xchg(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_push(const ZydisDecodedOperand* operands);
    bool translate_pop(const ZydisDecodedOperand* operands);
    bool translate_inc(const ZydisDecodedOperand* operands);
    bool translate_dec(const ZydisDecodedOperand* operands);
    bool translate_cdq();
    bool translate_nop();
    bool translate_lea(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_call(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_jump(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr,
        uint8_t vm_jump_type);
    bool translate_xorps(const ZydisDecodedOperand* operands);
    bool translate_movdqa(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_movzx(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_movsx(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operands, uint64_t current_addr);
    bool translate_movsb();
    bool translate_cmovnz(const ZydisDecodedOperand* operands);
    bool translate_cmovb(const ZydisDecodedOperand* operands);
    bool translate_setz(const ZydisDecodedOperand* operands);
    bool translate_setnz(const ZydisDecodedOperand* operands);
    bool resolve_memory_address(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operand, uint64_t current_addr,
        uint8_t& base, int32_t& offset);
    bool emit_load_from_memory(uint8_t dst, const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operand, uint64_t current_addr);
    bool emit_store_to_memory(const ZydisDecodedInstruction* instruction,
        const ZydisDecodedOperand* operand, uint64_t current_addr,
        uint8_t src, uint16_t width_bits);
    bool get_image_relative_or_absolute(uint64_t target, uint64_t& encoded) const;

    uint64_t internal_label_base = 0xFFFF000000000000ull;
    uint32_t internal_label_counter = 0;
    uint64_t function_end_address = 0;
};
