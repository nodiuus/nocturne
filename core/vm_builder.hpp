#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include "common.hpp"

class vm_builder {
private:
    vm_state& vm;
    std::map<uint64_t, uint32_t> jump_targets;
    std::vector<std::pair<uint32_t, uint64_t>> pending_jumps;

public:
    vm_builder(vm_state& vm_state);

    bool emit_u8(uint8_t value);
    bool emit_u32(uint32_t value);
    bool emit_u64(uint64_t value);
    bool emit_i32(int32_t value);

    void mark_jump_target(uint64_t x86_address);
    bool emit_jump(uint8_t jump_type, uint64_t x86_target);
    void resolve_jumps();

    void emit_mov_imm(uint8_t dst, uint64_t imm);
    void emit_mov_reg(uint8_t dst, uint8_t src);
    void emit_add(uint8_t dst, uint8_t a, uint8_t b);
    void emit_sub(uint8_t dst, uint8_t a, uint8_t b);
    void emit_and(uint8_t dst, uint8_t a, uint8_t b);
    void emit_or(uint8_t dst, uint8_t a, uint8_t b);
    void emit_xor(uint8_t dst, uint8_t a, uint8_t b);
    void emit_not(uint8_t dst, uint8_t src);
    void emit_shl(uint8_t dst, uint8_t a, uint8_t b);
    void emit_shr(uint8_t dst, uint8_t a, uint8_t b);
    void emit_sar(uint8_t dst, uint8_t a, uint8_t b);
    void emit_mul(uint8_t dst, uint8_t a, uint8_t b);
    void emit_div(uint8_t dst, uint8_t a, uint8_t b);
    void emit_cmp(uint8_t a, uint8_t b);
    void emit_push(uint8_t src);
    void emit_pop(uint8_t dst);
    void emit_call(uint64_t x86_target);
    void emit_call_native(uint64_t target_va);
    void emit_call_native_indirect(uint64_t target_slot_va);
    void emit_call_native_mem(uint8_t base, int32_t offset);
    void emit_call_native_reg(uint8_t target);
    void emit_nop();
    void emit_ret();
    void emit_halt();

    void emit_load_mem(uint8_t dst, uint8_t base, int32_t offset);
    void emit_store_mem(uint8_t base, int32_t offset, uint8_t src);
    void emit_store_mem8(uint8_t base, int32_t offset, uint8_t src);
    void emit_store_mem_zero128(uint8_t base, int32_t offset);
    void emit_cmpxchg_mem64(uint8_t base, int32_t offset, uint8_t src);
    void emit_xchg_mem64(uint8_t base, int32_t offset, uint8_t reg);

    uint32_t get_current_position();
};

