#include "vm_builder.hpp"
#include "byte_io.hpp"
#include <iostream>

vm_builder::vm_builder(vm_state& vm_state) : vm(vm_state) {
    vm.ip = 0;
    vm.code_size = 0;
}

bool vm_builder::emit_u8(uint8_t value) {
    if (!vm.code || vm.ip >= vm.code_capacity) {
        std::cerr << "vm_builder: bytecode buffer overflow\n";
        return false;
    }
    vm.code[vm.ip++] = value;
    if (vm.ip > vm.code_size) {
        vm.code_size = vm.ip;
    }
    return true;
}

bool vm_builder::emit_u32(uint32_t value) {
    return emit_u8(static_cast<uint8_t>(value & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 8) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 16) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 24) & 0xFF));
}

bool vm_builder::emit_u64(uint64_t value) {
    return emit_u8(static_cast<uint8_t>(value & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 8) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 16) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 24) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 32) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 40) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 48) & 0xFF))
        && emit_u8(static_cast<uint8_t>((value >> 56) & 0xFF));
}

bool vm_builder::emit_i32(int32_t value) {
    return emit_u32(static_cast<uint32_t>(value));
}

void vm_builder::mark_jump_target(uint64_t x86_address) {
    if (jump_targets.find(x86_address) == jump_targets.end()) {
        jump_targets[x86_address] = vm.ip;
        printf("Marking jump target: x86=0x%llX -> VM=%u\n", x86_address, vm.ip);
    }
}

bool vm_builder::emit_jump(uint8_t jump_type, uint64_t x86_target) {
    if (!emit_u8(jump_type)) return false;
    pending_jumps.push_back({ vm.ip, x86_target });
    return emit_i32(0);
}

void vm_builder::resolve_jumps() {
    for (auto& pending : pending_jumps) {
        uint32_t vm_pos = pending.first;
        uint64_t x86_target = pending.second;

        auto it = jump_targets.find(x86_target);
        if (it != jump_targets.end()) {
            uint32_t jump_from = vm_pos + 4;
            int32_t offset = static_cast<int32_t>(it->second) - static_cast<int32_t>(jump_from);
            if (vm.code && (vm_pos + 4) <= vm.code_capacity) {
                byte_io::write_i32_le(vm.code + vm_pos, offset);
            }
            printf("Resolved jump: VM pos %u -> target %u (from %u, offset %+d)\n",
                vm_pos, it->second, jump_from, offset);
        }
        else {
            printf("WARNING: Unresolved jump target: 0x%llX\n", x86_target);
        }
    }
}

void vm_builder::emit_mov_imm(uint8_t dst, uint64_t imm) { emit_u8(op_mov_imm); emit_u8(dst); emit_u64(imm); }
void vm_builder::emit_mov_reg(uint8_t dst, uint8_t src) { emit_u8(op_mov_reg); emit_u8(dst); emit_u8(src); }
void vm_builder::emit_add(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_add); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_and(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_and); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_or(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_or); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_xor(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_xor); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_not(uint8_t dst, uint8_t src) { emit_u8(op_not); emit_u8(dst); emit_u8(src); }
void vm_builder::emit_shl(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_shl); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_shr(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_shr); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_sar(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_sar); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_mul(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_mul); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_div(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_div); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_sub(uint8_t dst, uint8_t a, uint8_t b) { emit_u8(op_sub); emit_u8(dst); emit_u8(a); emit_u8(b); }
void vm_builder::emit_cmp(uint8_t a, uint8_t b) { emit_u8(op_cmp); emit_u8(a); emit_u8(b); }
void vm_builder::emit_push(uint8_t src) { emit_u8(op_push); emit_u8(src); }
void vm_builder::emit_pop(uint8_t dst) { emit_u8(op_pop); emit_u8(dst); }
void vm_builder::emit_call(uint64_t x86_target) { emit_jump(op_call, x86_target); }
void vm_builder::emit_call_native(uint64_t target_va) { emit_u8(op_call_native); emit_u64(target_va); }
void vm_builder::emit_call_native_indirect(uint64_t target_slot_va) { emit_u8(op_call_native_indirect); emit_u64(target_slot_va); }
void vm_builder::emit_call_native_mem(uint8_t base, int32_t offset) { emit_u8(op_call_native_mem); emit_u8(base); emit_i32(offset); }
void vm_builder::emit_call_native_reg(uint8_t target) { emit_u8(op_call_native_reg); emit_u8(target); }
void vm_builder::emit_nop() { emit_u8(op_nop); }
void vm_builder::emit_ret() { emit_u8(op_ret); }
void vm_builder::emit_halt() { emit_u8(op_halt); }

void vm_builder::emit_load_mem(uint8_t dst, uint8_t base, int32_t offset) {
    emit_u8(op_load_mem);
    emit_u8(dst);
    emit_u8(base);
    emit_i32(offset);
}

void vm_builder::emit_store_mem(uint8_t base, int32_t offset, uint8_t src) {
    emit_u8(op_store_mem);
    emit_u8(base);
    emit_i32(offset);
    emit_u8(src);
}

void vm_builder::emit_store_mem8(uint8_t base, int32_t offset, uint8_t src) {
    emit_u8(op_store_mem8);
    emit_u8(base);
    emit_i32(offset);
    emit_u8(src);
}

void vm_builder::emit_store_mem_zero128(uint8_t base, int32_t offset) {
    emit_u8(op_store_mem_zero128);
    emit_u8(base);
    emit_i32(offset);
}

void vm_builder::emit_cmpxchg_mem64(uint8_t base, int32_t offset, uint8_t src) {
    emit_u8(op_cmpxchg_mem64);
    emit_u8(base);
    emit_i32(offset);
    emit_u8(src);
}

void vm_builder::emit_xchg_mem64(uint8_t base, int32_t offset, uint8_t reg) {
    emit_u8(op_xchg_mem64);
    emit_u8(base);
    emit_i32(offset);
    emit_u8(reg);
}

uint32_t vm_builder::get_current_position() { return vm.ip; }

