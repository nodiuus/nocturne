#pragma once

#include "handler.hpp"
#include "vm_interpreter.hpp"
#include "vm_utils.hpp"

#include <intrin.h>

#pragma section(".vmb$m", read, execute)
#pragma code_seg(push, ".vmb$m")

using namespace vm_utils;
using byte_io::read_u64_le;
using byte_io::write_u64_le;

#define UNUSED [[maybe_unused]]

namespace {
    vm_inline bool fetch_valid_reg(vm_state& vm, uint8_t& reg) {
        if (!fetch_u8_or_halt(vm, reg)) {
            return false;
        }

        if (reg >= vm_register_count) {
            return halt_vm(vm);
        }

        return true;
    }

    vm_inline bool fetch_dst_imm64(vm_state& vm, uint8_t& dst, uint64_t& imm) {
        if (!require_code_bytes(vm, 9)) {
            return false;
        }

        if (!fetch_valid_reg(vm, dst)) {
            return false;
        }

        return fetch_u64_or_halt(vm, imm);
    }

    vm_inline bool fetch_reg1(vm_state& vm, uint8_t& reg) {
        if (!require_code_bytes(vm, 1)) {
            return false;
        }

        return fetch_valid_reg(vm, reg);
    }

    vm_inline bool fetch_reg2(vm_state& vm, uint8_t& a, uint8_t& b) {
        if (!require_code_bytes(vm, 2)) {
            return false;
        }

        return fetch_valid_reg(vm, a) &&
               fetch_valid_reg(vm, b);
    }

    vm_inline bool fetch_reg3(vm_state& vm, uint8_t& dst, uint8_t& a, uint8_t& b) {
        if (!require_code_bytes(vm, 3)) {
            return false;
        }

        return fetch_valid_reg(vm, dst) &&
               fetch_valid_reg(vm, a) &&
               fetch_valid_reg(vm, b);
    }

    vm_inline bool fetch_reg_i32(vm_state& vm, uint8_t& reg, int32_t& offset) {
        if (!require_code_bytes(vm, 5)) {
            return false;
        }

        return fetch_valid_reg(vm, reg) &&
               fetch_i32_or_halt(vm, offset);
    }

    vm_inline bool fetch_reg_i32_reg(vm_state& vm, uint8_t& base, int32_t& offset, uint8_t& reg) {
        if (!require_code_bytes(vm, 6)) {
            return false;
        }

        return fetch_valid_reg(vm, base) &&
               fetch_i32_or_halt(vm, offset) &&
               fetch_valid_reg(vm, reg);
    }

    vm_inline bool fetch_reg_reg_i32(vm_state& vm, uint8_t& dst, uint8_t& base, int32_t& offset) {
        if (!require_code_bytes(vm, 6)) {
            return false;
        }

        return fetch_valid_reg(vm, dst) &&
               fetch_valid_reg(vm, base) &&
               fetch_i32_or_halt(vm, offset);
    }

    using binary_op_t = uint64_t(*)(uint64_t, uint64_t);

    vm_inline bool apply_binary_reg_op(vm_state& vm, binary_op_t op) {
        uint8_t dst = 0;
        uint8_t a = 0;
        uint8_t b = 0;
        if (!fetch_reg3(vm, dst, a, b)) {
            return false;
        }

        vm.regs[dst] = op(vm.regs[a], vm.regs[b]);
        return true;
    }

    vm_inline uint64_t add_u64(uint64_t a, uint64_t b) { return a + b; }
    vm_inline uint64_t sub_u64(uint64_t a, uint64_t b) { return a - b; }
    vm_inline uint64_t mul_u64(uint64_t a, uint64_t b) { return a * b; }
    vm_inline uint64_t and_u64(uint64_t a, uint64_t b) { return a & b; }
    vm_inline uint64_t or_u64(uint64_t a, uint64_t b) { return a | b; }
    vm_inline uint64_t xor_u64(uint64_t a, uint64_t b) { return a ^ b; }

    vm_inline void update_cmp_flags(vm_flags& flags, uint64_t a, uint64_t b) {
        uint64_t result = a - b;
        flags.zf = result == 0;
        flags.sf = (result >> 63) != 0;
        flags.cf = a < b;
        flags.of = (((a ^ b) & (a ^ result)) >> 63) != 0;
    }

    vm_inline bool resolve_address(vm_state& vm, uint8_t base, int32_t offset, uint64_t& address) {
        int64_t addr = static_cast<int64_t>(vm.regs[base]) + offset;
        if (addr < 0) {
            return halt_vm(vm);
        }

        address = static_cast<uint64_t>(addr);
        return true;
    }

    vm_inline bool read_memory_u64(vm_state& vm, uint64_t address, uint64_t& value) {
        if (uint8_t* vm_ptr = vm_memory_ptr(vm, address, 8)) {
            value = read_u64_le(vm_ptr);
            return true;
        }

        value = read_u64_le(reinterpret_cast<const uint8_t*>(address));
        return true;
    }

    vm_inline bool write_memory_u64(vm_state& vm, uint64_t address, uint64_t value) {
        if (uint8_t* vm_ptr = vm_memory_ptr(vm, address, 8)) {
            write_u64_le(vm_ptr, value);
            return true;
        }

        write_u64_le(reinterpret_cast<uint8_t*>(address), value);
        return true;
    }

    vm_inline bool write_memory_u8(vm_state& vm, uint64_t address, uint8_t value) {
        if (uint8_t* vm_ptr = vm_memory_ptr(vm, address, 1)) {
            *vm_ptr = value;
            return true;
        }

        *reinterpret_cast<uint8_t*>(address) = value;
        return true;
    }

    vm_inline bool zero_memory_128(vm_state& vm, uint64_t address) {
        uint8_t* ptr = vm_memory_ptr(vm, address, 16);
        if (!ptr) {
            ptr = reinterpret_cast<uint8_t*>(address);
        }

        for (uint32_t i = 0; i < 16; ++i) {
            ptr[i] = 0;
        }
        return true;
    }

    vm_inline uint64_t resolve_native_target(const vm_state& vm, uint64_t target) {
        if (vm.image_base != 0 && vm.image_size != 0 && target < vm.image_size) {
            return vm.image_base + target;
        }

        return target;
    }

    vm_inline bool fetch_jump_target(vm_state& vm, uint32_t& target) {
        if (!require_code_bytes(vm, 4)) {
            return false;
        }

        int32_t offset = 0;
        if (!fetch_i32_or_halt(vm, offset)) {
            return false;
        }

        target = static_cast<uint32_t>(static_cast<int64_t>(vm.ip) + offset);
        if (target > vm.code_size) {
            return halt_vm(vm);
        }

        return true;
    }
}

vm_inline bool handlers::handle_nop(UNUSED vm_state& vm, UNUSED vm_flags& flags) {
    return true;
}

vm_inline bool handlers::handle_mov(vm_state& vm, UNUSED vm_flags& flags) {
    return handle_mov_imm(vm, flags);
}

vm_inline bool handlers::handle_mov_imm(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint64_t imm = 0;
    if (!fetch_dst_imm64(vm, dst, imm)) {
        return false;
    }

    vm.regs[dst] = imm;
    return true;
}

vm_inline bool handlers::handle_mov_reg(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint8_t src = 0;
    if (!fetch_reg2(vm, dst, src)) {
        return false;
    }

    vm.regs[dst] = vm.regs[src];
    return true;
}

vm_inline bool handlers::handle_add(vm_state& vm, UNUSED vm_flags& flags) {
    return apply_binary_reg_op(vm, add_u64);
}

vm_inline bool handlers::handle_sub(vm_state& vm, UNUSED vm_flags& flags) {
    return apply_binary_reg_op(vm, sub_u64);
}

vm_inline bool handlers::handle_mul(vm_state& vm, UNUSED vm_flags& flags) {
    return apply_binary_reg_op(vm, mul_u64);
}

vm_inline bool handlers::handle_div(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint8_t a = 0;
    uint8_t b = 0;
    if (!fetch_reg3(vm, dst, a, b)) {
        return false;
    }

    if (vm.regs[b] == 0) {
        return halt_vm(vm);
    }

    vm.regs[dst] = vm.regs[a] / vm.regs[b];
    return true;
}

vm_inline bool handlers::handle_x86_div(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t width = 0;
    uint8_t source = 0;
    uint8_t reg = 0;
    if (!fetch_u8_or_halt(vm, width) || !fetch_u8_or_halt(vm, source) || !fetch_valid_reg(vm, reg)) {
        return false;
    }
    if ((width != 8 && width != 16 && width != 32 && width != 64) || source > div_memory) {
        return halt_vm(vm);
    }

    uint64_t divisor = vm.regs[reg];
    if (source == div_high_byte) {
        if (width != 8 || reg > 3) {
            return halt_vm(vm);
        }
        divisor >>= 8;
    } else if (source == div_memory) {
        int32_t offset = 0;
        uint64_t address = 0;
        if (!fetch_i32_or_halt(vm, offset) || !resolve_address(vm, reg, offset, address)) {
            return false;
        }
        const uint32_t size = width / 8;
        const volatile uint8_t* bytes = vm_memory_ptr(vm, address, size);
        if (!bytes) {
            bytes = reinterpret_cast<const volatile uint8_t*>(address);
        }
        divisor = 0;
        for (uint32_t i = 0; i < size; ++i) {
            divisor |= static_cast<uint64_t>(bytes[i]) << (i * 8);
        }
    }

    const uint64_t mask = width == 64 ? UINT64_MAX : (uint64_t(1) << width) - 1;
    divisor &= mask;
    const uint64_t low = vm.regs[0] & mask;
    const uint64_t high = (width == 8 ? vm.regs[0] >> 8 : vm.regs[3]) & mask;

    // high >= divisor means the quotient cannot fit in the destination width.
    // Keep the VM's existing error policy: halt without changing the results.
    if (divisor == 0 || high >= divisor) {
        return halt_vm(vm);
    }

    uint64_t quotient = 0;
    uint64_t remainder = 0;
    if (width == 64) {
        quotient = _udiv128(high, low, divisor, &remainder);
    } else {
        const uint64_t dividend = (high << width) | low;
        quotient = dividend / divisor;
        remainder = dividend % divisor;
    }

    if (width == 8) {
        vm.regs[0] = (vm.regs[0] & ~uint64_t(0xFFFF)) | quotient | (remainder << 8);
    } else if (width == 16) {
        vm.regs[0] = (vm.regs[0] & ~mask) | quotient;
        vm.regs[3] = (vm.regs[3] & ~mask) | remainder;
    } else {
        vm.regs[0] = quotient;
        vm.regs[3] = remainder;
    }
    return true;
}

vm_inline bool handlers::handle_and(vm_state& vm, UNUSED vm_flags& flags) {
    return apply_binary_reg_op(vm, and_u64);
}

vm_inline bool handlers::handle_or(vm_state& vm, UNUSED vm_flags& flags) {
    return apply_binary_reg_op(vm, or_u64);
}

vm_inline bool handlers::handle_xor(vm_state& vm, UNUSED vm_flags& flags) {
    return apply_binary_reg_op(vm, xor_u64);
}

vm_inline bool handlers::handle_not(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint8_t src = 0;
    if (!fetch_reg2(vm, dst, src)) {
        return false;
    }

    vm.regs[dst] = ~vm.regs[src];
    return true;
}

vm_inline bool handlers::handle_shr(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint8_t a = 0;
    uint8_t b = 0;
    if (!fetch_reg3(vm, dst, a, b)) {
        return false;
    }

    vm.regs[dst] = vm.regs[a] >> (vm.regs[b] & 0x3F);
    return true;
}

vm_inline bool handlers::handle_shl(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint8_t a = 0;
    uint8_t b = 0;
    if (!fetch_reg3(vm, dst, a, b)) {
        return false;
    }

    vm.regs[dst] = vm.regs[a] << (vm.regs[b] & 0x3F);
    return true;
}

vm_inline bool handlers::handle_sar(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint8_t a = 0;
    uint8_t b = 0;
    if (!fetch_reg3(vm, dst, a, b)) {
        return false;
    }

    int64_t value = static_cast<int64_t>(vm.regs[a]);
    vm.regs[dst] = static_cast<uint64_t>(value >> (vm.regs[b] & 0x3F));
    return true;
}

vm_inline bool handlers::handle_cmp(vm_state& vm, vm_flags& flags) {
    uint8_t a = 0;
    uint8_t b = 0;
    if (!fetch_reg2(vm, a, b)) {
        return false;
    }

    update_cmp_flags(flags, vm.regs[a], vm.regs[b]);
    return true;
}

vm_inline bool handlers::handle_jmp(vm_state& vm, UNUSED vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    vm.ip = target;
    return true;
}

vm_inline bool handlers::handle_jz(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (flags.zf) {
        vm.ip = target;
    }
    return true;
}

vm_inline bool handlers::handle_jnz(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (!flags.zf) {
        vm.ip = target;
    }
    return true;
}

vm_inline bool handlers::handle_jl(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (flags.sf != flags.of) {
        vm.ip = target;
    }
    return true;
}

vm_inline bool handlers::handle_jg(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (!flags.zf && flags.sf == flags.of) {
        vm.ip = target;
    }
    return true;
}

vm_inline bool handlers::handle_jle(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (flags.zf || flags.sf != flags.of) {
        vm.ip = target;
    }
    return true;
}

vm_inline bool handlers::handle_jge(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (flags.sf == flags.of) {
        vm.ip = target;
    }
    return true;
}

vm_inline bool handlers::handle_jb(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;

    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (flags.cf) {
        vm.ip = target;
    }

    return true;
}

vm_inline bool handlers::handle_jbe(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;

    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (flags.cf || flags.zf) {
        vm.ip = target;
    }

    return true;
}

vm_inline bool handlers::handle_jae(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;

    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (!flags.cf) {
        vm.ip = target;
    }

    return true;
}

vm_inline bool handlers::handle_ja(vm_state& vm, vm_flags& flags) {
    uint32_t target = 0;

    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (!flags.cf && !flags.zf) {
        vm.ip = target;
    }

    return true;
}

vm_inline bool handlers::handle_push(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t src = 0;
    if (!fetch_reg1(vm, src)) {
        return false;
    }

    if (VM_REG_INDEX_RSP >= vm_register_count) {
        return halt_vm(vm);
    }

    uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
    if (!ensure_stack_space(vm, sp, 8)) {
        return halt_vm(vm);
    }

    sp -= 8;
    write_u64_le(vm_memory_ptr(vm, sp, 8), vm.regs[src]);
    return true;
}

vm_inline bool handlers::handle_pop(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    if (!fetch_reg1(vm, dst)) {
        return false;
    }

    if (VM_REG_INDEX_RSP >= vm_register_count) {
        return halt_vm(vm);
    }

    uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
    if (!ensure_stack_read(vm, sp, 8)) {
        return halt_vm(vm);
    }

    vm.regs[dst] = read_u64_le(vm_memory_ptr(vm, sp, 8));
    sp += 8;
    return true;
}

vm_inline bool handlers::handle_call(vm_state& vm, UNUSED vm_flags& flags) {
    uint32_t target = 0;
    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (VM_REG_INDEX_RSP >= vm_register_count) {
        return halt_vm(vm);
    }

    uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
    if (!ensure_stack_space(vm, sp, 8)) {
        return halt_vm(vm);
    }

    sp -= 8;
    write_u64_le(vm_memory_ptr(vm, sp, 8), static_cast<uint64_t>(vm.ip));
    vm.ip = target;
    return true;
}

vm_inline bool handlers::handle_loop(vm_state& vm, vm_flags& flags) {
    // TODO: at some point just combine LOOP/LOOPNE/LOOPE functionality into one handler
    
    uint8_t width = 0;

    if (!fetch_u8_or_halt(vm, width)) {
        return false;
    }

    if (width != 32 && width != 64) {
        return halt_vm(vm);
    }

    uint32_t target = 0;

    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (width == 32) {
        vm.regs[2] = static_cast<uint32_t>(vm.regs[2] - 1);
    } else {
        --vm.regs[2];
    }

    if (vm.regs[2] != 0) {
        vm.ip = target;
    }

    return true;
}

vm_inline bool handlers::handle_loope(vm_state& vm, vm_flags& flags) {
    // TODO: at some point just combine LOOP/LOOPNE/LOOPE functionality into one handler

    uint8_t width = 0;

    if (!fetch_u8_or_halt(vm, width)) {
        return false;
    }

    if (width != 32 && width != 64) {
        return halt_vm(vm);
    }

    uint32_t target = 0;

    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (width == 32) {
        vm.regs[2] = static_cast<uint32_t>(vm.regs[2] - 1);
    }
    else {
        --vm.regs[2];
    }

    if (vm.regs[2] != 0 && flags.zf) {
        vm.ip = target;
    }

    return true;
}

vm_inline bool handlers::handle_loopne(vm_state& vm, vm_flags& flags) {
    // TODO: at some point just combine LOOP/LOOPNE/LOOPE functionality into one handler

    uint8_t width = 0;

    if (!fetch_u8_or_halt(vm, width)) {
        return false;
    }

    if (width != 32 && width != 64) {
        return halt_vm(vm);
    }

    uint32_t target = 0;

    if (!fetch_jump_target(vm, target)) {
        return false;
    }

    if (width == 32) {
        vm.regs[2] = static_cast<uint32_t>(vm.regs[2] - 1);
    }
    else {
        --vm.regs[2];
    }

    if (vm.regs[2] != 0 && !flags.zf) {
        vm.ip = target;
    }

    return true;
}

vm_inline bool handlers::handle_ret(vm_state& vm, UNUSED vm_flags& flags) {
    if (VM_REG_INDEX_RSP >= vm_register_count) {
        return halt_vm(vm);
    }

    uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
    if (!ensure_stack_read(vm, sp, 8)) {
        return halt_vm(vm);
    }

    uint64_t return_addr = read_u64_le(vm_memory_ptr(vm, sp, 8));
    sp += 8;
    if (return_addr > vm.code_size) {
        return halt_vm(vm);
    }

    vm.ip = static_cast<uint32_t>(return_addr);
    return true;
}

vm_inline bool handlers::handle_load_mem(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t dst = 0;
    uint8_t base = 0;
    int32_t offset = 0;
    if (!fetch_reg_reg_i32(vm, dst, base, offset)) {
        return false;
    }

    uint64_t address = 0;
    if (!resolve_address(vm, base, offset, address)) {
        return false;
    }

    return read_memory_u64(vm, address, vm.regs[dst]);
}

vm_inline bool handlers::handle_store_mem(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t base = 0;
    uint8_t src = 0;
    int32_t offset = 0;
    if (!fetch_reg_i32_reg(vm, base, offset, src)) {
        return false;
    }

    uint64_t address = 0;
    if (!resolve_address(vm, base, offset, address)) {
        return false;
    }

    return write_memory_u64(vm, address, vm.regs[src]);
}

vm_inline bool handlers::handle_store_mem8(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t base = 0;
    uint8_t src = 0;
    int32_t offset = 0;
    if (!fetch_reg_i32_reg(vm, base, offset, src)) {
        return false;
    }

    uint64_t address = 0;
    if (!resolve_address(vm, base, offset, address)) {
        return false;
    }

    return write_memory_u8(vm, address, static_cast<uint8_t>(vm.regs[src] & 0xFF));
}

vm_inline bool handlers::handle_store_mem_zero128(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t base = 0;
    int32_t offset = 0;
    if (!fetch_reg_i32(vm, base, offset)) {
        return false;
    }

    uint64_t address = 0;
    if (!resolve_address(vm, base, offset, address)) {
        return false;
    }

    return zero_memory_128(vm, address);
}

vm_inline bool handlers::handle_call_native(vm_state& vm, UNUSED vm_flags& flags) {
    if (!require_code_bytes(vm, 8)) {
        return false;
    }

    uint64_t target = 0;
    if (!fetch_u64_or_halt(vm, target)) {
        return false;
    }

    vm.regs[0] = call_native_bridge(resolve_native_target(vm, target), vm);
    return true;
}

vm_inline bool handlers::handle_call_native_indirect(vm_state& vm, UNUSED vm_flags& flags) {
    if (!require_code_bytes(vm, 8)) {
        return false;
    }

    uint64_t target_slot = 0;
    if (!fetch_u64_or_halt(vm, target_slot)) {
        return false;
    }

    uint64_t actual_slot = resolve_native_target(vm, target_slot);
    uint64_t target = read_u64_le(reinterpret_cast<const uint8_t*>(actual_slot));
    vm.regs[0] = call_native_bridge(target, vm);
    return true;
}

vm_inline bool handlers::handle_call_native_mem(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t base = 0;
    int32_t offset = 0;
    if (!fetch_reg_i32(vm, base, offset)) {
        return false;
    }

    uint64_t slot_addr = 0;
    if (!resolve_address(vm, base, offset, slot_addr)) {
        return false;
    }

    uint64_t target = 0;
    if (!read_memory_u64(vm, slot_addr, target)) {
        return false;
    }

    vm.regs[0] = call_native_bridge(target, vm);
    return true;
}

vm_inline bool handlers::handle_call_native_reg(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t target_reg = 0;
    if (!fetch_reg1(vm, target_reg)) {
        return false;
    }

    vm.regs[0] = call_native_bridge(resolve_native_target(vm, vm.regs[target_reg]), vm);
    return true;
}

vm_inline bool handlers::handle_cmpxchg_mem64(vm_state& vm, vm_flags& flags) {
    uint8_t base = 0;
    uint8_t src = 0;
    int32_t offset = 0;
    if (!fetch_reg_i32_reg(vm, base, offset, src)) {
        return false;
    }

    uint64_t address = 0;
    if (!resolve_address(vm, base, offset, address)) {
        return false;
    }

    uint64_t expected = vm.regs[0];
    uint64_t desired = vm.regs[src];
    uint64_t old = 0;

    if (uint8_t* vm_ptr = vm_memory_ptr(vm, address, 8)) {
        old = read_u64_le(vm_ptr);
        if (old == expected) {
            write_u64_le(vm_ptr, desired);
        }
    } else {
        auto* ptr = reinterpret_cast<volatile long long*>(address);
        old = static_cast<uint64_t>(_InterlockedCompareExchange64(
            ptr,
            static_cast<long long>(desired),
            static_cast<long long>(expected)));
    }

    update_cmp_flags(flags, expected, old);
    if (old != expected) {
        vm.regs[0] = old;
    }

    return true;
}

vm_inline bool handlers::handle_xchg_mem64(vm_state& vm, UNUSED vm_flags& flags) {
    uint8_t base = 0;
    uint8_t reg = 0;
    int32_t offset = 0;
    if (!fetch_reg_i32_reg(vm, base, offset, reg)) {
        return false;
    }

    uint64_t address = 0;
    if (!resolve_address(vm, base, offset, address)) {
        return false;
    }

    uint64_t desired = vm.regs[reg];
    uint64_t old = 0;
    if (uint8_t* vm_ptr = vm_memory_ptr(vm, address, 8)) {
        old = read_u64_le(vm_ptr);
        write_u64_le(vm_ptr, desired);
    } else {
        auto* ptr = reinterpret_cast<volatile long long*>(address);
        old = static_cast<uint64_t>(_InterlockedExchange64(ptr, static_cast<long long>(desired)));
    }

    vm.regs[reg] = old;
    return true;
}

vm_inline bool handlers::handle_rdtsc(vm_state& vm, UNUSED vm_flags& flags) {
	const uint64_t value = __rdtsc();
    vm.regs[0] = static_cast<uint32_t>(value);          // low 32 bits
	vm.regs[3] = static_cast<uint32_t>(value >> 32);    // high 32 bits
    return true;
}

vm_inline bool handlers::handle_cpuid(vm_state& vm, UNUSED vm_flags& flags) {
    int result[4];

    const int mode = static_cast<int>(vm.regs[0]); //rax
    const int subleaf = static_cast<int>(vm.regs[2]);

    __cpuidex(result, mode, subleaf);

    // RAX, RBX, RCX, RDX

    vm.regs[0] = static_cast<uint32_t>(result[0]); // rax
    vm.regs[1] = static_cast<uint32_t>(result[1]); // rbx
    vm.regs[2] = static_cast<uint32_t>(result[2]); // rcx
    vm.regs[3] = static_cast<uint32_t>(result[3]); // rdx
    return true;
}

vm_inline bool handlers::handle_stosb(vm_state& vm, vm_flags& flags) {
    const auto value = static_cast<uint8_t>(vm.regs[0]);

    *reinterpret_cast<uint8_t*>(vm.regs[5]) = value;
    
    if (flags.df) {
        --vm.regs[5];
    } else {
        ++vm.regs[5];
    }

    return true;
}

vm_inline bool handlers::handle_rep_stosb(vm_state& vm, vm_flags& flags) {
    const auto value = static_cast<std::uint8_t>(vm.regs[0]);
    auto& count = vm.regs[2];
    auto& destination = vm.regs[5];

    while (count != 0) {
        *reinterpret_cast<std::uint8_t*>(destination) = value;

        if (flags.df) {
            --destination;
        }
        else {
            ++destination;
        }

        --count;
    }

    return true;
}

vm_inline bool handlers::handle_halt(vm_state& vm, UNUSED vm_flags& flags) {
    vm.halted = true;
    return true;
}

vm_inline bool handlers::handle_invalid(vm_state& vm, UNUSED vm_flags& flags) {
    vm.halted = true;
    return false;
}

#pragma code_seg(pop)

#undef UNUSED
