#include "x86_translator.hpp"
#include <iostream>
#include <cstring>

namespace {
    uint64_t mask_for_width(uint16_t width_bits) {
        if (width_bits >= 64 || width_bits == 0) {
            return ~0ull;
        }
        return (1ull << width_bits) - 1ull;
    }
}

x86_translator::x86_translator(vm_state& vm, uint64_t base_addr, uint64_t image_base_addr, uint32_t image_size_bytes)
    : builder(vm), base_address(base_addr), image_base(image_base_addr), image_size(image_size_bytes) {
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

uint64_t x86_translator::alloc_internal_label() {
    return internal_label_base + internal_label_counter++;
}

bool x86_translator::translate_function(const uint8_t* x86_code, size_t code_size) {
    printf("Starting advanced translation (%zu bytes)...\n", code_size);
    function_end_address = base_address + code_size;

    find_jump_targets(x86_code, code_size);

    size_t offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset < code_size) {
        uint64_t current_x86_addr = base_address + offset;
        builder.mark_jump_target(current_x86_addr);

        memset(&instruction, 0, sizeof(instruction));
        memset(operands, 0, sizeof(operands));

        ZyanStatus status = ZydisDecoderDecodeFull(&decoder,
            x86_code + offset, code_size - offset, &instruction, operands);

        if (!ZYAN_SUCCESS(status)) {
            printf("Decode failed at offset %zu\n", offset);
            offset++;
            continue;
        }

        printf("Translating x86 offset %zu (0x%llX) -> VM %u\n", offset, current_x86_addr, builder.get_current_position());

        if (!translate_instruction(&instruction, operands, current_x86_addr)) {
            printf("Failed to translate instruction at offset %zu\n", offset);
            return false;
        }

        offset += instruction.length;
    }

    builder.emit_halt();
    builder.resolve_jumps();
    printf("Advanced translation complete!\n");
    return true;
}

void x86_translator::find_jump_targets(const uint8_t* x86_code, size_t code_size) {
    size_t offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset < code_size) {
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder,
            x86_code + offset, code_size - offset, &instruction, operands);

        if (ZYAN_SUCCESS(status)) {
            if (instruction.mnemonic == ZYDIS_MNEMONIC_JMP ||
                instruction.mnemonic == ZYDIS_MNEMONIC_CALL ||
                instruction.mnemonic == ZYDIS_MNEMONIC_JZ || instruction.mnemonic == ZYDIS_MNEMONIC_JNZ ||
                instruction.mnemonic == ZYDIS_MNEMONIC_JL || instruction.mnemonic == ZYDIS_MNEMONIC_JLE ||
                instruction.mnemonic == ZYDIS_MNEMONIC_JB || instruction.mnemonic == ZYDIS_MNEMONIC_JBE ||
                instruction.mnemonic == ZYDIS_MNEMONIC_JNB || instruction.mnemonic == ZYDIS_MNEMONIC_JNBE ||
                instruction.mnemonic == ZYDIS_MNEMONIC_JNL || instruction.mnemonic == ZYDIS_MNEMONIC_JNLE) {

                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    uint64_t target;
                    ZydisCalcAbsoluteAddress(&instruction, &operands[0],
                        base_address + offset, &target);
                    printf("Found jump target: 0x%llX\n", target);
                }
            }
            offset += instruction.length;
        }
        else {
            offset++;
        }
    }
}

bool x86_translator::translate_instruction(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands, uint64_t current_addr) {
    switch (instruction->mnemonic) {
    case ZYDIS_MNEMONIC_MOV: return translate_mov(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_ADD: return translate_add(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_AND: return translate_and(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_OR: return translate_or(operands);
    case ZYDIS_MNEMONIC_XOR: return translate_xor(operands);
    case ZYDIS_MNEMONIC_NOT: return translate_not(operands);
    case ZYDIS_MNEMONIC_TEST: return translate_test(operands);
    case ZYDIS_MNEMONIC_SHL: return translate_shift(operands, op_shl);
    case ZYDIS_MNEMONIC_SHR: return translate_shift(operands, op_shr);
    case ZYDIS_MNEMONIC_SAR: return translate_shift(operands, op_sar);
    case ZYDIS_MNEMONIC_SUB: return translate_sub(instruction, operands, current_addr);

    case ZYDIS_MNEMONIC_INC: return translate_inc(operands);
    case ZYDIS_MNEMONIC_DEC: return translate_dec(operands);
    case ZYDIS_MNEMONIC_CDQ: return translate_cdq();
    case ZYDIS_MNEMONIC_IMUL: return translate_imul(operands);
    case ZYDIS_MNEMONIC_MUL: return translate_mul(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_DIV: return translate_div(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_CMP: return translate_cmp(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_CMPXCHG: return translate_cmpxchg(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_XCHG: return translate_xchg(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_LEA: return translate_lea(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_XORPS: return translate_xorps(operands);
    case ZYDIS_MNEMONIC_MOVDQA: return translate_movdqa(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_MOVZX: return translate_movzx(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD:
        return translate_movsx(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_MOVSB: return translate_movsb();
    case ZYDIS_MNEMONIC_CMOVNZ: return translate_cmovnz(operands);
    case ZYDIS_MNEMONIC_CMOVB: return translate_cmovb(operands);
    case ZYDIS_MNEMONIC_SETZ: return translate_setz(operands);
    case ZYDIS_MNEMONIC_SETNZ: return translate_setnz(operands);
    case ZYDIS_MNEMONIC_PUSH: return translate_push(operands);
    case ZYDIS_MNEMONIC_POP: return translate_pop(operands);
    case ZYDIS_MNEMONIC_CALL: return translate_call(instruction, operands, current_addr);
    case ZYDIS_MNEMONIC_RET: builder.emit_ret(); return true;
    case ZYDIS_MNEMONIC_JMP: return translate_jump(instruction, operands, current_addr, op_jmp);
    case ZYDIS_MNEMONIC_JZ: return translate_jump(instruction, operands, current_addr, op_jz);
    case ZYDIS_MNEMONIC_JNZ: return translate_jump(instruction, operands, current_addr, op_jnz);
    case ZYDIS_MNEMONIC_JL: return translate_jump(instruction, operands, current_addr, op_jl);
    case ZYDIS_MNEMONIC_JLE: return translate_jump(instruction, operands, current_addr, op_jle);
    case ZYDIS_MNEMONIC_JB: return translate_jump(instruction, operands, current_addr, op_jl);
    case ZYDIS_MNEMONIC_JBE: return translate_jump(instruction, operands, current_addr, op_jle);
    case ZYDIS_MNEMONIC_JNB: return translate_jump(instruction, operands, current_addr, op_jge);
    case ZYDIS_MNEMONIC_JNBE: return translate_jump(instruction, operands, current_addr, op_jg);
    case ZYDIS_MNEMONIC_JNL: return translate_jump(instruction, operands, current_addr, op_jge);
    case ZYDIS_MNEMONIC_JNLE: return translate_jump(instruction, operands, current_addr, op_jg);
    case ZYDIS_MNEMONIC_NOP: return translate_nop();
    case ZYDIS_MNEMONIC_INT3:
    case ZYDIS_MNEMONIC_INT:
        return true;

    default:
        printf("Unsupported instruction: %x %x\n", instruction->mnemonic, instruction->opcode);
        return false;
    }
}

bool x86_translator::get_image_relative_or_absolute(uint64_t target, uint64_t& encoded) const {
    if (image_base != 0 && image_size != 0 && target >= image_base && target < (image_base + image_size)) {
        encoded = target - image_base;
    } else {
        encoded = target;
    }
    return true;
}

bool x86_translator::translate_nop() {
    builder.emit_nop();
    return true;
}

bool x86_translator::resolve_memory_address(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operand,
    uint64_t current_addr,
    uint8_t& base,
    int32_t& offset) {
    const auto& mem = operand->mem;

    if (mem.base == ZYDIS_REGISTER_RIP || mem.base == ZYDIS_REGISTER_NONE) {
        uint64_t target = 0;
        if (mem.base == ZYDIS_REGISTER_RIP) {
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(instruction, operand, current_addr, &target))) {
                return false;
            }
        } else {
            target = static_cast<uint64_t>(mem.disp.value);
        }

        uint64_t encoded = 0;
        get_image_relative_or_absolute(target, encoded);
        base = vm_scratch_register;
        if (image_base != 0 && image_size != 0 && target >= image_base && target < (image_base + image_size)) {
            builder.emit_mov_imm(base, encoded);
            builder.emit_add(base, base, vm_image_base_register);
        } else {
            builder.emit_mov_imm(base, encoded);
        }
        offset = 0;
        return true;
    }

    if (mem.base == ZYDIS_REGISTER_NONE) {
        return false;
    }

    base = reg_mapper.get_vm_register(mem.base);
    offset = static_cast<int32_t>(mem.disp.value);
    return true;
}

bool x86_translator::emit_load_from_memory(
    uint8_t dst,
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operand,
    uint64_t current_addr) {
    uint8_t base = 0;
    int32_t offset = 0;
    if (!resolve_memory_address(instruction, operand, current_addr, base, offset)) {
        return false;
    }

    builder.emit_load_mem(dst, base, offset);
    return true;
}

bool x86_translator::emit_store_to_memory(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operand,
    uint64_t current_addr,
    uint8_t src,
    uint16_t width_bits) {
    uint8_t base = 0;
    int32_t offset = 0;
    if (!resolve_memory_address(instruction, operand, current_addr, base, offset)) {
        return false;
    }

    if (width_bits == 8) {
        builder.emit_store_mem8(base, offset, src);
    } else {
        builder.emit_store_mem(base, offset, src);
    }
    return true;
}

bool x86_translator::translate_mov(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

        if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            builder.emit_mov_imm(dst, operands[1].imm.value.u);
            return true;
        }
        else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
            uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
            builder.emit_mov_reg(dst, src);
            if (operands[0].size == 32) {
                builder.emit_mov_imm(vm_scratch_register, 0xFFFFFFFFull);
                builder.emit_and(dst, dst, vm_scratch_register);
            } else if (operands[0].size == 16) {
                builder.emit_mov_imm(vm_scratch_register, 0xFFFFull);
                builder.emit_and(dst, dst, vm_scratch_register);
            } else if (operands[0].size == 8) {
                builder.emit_mov_imm(vm_scratch_register, 0xFFull);
                builder.emit_and(dst, dst, vm_scratch_register);
            }
            return true;
        }
        else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (!emit_load_from_memory(dst, instruction, &operands[1], current_addr)) {
                return false;
            }
            if (operands[0].size == 32) {
                builder.emit_mov_imm(vm_scratch_register, 0xFFFFFFFFull);
                builder.emit_and(dst, dst, vm_scratch_register);
            } else if (operands[0].size == 16) {
                builder.emit_mov_imm(vm_scratch_register, 0xFFFFull);
                builder.emit_and(dst, dst, vm_scratch_register);
            } else if (operands[0].size == 8) {
                builder.emit_mov_imm(vm_scratch_register, 0xFFull);
                builder.emit_and(dst, dst, vm_scratch_register);
            }
            return true;
        }
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        return emit_store_to_memory(instruction, &operands[0], current_addr, src, operands[1].size);
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
        && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {
        uint8_t  base = 0;
        int32_t  disp = 0;
        if (!resolve_memory_address(instruction, &operands[0], current_addr, base, disp)) {
            return false;
        }
        uint64_t imm = operands[1].imm.value.u;
        constexpr uint8_t scratch = vm_scratch_register;

        builder.emit_mov_imm(scratch, imm);
        if (operands[0].size == 8) {
            builder.emit_store_mem8(base, disp, scratch);
        } else {
            builder.emit_store_mem(base, disp, scratch);
        }
        return true;
    }
    return false;
}

bool x86_translator::translate_add(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    constexpr uint8_t temp_reg = vm_scratch_register;
    constexpr uint8_t temp_reg2 = vm_scratch_register - 1;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_add(dst, dst, src);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint64_t immediate = operands[1].imm.value.u;

        builder.emit_mov_imm(temp_reg, immediate);
        builder.emit_add(dst, dst, temp_reg);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

        if (operands[1].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[1].mem.base);
            int32_t offset = (int32_t)operands[1].mem.disp.value;

            printf("  -> VM: LOAD_MEM r7, [r%u + %d]; ADD r%u, r%u, r7\n", base, offset, dst, dst);

            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_add(dst, dst, temp_reg);
            return true;
        }
        else {
            printf("  -> Unsupported memory addressing mode in ADD\n");
            return false;
        }
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t base = 0;
        int32_t offset = 0;
        if (!resolve_memory_address(instruction, &operands[0], current_addr, base, offset)) {
            return false;
        }

        builder.emit_load_mem(temp_reg, base, offset);
        builder.emit_mov_imm(temp_reg2, operands[1].imm.value.u);
        builder.emit_add(temp_reg, temp_reg, temp_reg2);
        builder.emit_store_mem(base, offset, temp_reg);
        return true;
    }
    return false;
}

bool x86_translator::translate_and(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    constexpr uint8_t temp_reg = vm_scratch_register;
    constexpr uint8_t temp_reg2 = vm_scratch_register - 1;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_and(dst, dst, src);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint64_t immediate = operands[1].imm.value.u;
        builder.emit_mov_imm(temp_reg, immediate);
        builder.emit_and(dst, dst, temp_reg);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

        if (operands[1].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[1].mem.base);
            int32_t offset = (int32_t)operands[1].mem.disp.value;

            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_and(dst, dst, temp_reg);
            return true;
        }
        else {
            printf("  -> Unsupported memory addressing mode in AND\n");
            return false;
        }
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t base = 0;
        int32_t offset = 0;
        if (!resolve_memory_address(instruction, &operands[0], current_addr, base, offset)) {
            return false;
        }

        builder.emit_load_mem(temp_reg, base, offset);
        builder.emit_mov_imm(temp_reg2, operands[1].imm.value.u);
        builder.emit_and(temp_reg, temp_reg, temp_reg2);
        builder.emit_store_mem(base, offset, temp_reg);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t base = 0;
        int32_t offset = 0;
        if (!resolve_memory_address(instruction, &operands[0], current_addr, base, offset)) {
            return false;
        }

        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_load_mem(temp_reg, base, offset);
        builder.emit_and(temp_reg, temp_reg, src);
        builder.emit_store_mem(base, offset, temp_reg);
        return true;
    }
    return false;
}

bool x86_translator::translate_or(const ZydisDecodedOperand* operands) {
    constexpr uint8_t temp_reg = vm_scratch_register;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_or(dst, dst, src);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint64_t immediate = operands[1].imm.value.u;
        builder.emit_mov_imm(temp_reg, immediate);
        builder.emit_or(dst, dst, temp_reg);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

        if (operands[1].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[1].mem.base);
            int32_t offset = (int32_t)operands[1].mem.disp.value;

            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_or(dst, dst, temp_reg);
            return true;
        }
        else {
            printf("  -> Unsupported memory addressing mode in OR\n");
            return false;
        }
    }
    return false;
}

bool x86_translator::translate_xor(const ZydisDecodedOperand* operands) {
    constexpr uint8_t temp_reg = vm_scratch_register;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_xor(dst, dst, src);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint64_t immediate = operands[1].imm.value.u;
        builder.emit_mov_imm(temp_reg, immediate);
        builder.emit_xor(dst, dst, temp_reg);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

        if (operands[1].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[1].mem.base);
            int32_t offset = (int32_t)operands[1].mem.disp.value;

            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_xor(dst, dst, temp_reg);
            return true;
        }
        else {
            printf("  -> Unsupported memory addressing mode in XOR\n");
            return false;
        }
    }
    return false;
}

bool x86_translator::translate_not(const ZydisDecodedOperand* operands) {
    constexpr uint8_t temp_reg = vm_scratch_register;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        builder.emit_not(dst, dst);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (operands[0].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[0].mem.base);
            int32_t offset = (int32_t)operands[0].mem.disp.value;

            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_not(temp_reg, temp_reg);
            builder.emit_store_mem(base, (uint32_t)offset, temp_reg);
            return true;
        }
        else {
            printf("  -> Unsupported memory addressing mode in NOT\n");
            return false;
        }
    }
    return false;
}

bool x86_translator::translate_test(const ZydisDecodedOperand* operands) {
    constexpr uint8_t temp_reg = vm_scratch_register;
    constexpr uint8_t zero_reg = vm_scratch_register - 1;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t a = reg_mapper.get_vm_register(operands[0].reg.value);
        uint8_t b = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_and(temp_reg, a, b);
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t a = reg_mapper.get_vm_register(operands[0].reg.value);
        uint64_t imm = operands[1].imm.value.u;
        builder.emit_mov_imm(temp_reg, imm);
        builder.emit_and(temp_reg, a, temp_reg);
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint8_t a = reg_mapper.get_vm_register(operands[0].reg.value);
        if (operands[1].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[1].mem.base);
            int32_t offset = (int32_t)operands[1].mem.disp.value;
            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_and(temp_reg, a, temp_reg);
        } else {
            printf("  -> Unsupported memory addressing mode in TEST\n");
            return false;
        }
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t b = reg_mapper.get_vm_register(operands[1].reg.value);
        if (operands[0].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[0].mem.base);
            int32_t offset = (int32_t)operands[0].mem.disp.value;
            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_and(temp_reg, temp_reg, b);
        } else {
            printf("  -> Unsupported memory addressing mode in TEST\n");
            return false;
        }
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t imm = operands[1].imm.value.u;
        if (operands[0].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[0].mem.base);
            int32_t offset = (int32_t)operands[0].mem.disp.value;
            builder.emit_load_mem(temp_reg, base, (uint32_t)offset);
            builder.emit_mov_imm(zero_reg, imm);
            builder.emit_and(temp_reg, temp_reg, zero_reg);
        } else {
            printf("  -> Unsupported memory addressing mode in TEST\n");
            return false;
        }
    }
    else {
        return false;
    }

    if (operands[0].size > 0 && operands[0].size < 64) {
        builder.emit_mov_imm(zero_reg, mask_for_width(operands[0].size));
        builder.emit_and(temp_reg, temp_reg, zero_reg);
    }

    builder.emit_mov_imm(zero_reg, 0);
    builder.emit_cmp(temp_reg, zero_reg);
    return true;
}

bool x86_translator::translate_imul(const ZydisDecodedOperand* operands) {
    constexpr uint8_t temp1 = vm_scratch_register;
    constexpr uint8_t temp2 = vm_scratch_register - 1;

    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

    const bool has_imm = (operands[2].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);

    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);

        if (has_imm) {
            builder.emit_mov_reg(temp1, src);
            builder.emit_mov_imm(temp2, operands[2].imm.value.u);
            builder.emit_mul(dst, temp1, temp2);
        } else {
            builder.emit_mul(dst, dst, src);
        }
        return true;
    }
    else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (operands[1].mem.base != ZYDIS_REGISTER_NONE) {
            uint8_t base = reg_mapper.get_vm_register(operands[1].mem.base);
            int32_t offset = (int32_t)operands[1].mem.disp.value;

            builder.emit_load_mem(temp1, base, (uint32_t)offset);

            if (has_imm) {
                builder.emit_mov_imm(temp2, operands[2].imm.value.u);
                builder.emit_mul(dst, temp1, temp2);
            } else {
                builder.emit_mul(dst, dst, temp1);
            }
            return true;
        } else {
            printf("  -> Unsupported memory addressing mode in IMUL\n");
            return false;
        }
    }

    return false;
}

bool x86_translator::translate_mul(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    constexpr uint8_t rax = 0;
    constexpr uint8_t rdx = 3;
    constexpr uint8_t src_value = vm_scratch_register;
    constexpr uint8_t zero = vm_scratch_register - 1;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[0].reg.value);
        builder.emit_mov_reg(src_value, src);
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!emit_load_from_memory(src_value, instruction, &operands[0], current_addr)) {
            return false;
        }
    }
    else {
        return false;
    }

    builder.emit_mul(rax, rax, src_value);
    builder.emit_mov_imm(rdx, 0);
    builder.emit_mov_imm(zero, 0);
    builder.emit_cmp(rdx, zero);
    return true;
}

bool x86_translator::translate_div(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    constexpr uint8_t dividend = vm_scratch_register;
    constexpr uint8_t divisor = vm_scratch_register - 1;
    constexpr uint8_t rax = 0;
    constexpr uint8_t rdx = 3;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[0].reg.value);
        builder.emit_mov_reg(divisor, src);
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!emit_load_from_memory(divisor, instruction, &operands[0], current_addr)) {
            return false;
        }
    }
    else {
        return false;
    }

    builder.emit_mov_reg(dividend, rax);
    builder.emit_div(rax, dividend, divisor);
    builder.emit_mul(rdx, rax, divisor);
    builder.emit_sub(rdx, dividend, rdx);
    return true;
}

bool x86_translator::translate_shift(const ZydisDecodedOperand* operands, uint8_t op) {
    constexpr uint8_t temp_reg = vm_scratch_register;

    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

    if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t immediate = operands[1].imm.value.u;
        builder.emit_mov_imm(temp_reg, immediate);
    }
    else if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_mov_reg(temp_reg, src);
    }
    else {
        return false;
    }

    switch (op) {
    case op_shl: builder.emit_shl(dst, dst, temp_reg); break;
    case op_shr: builder.emit_shr(dst, dst, temp_reg); break;
    case op_sar: builder.emit_sar(dst, dst, temp_reg); break;
    default: return false;
    }

    return true;
}

bool x86_translator::translate_sub(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    constexpr uint8_t scratch = vm_scratch_register;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_sub(dst, dst, src);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        uint64_t imm = operands[1].imm.value.u;
        builder.emit_mov_imm(scratch, imm);
        builder.emit_sub(dst, dst, scratch);
        return true;
    }
    else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        if (!emit_load_from_memory(scratch, instruction, &operands[1], current_addr)) {
            return false;
        }
        builder.emit_sub(dst, dst, scratch);
        return true;
    }
    return false;
}

bool x86_translator::translate_cmp(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    constexpr uint8_t temp_a = vm_scratch_register;
    constexpr uint8_t temp_b = vm_scratch_register - 1;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t a = reg_mapper.get_vm_register(operands[0].reg.value);
        uint8_t b = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_cmp(a, b);
        return true;
    }
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint8_t a = reg_mapper.get_vm_register(operands[0].reg.value);
        builder.emit_mov_imm(temp_b, operands[1].imm.value.u & mask_for_width(operands[0].size));
        builder.emit_cmp(a, temp_b);
        return true;
    }
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint8_t a = reg_mapper.get_vm_register(operands[0].reg.value);
        if (!emit_load_from_memory(temp_b, instruction, &operands[1], current_addr)) {
            return false;
        }
        builder.emit_cmp(a, temp_b);
        return true;
    }
    if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t b = reg_mapper.get_vm_register(operands[1].reg.value);
        if (!emit_load_from_memory(temp_a, instruction, &operands[0], current_addr)) {
            return false;
        }
        builder.emit_cmp(temp_a, b);
        return true;
    }
    if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        if (!emit_load_from_memory(temp_a, instruction, &operands[0], current_addr)) {
            return false;
        }
        builder.emit_mov_imm(temp_b, operands[1].imm.value.u & mask_for_width(operands[0].size));
        builder.emit_cmp(temp_a, temp_b);
        return true;
    }
    return false;
}

bool x86_translator::translate_cmpxchg(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[0].size == 64 && operands[1].size == 64) {
        uint8_t base = 0;
        int32_t offset = 0;
        if (!resolve_memory_address(instruction, &operands[0], current_addr, base, offset)) {
            return false;
        }

        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_cmpxchg_mem64(base, offset, src);
        return true;
    }

    printf("  -> Unsupported CMPXCHG form (only qword memory, 64-bit register source is supported)\n");
    return false;
}

bool x86_translator::translate_xchg(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    const ZydisDecodedOperand* mem = nullptr;
    const ZydisDecodedOperand* reg = nullptr;

    if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        mem = &operands[0];
        reg = &operands[1];
    } else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
               operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        reg = &operands[0];
        mem = &operands[1];
    }

    if (mem && reg && mem->size == 64 && reg->size == 64) {
        uint8_t base = 0;
        int32_t offset = 0;
        if (!resolve_memory_address(instruction, mem, current_addr, base, offset)) {
            return false;
        }

        uint8_t vm_reg = reg_mapper.get_vm_register(reg->reg.value);
        builder.emit_xchg_mem64(base, offset, vm_reg);
        return true;
    }

    printf("  -> Unsupported XCHG form (only qword memory/register is supported)\n");
    return false;
}

bool x86_translator::translate_push(const ZydisDecodedOperand* operands) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[0].reg.value);
        builder.emit_push(src);
        return true;
    }
    return false;
}

bool x86_translator::translate_inc(const ZydisDecodedOperand* operands) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

        const int temp_register = vm_scratch_register;

        builder.emit_mov_imm(temp_register, 1);
        builder.emit_add(dst, dst, temp_register);
        return true;
    }

    return false;
}

bool x86_translator::translate_dec(const ZydisDecodedOperand* operands) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

        const int temp_register = vm_scratch_register;

        builder.emit_mov_imm(temp_register, 1);
        builder.emit_sub(dst, dst, temp_register);
        return true;
    }

    return false;
}

bool x86_translator::translate_cdq() {
    uint8_t rax = reg_mapper.get_vm_register(ZYDIS_REGISTER_RAX);
    uint8_t rdx = reg_mapper.get_vm_register(ZYDIS_REGISTER_RDX);
    constexpr uint8_t scratch = vm_scratch_register;

    builder.emit_mov_imm(rdx, 0);
    builder.emit_mov_imm(scratch, 0x80000000ull);
    builder.emit_cmp(rax, scratch);

    uint64_t label_neg = alloc_internal_label();
    uint64_t label_end = alloc_internal_label();

    builder.emit_jump(op_jge, label_neg);
    builder.emit_jump(op_jmp, label_end);

    builder.mark_jump_target(label_neg);
    builder.emit_mov_imm(rdx, 0xFFFFFFFFull);

    builder.mark_jump_target(label_end);
    return true;
}

bool x86_translator::translate_lea(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands, uint64_t current_addr) {
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        operands[1].type != ZYDIS_OPERAND_TYPE_MEMORY) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
    const auto& mem = operands[1].mem;

    constexpr uint8_t scratch1 = vm_scratch_register;
    constexpr uint8_t scratch2 = vm_scratch_register - 1;

    if (mem.base == ZYDIS_REGISTER_RIP) {
        uint64_t target = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(instruction, &operands[1], current_addr, &target))) {
            return false;
        }
        if (image_base != 0 && image_size != 0 && target >= image_base && target < (image_base + image_size)) {
            uint64_t rva = target - image_base;
            builder.emit_mov_imm(dst, rva);
            builder.emit_add(dst, dst, vm_image_base_register);
        } else {
            builder.emit_mov_imm(dst, target);
        }
        return true;
    }

    if (mem.base != ZYDIS_REGISTER_NONE) {
        uint8_t base = reg_mapper.get_vm_register(mem.base);
        builder.emit_mov_reg(dst, base);
    } else {
        builder.emit_mov_imm(dst, 0);
    }

    if (mem.index != ZYDIS_REGISTER_NONE) {
        uint8_t index = reg_mapper.get_vm_register(mem.index);
        uint32_t scale = mem.scale ? static_cast<uint32_t>(mem.scale) : 1;

        if (scale == 1) {
            builder.emit_add(dst, dst, index);
        } else {
            builder.emit_mov_reg(scratch1, index);
            builder.emit_mov_imm(scratch2, scale);
            builder.emit_mul(scratch1, scratch1, scratch2);
            builder.emit_add(dst, dst, scratch1);
        }
    }

    int64_t disp = static_cast<int64_t>(mem.disp.value);
    if (disp > 0) {
        builder.emit_mov_imm(scratch1, static_cast<uint64_t>(disp));
        builder.emit_add(dst, dst, scratch1);
    } else if (disp < 0) {
        builder.emit_mov_imm(scratch1, static_cast<uint64_t>(-disp));
        builder.emit_sub(dst, dst, scratch1);
    }

    return true;
}

bool x86_translator::translate_pop(const ZydisDecodedOperand* operands) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
        builder.emit_pop(dst);
        return true;
    }
    return false;
}

bool x86_translator::translate_call(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands, uint64_t current_addr) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t target;
        ZydisCalcAbsoluteAddress(instruction, &operands[0], current_addr, &target);
        if (target >= base_address && target < function_end_address) {
            builder.emit_call(target);
        } else {
            if (image_base != 0 && image_size != 0 && target >= image_base && target < (image_base + image_size)) {
                builder.emit_call_native(target - image_base);
            } else {
                builder.emit_call_native(target);
            }
        }
        return true;
    }
    if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        uint64_t target = 0;
        if (operands[0].mem.base == ZYDIS_REGISTER_RIP) {
            if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(instruction, &operands[0], current_addr, &target))) {
                return false;
            }
        } else if (operands[0].mem.base == ZYDIS_REGISTER_NONE) {
            target = static_cast<uint64_t>(operands[0].mem.disp.value);
        } else {
            uint8_t base = 0;
            int32_t offset = 0;
            if (!resolve_memory_address(instruction, &operands[0], current_addr, base, offset)) {
                printf("  -> Unsupported indirect call addressing mode\n");
                return false;
            }
            builder.emit_call_native_mem(base, offset);
            return true;
        }

        uint64_t encoded = 0;
        get_image_relative_or_absolute(target, encoded);
        builder.emit_call_native_indirect(encoded);
        return true;
    }
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t target = reg_mapper.get_vm_register(operands[0].reg.value);
        builder.emit_call_native_reg(target);
        return true;
    }
    return false;
}

bool x86_translator::translate_xorps(const ZydisDecodedOperand* operands) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        operands[0].reg.value == operands[1].reg.value) {
        ZydisRegister reg = operands[0].reg.value;
        if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM15) {
            xmm_known_zero[reg - ZYDIS_REGISTER_XMM0] = true;
            return true;
        }
    }
    return false;
}

bool x86_translator::translate_movdqa(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
        operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        ZydisRegister reg = operands[1].reg.value;
        if (reg >= ZYDIS_REGISTER_XMM0 && reg <= ZYDIS_REGISTER_XMM15 &&
            xmm_known_zero[reg - ZYDIS_REGISTER_XMM0]) {
            uint8_t base = 0;
            int32_t offset = 0;
            if (!resolve_memory_address(instruction, &operands[0], current_addr, base, offset)) {
                return false;
            }
            builder.emit_store_mem_zero128(base, offset);
            return true;
        }
    }
    return false;
}

bool x86_translator::translate_movzx(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_mov_reg(dst, src);
    } else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!emit_load_from_memory(dst, instruction, &operands[1], current_addr)) {
            return false;
        }
    } else {
        return false;
    }

    builder.emit_mov_imm(vm_scratch_register, mask_for_width(operands[1].size));
    builder.emit_and(dst, dst, vm_scratch_register);
    return true;
}

bool x86_translator::translate_movsx(
    const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands,
    uint64_t current_addr) {
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    const uint16_t src_width = operands[1].size;
    if (src_width == 0 || src_width > 64) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);

    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
        builder.emit_mov_reg(dst, src);
    } else if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (!emit_load_from_memory(dst, instruction, &operands[1], current_addr)) {
            return false;
        }
    } else {
        return false;
    }

    if (src_width < 64) {
        const uint64_t shift = 64u - src_width;
        builder.emit_mov_imm(vm_scratch_register, mask_for_width(src_width));
        builder.emit_and(dst, dst, vm_scratch_register);
        builder.emit_mov_imm(vm_scratch_register, shift);
        builder.emit_shl(dst, dst, vm_scratch_register);
        builder.emit_sar(dst, dst, vm_scratch_register);
    }

    if (operands[0].size > 0 && operands[0].size < 64) {
        builder.emit_mov_imm(vm_scratch_register, mask_for_width(operands[0].size));
        builder.emit_and(dst, dst, vm_scratch_register);
    }

    return true;
}

bool x86_translator::translate_movsb() {
    constexpr uint8_t rsi = 4;
    constexpr uint8_t rdi = 5;
    constexpr uint8_t rcx = 2;
    constexpr uint8_t byte_value = vm_scratch_register;
    constexpr uint8_t temp = vm_scratch_register - 1;

    uint64_t loop = alloc_internal_label();
    uint64_t done = alloc_internal_label();

    builder.mark_jump_target(loop);
    builder.emit_mov_imm(temp, 0);
    builder.emit_cmp(rcx, temp);
    builder.emit_jump(op_jz, done);

    builder.emit_load_mem(byte_value, rsi, 0);
    builder.emit_store_mem8(rdi, 0, byte_value);

    builder.emit_mov_imm(temp, 1);
    builder.emit_add(rsi, rsi, temp);
    builder.emit_add(rdi, rdi, temp);
    builder.emit_sub(rcx, rcx, temp);
    builder.emit_jump(op_jmp, loop);

    builder.mark_jump_target(done);
    return true;
}

bool x86_translator::translate_cmovnz(const ZydisDecodedOperand* operands) {
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
    uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
    uint64_t skip = alloc_internal_label();

    builder.emit_jump(op_jz, skip);
    builder.emit_mov_reg(dst, src);
    if (operands[0].size > 0 && operands[0].size < 64) {
        builder.emit_mov_imm(vm_scratch_register, mask_for_width(operands[0].size));
        builder.emit_and(dst, dst, vm_scratch_register);
    }
    builder.mark_jump_target(skip);
    return true;
}

bool x86_translator::translate_cmovb(const ZydisDecodedOperand* operands) {
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    uint64_t done = alloc_internal_label();
    builder.emit_jump(op_jge, done);
    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
    uint8_t src = reg_mapper.get_vm_register(operands[1].reg.value);
    builder.emit_mov_reg(dst, src);
    builder.mark_jump_target(done);
    return true;
}

bool x86_translator::translate_setnz(const ZydisDecodedOperand* operands) {
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
    uint64_t done = alloc_internal_label();

    builder.emit_mov_imm(vm_scratch_register, ~0xFFull);
    builder.emit_and(dst, dst, vm_scratch_register);
    builder.emit_jump(op_jz, done);
    builder.emit_mov_imm(vm_scratch_register, 1);
    builder.emit_or(dst, dst, vm_scratch_register);
    builder.mark_jump_target(done);
    return true;
}

bool x86_translator::translate_setz(const ZydisDecodedOperand* operands) {
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
        return false;
    }

    uint8_t dst = reg_mapper.get_vm_register(operands[0].reg.value);
    uint64_t done = alloc_internal_label();

    builder.emit_mov_imm(vm_scratch_register, ~0xFFull);
    builder.emit_and(dst, dst, vm_scratch_register);
    builder.emit_jump(op_jnz, done);
    builder.emit_mov_imm(vm_scratch_register, 1);
    builder.emit_or(dst, dst, vm_scratch_register);
    builder.mark_jump_target(done);
    return true;
}

bool x86_translator::translate_jump(const ZydisDecodedInstruction* instruction,
    const ZydisDecodedOperand* operands, uint64_t current_addr,
    uint8_t vm_jump_type) {
    if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        uint64_t target;
        ZydisCalcAbsoluteAddress(instruction, &operands[0], current_addr, &target);
        builder.emit_jump(vm_jump_type, target);
        return true;
    }
    return false;
}
