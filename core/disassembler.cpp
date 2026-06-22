#include "disassembler.hpp"
#include "common.hpp"
#include <iostream>
#include <cstring>

disassembler::disassembler() {
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

void disassembler::dump_x86_assembly(const uint8_t* code, size_t length, const char* title) {
    printf("\n=== %s ===\n", title);

    size_t offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset < length) {
        ZyanStatus status = ZydisDecoderDecodeFull(&decoder,
            code + offset, length - offset, &instruction, operands);

        if (!ZYAN_SUCCESS(status)) {
            printf("%04zX: [INVALID]\n", offset);
            offset++;
            continue;
        }

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
            instruction.operand_count_visible, buffer, sizeof(buffer), 0, ZYAN_NULL);

        printf("%04zX: ", offset);
        for (size_t i = 0; i < instruction.length; i++) {
            printf("%02X ", code[offset + i]);
        }
        for (size_t i = instruction.length; i < 10; i++) {
            printf("   ");
        }
        printf(" %s\n", buffer);

        offset += instruction.length;
    }
    printf("========================================\n");
}

void disassembler::dump_vm_bytecode(const uint8_t* code, size_t length, const char* title) {
    printf("\n=== %s ===\n", title);

    size_t offset = 0;
    while (offset < length) {
        uint8_t opcode = code[offset];
        printf("%04zX: %02X ", offset, opcode);

        switch (opcode) {
        case op_mov_imm: {
            if (offset + 10 > length) goto invalid;
            uint8_t reg = code[offset + 1];
            uint64_t imm;
            memcpy(&imm, &code[offset + 2], 8);
            printf("%02X %016llX MOV_IMM r%u, %llu\n", reg, imm, reg, imm);
            offset += 10;
            break;
        }
        case op_mov_reg: {
            if (offset + 3 > length) goto invalid;
            printf("%02X %02X      MOV_REG r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 1], code[offset + 2]);
            offset += 3;
            break;
        }
        case op_add: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   ADD r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_sub: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   SUB r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_mul: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   MUL r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_div: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   DIV r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_and: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   AND r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_or: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   OR r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_xor: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   XOR r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_not: {
            if (offset + 3 > length) goto invalid;
            printf("%02X %02X      NOT r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 1], code[offset + 2]);
            offset += 3;
            break;
        }
        case op_shl: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   SHL r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_shr: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   SHR r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_nop: {
            printf("NOP\n");
            offset++;
            break;
        }
        case op_sar: {
            if (offset + 4 > length) goto invalid;
            printf("%02X %02X %02X   SAR r%u, r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 3],
                code[offset + 1], code[offset + 2], code[offset + 3]);
            offset += 4;
            break;
        }
        case op_cmp: {
            if (offset + 3 > length) goto invalid;
            printf("%02X %02X      CMP r%u, r%u\n",
                code[offset + 1], code[offset + 2], code[offset + 1], code[offset + 2]);
            offset += 3;
            break;
        }
        case op_jmp: case op_jz: case op_jnz: case op_jl: case op_jg: case op_jle: case op_jge: {
            if (offset + 5 > length) goto invalid;
            int32_t target;
            memcpy(&target, &code[offset + 1], 4);
            const char* jmp_name[] = { "???", "???", "???", "???", "???", "???", "???", "???",
                                     "???", "???", "???", "???", "???", "???", "???", "???",
                                     "JMP", "JZ", "CMP", "JNZ", "JL", "JG", "JLE", "JGE" };
            printf("%08X %s %+d (target: %04zX)\n", target,
                jmp_name[opcode], target, offset + 5 + target);
            offset += 5;
            break;
        }
        case op_push: {
            if (offset + 2 > length) goto invalid;
            printf("%02X         PUSH r%u\n", code[offset + 1], code[offset + 1]);
            offset += 2;
            break;
        }
        case op_pop: {
            if (offset + 2 > length) goto invalid;
            printf("%02X         POP r%u\n", code[offset + 1], code[offset + 1]);
            offset += 2;
            break;
        }
        case op_call: {
            if (offset + 5 > length) goto invalid;
            int32_t target;
            memcpy(&target, &code[offset + 1], 4);
            uint32_t call_target = offset + 5 + target;
            printf("%08X CALL %+d (target: %04X)\n", target, target, call_target);
            offset += 5;
            break;
        }
        case op_call_native: {
            if (offset + 9 > length) goto invalid;
            uint64_t target;
            memcpy(&target, &code[offset + 1], 8);
            printf("%016llX CALL_NATIVE\n", target);
            offset += 9;
            break;
        }
        case op_call_native_indirect: {
            if (offset + 9 > length) goto invalid;
            uint64_t target;
            memcpy(&target, &code[offset + 1], 8);
            printf("%016llX CALL_NATIVE_INDIRECT\n", target);
            offset += 9;
            break;
        }
        case op_call_native_mem: {
            if (offset + 6 > length) goto invalid;
            uint8_t base = code[offset + 1];
            uint32_t offs;
            memcpy(&offs, &code[offset + 2], 4);
            printf("%02X %08X CALL_NATIVE_MEM [r%u + %u]\n", base, offs, base, offs);
            offset += 6;
            break;
        }
        case op_call_native_reg: {
            if (offset + 2 > length) goto invalid;
            uint8_t target = code[offset + 1];
            printf("%02X         CALL_NATIVE_REG r%u\n", target, target);
            offset += 2;
            break;
        }
        case op_load_mem: {
            if (offset + 7 > length) goto invalid;
            uint8_t dst = code[offset + 1];
            uint8_t base = code[offset + 2];
            uint32_t offs;
            memcpy(&offs, &code[offset + 3], 4);
            printf("%02X %02X %08X LOAD_MEM r%u, [r%u + %u]\n", dst, base, offs, dst, base, offs);
            offset += 7;
            break;
        }
        case op_store_mem: {
            if (offset + 7 > length) goto invalid;
            uint8_t base = code[offset + 1];
            uint32_t offs;
            memcpy(&offs, &code[offset + 2], 4);
            uint8_t src = code[offset + 6];
            printf("%02X %08X %02X STORE_MEM [r%u + %u], r%u\n", base, offs, src, base, offs, src);
            offset += 7;
            break;
        }
        case op_store_mem8: {
            if (offset + 7 > length) goto invalid;
            uint8_t base = code[offset + 1];
            uint32_t offs;
            memcpy(&offs, &code[offset + 2], 4);
            uint8_t src = code[offset + 6];
            printf("%02X %08X %02X STORE_MEM8 [r%u + %u], r%u\n", base, offs, src, base, offs, src);
            offset += 7;
            break;
        }
        case op_store_mem_zero128: {
            if (offset + 6 > length) goto invalid;
            uint8_t base = code[offset + 1];
            uint32_t offs;
            memcpy(&offs, &code[offset + 2], 4);
            printf("%02X %08X STORE_MEM_ZERO128 [r%u + %u]\n", base, offs, base, offs);
            offset += 6;
            break;
        }
        case op_cmpxchg_mem64: {
            if (offset + 7 > length) goto invalid;
            uint8_t base = code[offset + 1];
            uint32_t offs;
            memcpy(&offs, &code[offset + 2], 4);
            uint8_t src = code[offset + 6];
            printf("%02X %08X %02X CMPXCHG_MEM64 [r%u + %u], r%u\n", base, offs, src, base, offs, src);
            offset += 7;
            break;
        }
        case op_xchg_mem64: {
            if (offset + 7 > length) goto invalid;
            uint8_t base = code[offset + 1];
            uint32_t offs;
            memcpy(&offs, &code[offset + 2], 4);
            uint8_t reg = code[offset + 6];
            printf("%02X %08X %02X XCHG_MEM64 [r%u + %u], r%u\n", base, offs, reg, base, offs, reg);
            offset += 7;
            break;
        }
        case op_ret:
            printf("          RET\n");
            offset += 1;
            break;
        case op_halt:
            printf("          HALT\n");
            offset += 1;
            break;
        default:
        invalid:
            printf("          [UNKNOWN: 0x%02X]\n", opcode);
            offset += 1;
            break;
        }
    }
    printf("========================================\n");
}
