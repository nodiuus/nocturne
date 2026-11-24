#include "pe_rewriter.hpp"

#include <Zydis/Zydis.h>
#include <limits>
#include <print>
#include <utility>

#include "alignment.hpp"
#include "byte_io.hpp"
#include "pe_utils.hpp"
#include "vm_interpreter.hpp"

namespace {

bool validate_blob(const uint8_t* blob, size_t size, uint32_t entry_offset) {
    if (!blob || size == 0) {
        std::println("Blob validation failed: empty blob");
        return false;
    }
    if (entry_offset >= size) {
        std::println("Blob validation failed: entry offset out of range");
        return false;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::vector<uint8_t> visited(size, 0);
    std::vector<uint32_t> worklist;
    worklist.push_back(entry_offset);

    while (!worklist.empty()) {
        uint32_t offset = worklist.back();
        worklist.pop_back();

        while (offset < size) {
            if (visited[offset]) {
                break;
            }
            visited[offset] = 1;

            ZydisDecodedInstruction instr;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, blob + offset, size - offset, &instr, operands))) {
                std::println("Blob validation failed: decode error at +0x{:X}", offset);
                return false;
            }

            const bool is_call = instr.meta.category == ZYDIS_CATEGORY_CALL;
            const bool is_branch =
                instr.meta.category == ZYDIS_CATEGORY_COND_BR ||
                instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
            const bool is_ret = instr.meta.category == ZYDIS_CATEGORY_RET;

            if (is_call || is_branch) {
                bool has_relative = false;
                int64_t rel = 0;
                for (uint8_t i = 0; i < instr.operand_count; ++i) {
                    const auto& op = operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                        rel = op.imm.value.s;
                        has_relative = true;
                        break;
                    }
                }

                if (!has_relative) {
                    bool uses_rip_mem = false;
                    for (uint8_t i = 0; i < instr.operand_count; ++i) {
                        const auto& op = operands[i];
                        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            op.mem.base == ZYDIS_REGISTER_RIP) {
                            uses_rip_mem = true;
                            break;
                        }
                    }

                    if (uses_rip_mem) {
                        std::println("Blob validation failed: RIP-relative indirect control transfer at +0x{:X} ({})",
                                     offset, ZydisMnemonicGetString(instr.mnemonic));
                        return false;
                    }

                    offset += instr.length;
                    continue;
                }

                int64_t target = static_cast<int64_t>(offset) + instr.length + rel;
                if (target < 0 || target >= static_cast<int64_t>(size)) {
                    std::println(
                        "Blob validation failed: {} at +0x{:X} targets +0x{:X} (out of blob)",
                        ZydisMnemonicGetString(instr.mnemonic),
                        offset,
                        static_cast<uint64_t>(target));
                    return false;
                }

                worklist.push_back(static_cast<uint32_t>(target));

                if (instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR || instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
                    break;
                }
            }

            if (is_ret) {
                break;
            }

            offset += instr.length;
        }
    }

    return true;
}

} // namespace

pe_rewriter::pe_rewriter(LIEF::PE::Binary& pe, std::string section_name)
    : pe_(pe), section_name_(std::move(section_name)) {
}

uint32_t pe_rewriter::add_vm_section(const std::vector<uint8_t>& bytecode) {
    if (vm_section_created_) {
        auto* existing = pe_.get_section(section_name_);
        if (!existing) {
            std::println("Error: injected VM section {} disappeared", section_name_);
            return 0;
        }

        auto current_content = existing->content();
        std::vector<uint8_t> new_content(current_content.begin(), current_content.end());

        size_t bytecode_offset = alignment::align_up_size(new_content.size(), 16);
        if (bytecode_offset > new_content.size()) {
            new_content.resize(bytecode_offset, 0x00);
        }

        new_content.insert(new_content.end(), bytecode.begin(), bytecode.end());

        uint32_t file_align = pe_.optional_header().file_alignment();
        uint32_t section_align = pe_.optional_header().section_alignment();
        uint32_t new_raw_size = static_cast<uint32_t>(alignment::align_up_size(new_content.size(), file_align));
        uint32_t new_virtual_size = static_cast<uint32_t>(alignment::align_up_size(new_content.size(), section_align));

        existing->content(new_content);
        existing->size(new_raw_size);
        existing->virtual_size(new_virtual_size);

        return static_cast<uint32_t>(existing->virtual_address()) + static_cast<uint32_t>(bytecode_offset);
    }

    std::string preferred_name = section_name_;
    section_name_ = pe_utils::choose_available_section_name(pe_, section_name_);
    if (section_name_ != preferred_name) {
        std::println("Section {} already exists; using {} for injected VM blob", preferred_name, section_name_);
    }

    LIEF::PE::Section section(section_name_);
    section.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
    section.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);

    std::vector<uint8_t> vm_blob;

    const uint8_t* interpreter_begin = &__vmb_blob_start;
    const uint8_t* interpreter_end = &__vmb_blob_end;
    size_t interpreter_size = interpreter_end - interpreter_begin;
    const uint8_t* wrapper_thunk_ptr = reinterpret_cast<const uint8_t*>(&run_vm_from_blob);
    const uint8_t* wrapper_ptr = pe_utils::resolve_direct_jmp_thunk(wrapper_thunk_ptr);

    if (interpreter_begin >= interpreter_end) {
        std::println("Error: VM blob markers are invalid");
        return 0;
    }
    if (wrapper_ptr < interpreter_begin || wrapper_ptr >= interpreter_end) {
        std::println("Error: run_vm_from_blob is not inside VM blob section");
        std::println("       thunk: {}, resolved: {}, blob: {}..{}",
                     static_cast<const void*>(wrapper_thunk_ptr),
                     static_cast<const void*>(wrapper_ptr),
                     static_cast<const void*>(interpreter_begin),
                     static_cast<const void*>(interpreter_end));
        return 0;
    }

    size_t wrapper_offset = static_cast<size_t>(wrapper_ptr - interpreter_begin);
    wrapper_offset_ = static_cast<uint32_t>(wrapper_offset);

    std::println("Interpreter size: {} bytes", interpreter_size);
    std::println("Interpreter entry offset: 0x{:X}", static_cast<uint32_t>(wrapper_offset));

    if (!validate_blob(interpreter_begin, interpreter_size, wrapper_offset_)) {
        std::println("Error: VM blob contains external or invalid control flow.");
        std::println("Build the interpreter with optimizations and without tracing or stack probes.");
        return 0;
    }

    vm_blob.insert(vm_blob.end(), interpreter_begin, interpreter_end);

    std::print("VM Blob Head: ");
    for (size_t i = 0; i < std::min<size_t>(32, vm_blob.size()); ++i) {
        std::print("{:02X} ", vm_blob[i]);
    }
    std::println();

    size_t bytecode_offset = alignment::align_up_size(vm_blob.size(), 16);
    if (bytecode_offset > vm_blob.size()) {
        vm_blob.resize(bytecode_offset, 0x00);
    }

    vm_blob.insert(vm_blob.end(), bytecode.begin(), bytecode.end());

    section.content(vm_blob);

    section.characteristics(static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE) |
                            static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ) |
                            static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE) |
                            static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::CNT_CODE));

    uint32_t next_rva = 0x1000;
    uint32_t section_alignment = pe_.optional_header().section_alignment();

    auto sections = pe_.sections();
    if (sections.begin() != sections.end()) {
        LIEF::PE::Section* last_sect = nullptr;
        for (auto& sect : sections) {
            last_sect = &sect;
        }

        if (last_sect) {
            uint32_t last_va = static_cast<uint32_t>(last_sect->virtual_address());
            uint32_t last_vsize = static_cast<uint32_t>(last_sect->virtual_size());
            next_rva = alignment::align_up(last_va + last_vsize, section_alignment);
        }
    }

    std::println("Calculated next section RVA: 0x{:X} (alignment: 0x{:X})", next_rva, section_alignment);
    section.virtual_address(next_rva);

    pe_.add_section(section);
    vm_section_created_ = true;

    auto* added = pe_.get_section(section_name_);
    interpreter_rva_ = added ? static_cast<uint32_t>(added->virtual_address())
                             : static_cast<uint32_t>(section.virtual_address());
    wrapper_rva_ = interpreter_rva_ + wrapper_offset_;
    std::println("Interpreter RVA: 0x{:X}", interpreter_rva_);
    std::println("Wrapper RVA: 0x{:X}", wrapper_rva_);

    return interpreter_rva_ + static_cast<uint32_t>(bytecode_offset);
}

bool pe_rewriter::patch_function(
    uint32_t fn_rva,
    uint32_t end_rva,
    uint32_t bytecode_rva,
    uint32_t bytecode_size)
{
    auto* virtualized_section = pe_.get_section(section_name_);
    if (!virtualized_section) {
        std::println("Error: {} section not found", section_name_);
        return false;
    }

    uint32_t sect_rva = static_cast<uint32_t>(virtualized_section->virtual_address());
    uint64_t image_base = pe_.optional_header().imagebase();

    // LIEF may adjust the section RVA when writing the PE.
    interpreter_rva_ = sect_rva;
    wrapper_rva_ = interpreter_rva_ + wrapper_offset_;

    uint64_t interpreter_va = image_base + interpreter_rva_;
    uint64_t entry_va = image_base + wrapper_rva_;
    uint64_t bytecode_va = image_base + bytecode_rva;

    std::println("Image Base: 0x{:X}", image_base);
    std::println("Interpreter VA: 0x{:X} (RVA: 0x{:X})", interpreter_va, interpreter_rva_);
    std::println("Entry VA: 0x{:X} (RVA: 0x{:X})", entry_va, wrapper_rva_);
    std::println("Bytecode VA: 0x{:X} (RVA: 0x{:X}, size: 0x{:X})", bytecode_va, bytecode_rva, bytecode_size);

    auto current_content = virtualized_section->content();
    std::vector<uint8_t> new_content(current_content.begin(), current_content.end());

    uint32_t stub_offset = static_cast<uint32_t>(current_content.size());
    uint32_t stub_rva = sect_rva + stub_offset;

    std::println("Trampoline stub will be at RVA: 0x{:X}", stub_rva);

    std::vector<uint8_t> stub;

    stub.insert(stub.end(), {
        0x53,                           // push rbx
        0x51,                           // push rcx
        0x52,                           // push rdx
        0x41, 0x50,                     // push r8
        0x41, 0x51,                     // push r9
        0x41, 0x52,                     // push r10
        0x41, 0x53                      // push r11
        });

    static_assert(sizeof(vm_state) < 0x1000, "vm_state too large for stack probe tail");

    // Manual stack probing keeps large VM frames from jumping past guard pages.
    auto align16 = [](uint32_t v) { return (v + 0xF) & ~0xFu; };
    constexpr uint32_t call_frame_size = 0x40;
    uint32_t total_size = align16(call_frame_size + static_cast<uint32_t>(sizeof(vm_state)) + vm_memory_size);

    uint32_t page_count = total_size / 0x1000;
    uint32_t remainder = total_size % 0x1000;

    stub.push_back(0xB8); // mov eax, imm32
    size_t page_count_pos = stub.size();
    stub.resize(stub.size() + 4);
    byte_io::write_u32_le_at(stub, page_count_pos, page_count);

    stub.insert(stub.end(), {
        0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00, // sub rsp, 4096
        0x48, 0x85, 0x24, 0x24,         // test [rsp], rsp (commit page)
        0xFF, 0xC8,                     // dec eax
        0x75, 0xF1                      // jnz loop (offset -15 bytes: 7+4+2+2=15)
    });

    if (remainder != 0) {
        stub.insert(stub.end(), { 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00 }); // sub rsp, imm32
        byte_io::write_u32_le_at(stub, stub.size() - 4, remainder);
        stub.insert(stub.end(), { 0x48, 0x85, 0x24, 0x24 }); // test [rsp], rsp (commit final page)
    }

    auto append_lea_rip = [&](uint8_t modrm, uint32_t target_rva) {
        size_t instr_start = stub.size();
        stub.push_back(0x48);
        stub.push_back(0x8D);
        stub.push_back(modrm);
        size_t disp_offset = stub.size();
        stub.resize(stub.size() + 4);
        int64_t next_instr_rva = static_cast<int64_t>(stub_rva + instr_start + 7);
        int64_t disp = static_cast<int64_t>(target_rva) - next_instr_rva;
        if (disp < std::numeric_limits<int32_t>::min() || disp > std::numeric_limits<int32_t>::max()) {
            throw std::runtime_error("Relative displacement out of range for trampoline stub");
        }
        byte_io::write_i32_le_at(stub, disp_offset, static_cast<int32_t>(disp));
    };

    append_lea_rip(0x0D, bytecode_rva); // lea rcx, [rip + bytecode]

    stub.push_back(0xBA); // mov edx, imm32
    size_t size_pos = stub.size();
    stub.resize(stub.size() + 4);
    byte_io::write_u32_le_at(stub, size_pos, bytecode_size);

    // vm_state starts above the shadow space and copied stack args.
    stub.insert(stub.end(), { 0x4C, 0x8D, 0x44, 0x24, static_cast<uint8_t>(call_frame_size) });
    stub.insert(stub.end(), { 0x4C, 0x89, 0xC3 }); // mov rbx, r8

    auto append_mov_rax_from_rsp = [&](uint32_t disp) {
        stub.insert(stub.end(), { 0x48, 0x8B, 0x84, 0x24 }); // mov rax, [rsp+disp32]
        size_t pos = stub.size();
        stub.resize(stub.size() + 4);
        byte_io::write_u32_le_at(stub, pos, disp);
    };
    auto append_mov_rsp_from_rax = [&](uint8_t disp) {
        stub.insert(stub.end(), { 0x48, 0x89, 0x44, 0x24, disp }); // mov [rsp+disp8], rax
    };

    constexpr uint32_t saved_r9_offset = 16;
    constexpr uint32_t saved_r8_offset = 24;
    constexpr uint32_t saved_rdx_offset = 32;
    constexpr uint32_t saved_rcx_offset = 40;

    // Seed VM argument registers from the original Windows x64 call arguments.
    stub.insert(stub.end(), { 0x4C, 0x8B, 0x8C, 0x24 }); // mov r9, [rsp+disp32]
    size_t original_rcx_pos = stub.size();
    stub.resize(stub.size() + 4);
    byte_io::write_u32_le_at(stub, original_rcx_pos, total_size + saved_rcx_offset);
    append_mov_rax_from_rsp(total_size + saved_rdx_offset);
    append_mov_rsp_from_rax(0x20);
    append_mov_rax_from_rsp(total_size + saved_r8_offset);
    append_mov_rsp_from_rax(0x28);
    append_mov_rax_from_rsp(total_size + saved_r9_offset);
    append_mov_rsp_from_rax(0x30);

    std::println("DEBUG TRAMPOLINE: stub_rva=0x{:X}, wrapper_rva_=0x{:X}, bytecode_rva=0x{:X}",
                 stub_rva, wrapper_rva_, bytecode_rva);
    std::println("DEBUG TRAMPOLINE: About to calculate LEA for wrapper at RVA 0x{:X}", wrapper_rva_);
    std::println("DEBUG TRAMPOLINE: stub.size()={}, so LEA instr will be at stub_rva + {} = 0x{:X}",
                 stub.size(), stub.size(), stub_rva + stub.size());

    size_t lea_position_before = stub.size();
    append_lea_rip(0x05, wrapper_rva_); // lea rax, [rip + wrapper]
    size_t lea_position_after = stub.size();

    std::print("DEBUG: LEA bytes: ");
    for (size_t i = lea_position_before; i < lea_position_after; ++i) {
        std::print("{:02X} ", stub[i]);
    }
    std::println("");

    stub.insert(stub.end(), { 0xFF, 0xD0 }); // call rax
    stub.insert(stub.end(), { 0x48, 0x8B, 0x03 }); // mov rax, [rbx]

    stub.insert(stub.end(), { 0x48, 0x81, 0xC4, 0x00, 0x00, 0x00, 0x00 });
    byte_io::write_u32_le_at(stub, stub.size() - 4, total_size);

    stub.insert(stub.end(), {
        0x41, 0x5B,                     // pop r11
        0x41, 0x5A,                     // pop r10
        0x41, 0x59,                     // pop r9
        0x41, 0x58,                     // pop r8
        0x5A,                           // pop rdx
        0x59,                           // pop rcx
        0x5B                            // pop rbx
        });

    stub.push_back(0xC3); // ret

    std::println("Generated trampoline stub size: {} bytes", stub.size());

    std::print("Stub bytes: ");
    for (auto b : stub) {
        std::print("{:02X} ", b);
    }
    std::println();

    new_content.insert(new_content.end(), stub.begin(), stub.end());

    uint32_t file_align = pe_.optional_header().file_alignment();
    uint32_t section_align = pe_.optional_header().section_alignment();
    uint32_t new_raw_size = alignment::align_up(static_cast<uint32_t>(new_content.size()), file_align);
    uint32_t new_virtual_size = alignment::align_up(static_cast<uint32_t>(new_content.size()), section_align);

    std::println("New section sizes - Raw: 0x{:X}, Virtual: 0x{:X}", new_raw_size, new_virtual_size);

    virtualized_section->content(new_content);
    virtualized_section->size(new_raw_size);
    virtualized_section->virtual_size(new_virtual_size);

    int32_t jmp_rel = static_cast<int32_t>(stub_rva - (fn_rva + 5));

    std::println("Jump from RVA 0x{:X} to 0x{:X}, relative offset: 0x{:X}",
        fn_rva, stub_rva, static_cast<uint32_t>(jmp_rel));

    std::vector<uint8_t> jmp_patch = {
        0xE9,
        static_cast<uint8_t>(jmp_rel & 0xFF),
        static_cast<uint8_t>((jmp_rel >> 8) & 0xFF),
        static_cast<uint8_t>((jmp_rel >> 16) & 0xFF),
        static_cast<uint8_t>((jmp_rel >> 24) & 0xFF)
    };

    pe_.patch_address(fn_rva, jmp_patch, LIEF::Binary::VA_TYPES::RVA);

    uint32_t fn_size = end_rva - fn_rva;
    if (fn_size > 5) {
        std::vector<uint8_t> nops(fn_size - 5, 0x90);
        pe_.patch_address(fn_rva + 5, nops, LIEF::Binary::VA_TYPES::RVA);
    }

    std::println("Successfully patched function - calls embedded interpreter at 0x{:X}", interpreter_va);
    return true;
}
