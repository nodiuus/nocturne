#include <print>
#include <format>
#include <Zydis/Zydis.h>
#include <algorithm>
#include <deque>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <vector>

#include "patcher.hpp"
#include "alignment.hpp"
#include "byte_io.hpp"
#include "pe_utils.hpp"
#include "pe_rewriter.hpp"
#include "disassembler.hpp"
#include "x86_translator.hpp"
#include "vm_interpreter.hpp"

static constexpr uint64_t vmp_marker_magic = 0x314B52414D504D56ull; // "VMPMARK1"

static bool is_padding_byte(uint8_t byte) {
    return byte == 0x00 || byte == 0xCC;
}

static uint32_t find_reachable_function_end_rva(
    LIEF::PE::Binary& pe,
    uint32_t start_rva,
    uint32_t limit_rva) {
    auto* section = pe_utils::find_section_containing_rva(pe, start_rva);
    if (!section || limit_rva <= start_rva) {
        return limit_rva;
    }

    auto content = section->content();
    uint32_t section_rva = static_cast<uint32_t>(section->virtual_address());
    uint32_t section_content_end = section_rva + static_cast<uint32_t>(content.size());
    limit_rva = (std::min)(limit_rva, section_content_end);
    if (limit_rva <= start_rva) {
        return limit_rva;
    }

    uint32_t start_offset = start_rva - section_rva;
    uint32_t max_size = limit_rva - start_rva;
    const uint8_t* code = content.data() + start_offset;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::vector<uint8_t> visited(max_size, 0);
    std::deque<uint32_t> worklist;
    worklist.push_back(0);

    uint32_t max_reachable_end = 0;

    while (!worklist.empty()) {
        uint32_t offset = worklist.front();
        worklist.pop_front();

        while (offset < max_size) {
            if (visited[offset]) {
                break;
            }
            visited[offset] = 1;

            if (offset != 0 && is_padding_byte(code[offset])) {
                break;
            }

            ZydisDecodedInstruction instr;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                    &decoder, code + offset, max_size - offset, &instr, operands))) {
                break;
            }

            uint32_t next_offset = offset + instr.length;
            max_reachable_end = (std::max)(max_reachable_end, next_offset);

            const bool is_ret = instr.meta.category == ZYDIS_CATEGORY_RET;
            const bool is_cond_branch = instr.meta.category == ZYDIS_CATEGORY_COND_BR;
            const bool is_uncond_branch = instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR;

            if (is_ret) {
                break;
            }

            if (is_cond_branch || is_uncond_branch) {
                for (uint8_t i = 0; i < instr.operand_count; ++i) {
                    const auto& op = operands[i];
                    if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !op.imm.is_relative) {
                        continue;
                    }

                    uint64_t target = 0;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                            &instr, &op, start_rva + offset, &target)) &&
                        target >= start_rva && target < limit_rva) {
                        worklist.push_back(static_cast<uint32_t>(target - start_rva));
                    }
                    break;
                }

                if (is_uncond_branch) {
                    break;
                }
            }

            offset = next_offset;
        }
    }

    if (max_reachable_end == 0) {
        return limit_rva;
    }

    return start_rva + max_reachable_end;
}

static std::vector<uint8_t> build_chunked_bytecode_blob(const std::vector<uint8_t>& flat, uint32_t chunk_size) {
    if (flat.empty()) {
        return {};
    }

    chunk_size = (std::max)(chunk_size, 1u);
    uint32_t logical_size = static_cast<uint32_t>(flat.size());
    uint32_t chunk_count = (logical_size + chunk_size - 1) / chunk_size;

    std::vector<uint8_t> chunked;
    chunked.reserve(vm_chunked_code_header_size +
                    (chunk_count * vm_chunked_code_descriptor_size) +
                    flat.size());

    byte_io::append_u32_le(chunked, vm_chunked_code_magic);
    byte_io::append_u32_le(chunked, vm_chunked_code_version);
    byte_io::append_u32_le(chunked, logical_size);
    byte_io::append_u32_le(chunked, chunk_count);
    chunked.resize(vm_chunked_code_header_size + (chunk_count * vm_chunked_code_descriptor_size), 0);

    // Store chunks in reverse physical order. The descriptor table maps them back
    // to the VM's logical address space, so relative jumps and calls still work.
    for (uint32_t physical = chunk_count; physical > 0; --physical) {
        uint32_t chunk_index = physical - 1;
        uint32_t logical_start = chunk_index * chunk_size;
        uint32_t current_size = (std::min)(chunk_size, logical_size - logical_start);
        uint32_t data_offset = static_cast<uint32_t>(chunked.size());

        chunked.insert(chunked.end(),
                       flat.begin() + logical_start,
                       flat.begin() + logical_start + current_size);

        size_t desc = vm_chunked_code_header_size +
                      (static_cast<size_t>(chunk_index) * vm_chunked_code_descriptor_size);
        byte_io::write_u32_le_at(chunked, desc + 0, logical_start);
        byte_io::write_u32_le_at(chunked, desc + 4, current_size);
        byte_io::write_u32_le_at(chunked, desc + 8, data_offset);
    }

    return chunked;
}

patcher::patcher(const std::string& input_path, const std::string& output, std::vector<std::pair<uint32_t, uint32_t>> targets)
    : pe(LIEF::PE::Parser::parse(input_path)),
    output_path(output)
{
    if (!pe) {
        throw std::runtime_error("Failed to load input PE file");
    }
    if (targets.empty()) {
        throw std::runtime_error("No functions selected");
    }

    rewriter_ = std::make_unique<pe_rewriter>(*pe);
    uint64_t image_base = pe->imagebase();
    uint32_t image_size = 0;
    uint32_t section_align = pe->optional_header().section_alignment();
    for (const auto& sect : pe->sections()) {
        uint32_t end = static_cast<uint32_t>(sect.virtual_address() + sect.virtual_size());
        if (end > image_size) {
            image_size = end;
        }
    }
    image_size = alignment::align_up(image_size, section_align);

    for (auto [start, end] : targets) {
        if (end <= start || end - start < 5) {
            throw std::runtime_error("Selected function must contain at least 5 bytes for the entry jump");
        }

        uint32_t size = end - start;
        if (!virtualize_region(start, size, image_base, image_size)) {
            throw std::runtime_error(std::format("Failed to virtualize target RVA=0x{:X}", start));
        }

        std::println("Successfully virtualized target RVA=0x{:X}", start);
    }

    output_pe();
}

patcher::patcher(const std::string& input_path, const std::string& output, uint32_t target_rva, uint32_t target_size)
    : pe(LIEF::PE::Parser::parse(input_path)),
      output_path(output),
      rewriter_(std::make_unique<pe_rewriter>(*pe))
    {

    uint64_t image_base = pe->imagebase();
    uint32_t image_size = 0;
    uint32_t section_align = pe->optional_header().section_alignment();
    for (const auto& sect : pe->sections()) {
        uint32_t end = static_cast<uint32_t>(sect.virtual_address() + sect.virtual_size());
        if (end > image_size) {
            image_size = end;
        }
    }
    image_size = alignment::align_up(image_size, section_align);

    if (target_rva == 0 && target_size == 0) {
        auto targets = grab_rvas_from_markers();
        if (targets.empty()) {
            std::println("No VMP marker records found; aborting patch.");
            return;
        }

        std::println("Found {} VMP marker target(s)", targets.size());
        for (auto [rva, size] : targets) {
            std::println("Virtualizing marked function RVA=0x{:X}, size=0x{:X}", rva, size);
            if (!virtualize_region(rva, size, image_base, image_size)) {
                std::println("Failed to virtualize marked function RVA=0x{:X}", rva);
                return;
            }
        }

        output_pe();
        return;
    }

    if (!virtualize_region(target_rva, target_size, image_base, image_size)) {
        return;
    }

    output_pe();
}

patcher::~patcher() = default;

bool patcher::virtualize_region(uint32_t target_rva, uint32_t target_size, uint64_t image_base, uint32_t image_size) {
    std::vector<uint8_t> opcodes = get_code_at_rva(target_rva, target_rva + target_size);
    std::println("Extracted {} bytes", opcodes.size());
    
    disassembler dumper;
    dumper.dump_x86_assembly(opcodes.data(), opcodes.size(), "assembly dump");

    auto vm = std::make_unique<vm_state>();
    std::vector<uint8_t> vm_code_buffer(vm_max_code_size, 0);
    std::vector<uint8_t> vm_memory_buffer(vm_memory_size, 0);
    vm_initialize_state(*vm, vm_code_buffer.data(), static_cast<uint32_t>(vm_code_buffer.size()), vm_memory_buffer.data(), static_cast<uint32_t>(vm_memory_buffer.size()));
    
    uint64_t base_address = image_base + target_rva;
    x86_translator translator(*vm, base_address, image_base, image_size);
    
    if (!translator.translate_function(opcodes.data(), opcodes.size())) {
        std::println("Translator failed to process target function.");
        return false;
    }

    bytecode_size_ = vm->code_size;
    dumper.dump_vm_bytecode(vm->code, bytecode_size_, "TEST 5");
    bool has_native_call = false;
    for (uint32_t i = 0; i < bytecode_size_; ++i) {
        if (vm->code[i] == op_call_native ||
            vm->code[i] == op_call_native_indirect ||
            vm->code[i] == op_call_native_mem ||
            vm->code[i] == op_call_native_reg) {
            has_native_call = true;
            break;
        }
    }

    if (!has_native_call) {
        run_advanced_vm(*vm);
        printf("Final: EAX (r0) = %llu, EBX (r1) = %llu, ECX (r2) = %llu\n",
            vm->regs[0], vm->regs[1], vm->regs[2]);
    } else {
        std::println("Skipping VM execution: bytecode contains native calls.");
    }

    bytecode.clear();
    bytecode.reserve(bytecode_size_);
    for (uint32_t i = 0; i < bytecode_size_; ++i) {
        std::printf("%02x ", vm->code[i]);
        bytecode.push_back(vm->code[i]);
    }
    std::println();

    if (bytecode.empty()) {
        std::println("No VM bytecode generated; aborting patch.");
        return false;
    }

    uint32_t flat_bytecode_size = bytecode_size_;
    bytecode = build_chunked_bytecode_blob(bytecode, 0x20);
    bytecode_size_ = static_cast<uint32_t>(bytecode.size());
    std::println("Chunked VM bytecode: logical={} bytes, physical={} bytes, chunks={}",
                 flat_bytecode_size,
                 bytecode_size_,
                 (flat_bytecode_size + 0x1F) / 0x20);

    uint32_t bytecode_rva = rewriter_->add_vm_section(bytecode);
    if (bytecode_rva == 0) {
        std::println("Failed to add VM section; aborting patch.");
        return false;
    }
    if (!rewriter_->patch_function(target_rva, target_rva + target_size, bytecode_rva, bytecode_size_)) {
        return false;
    }
    return true;
}

std::vector<std::pair<uint32_t, uint32_t>> patcher::grab_rvas_from_markers() {
    auto* marker_section = pe->get_section(".mark");
    if (!marker_section) {
        marker_section = pe->get_section(".vmpm");
    }
    if (!marker_section) {
        std::println("Marker section .mark/.vmpm not found.");
        return {};
    }

    auto marker_content = marker_section->content();
    uint64_t image_base = pe->imagebase();

    std::vector<uint32_t> target_rvas;
    for (size_t offset = 0; offset + 16 <= marker_content.size(); offset += 8) {
        uint64_t magic = byte_io::read_u64_le(marker_content.data() + offset);
        if (magic != vmp_marker_magic) {
            continue;
        }

        uint64_t target = byte_io::read_u64_le(marker_content.data() + offset + 8);
        uint64_t rva64 = target;
        if (target >= image_base) {
            rva64 = target - image_base;
        }

        if (rva64 == 0 || rva64 > (std::numeric_limits<uint32_t>::max)()) {
            continue;
        }

        uint32_t raw_rva = static_cast<uint32_t>(rva64);
        uint32_t resolved_rva = pe_utils::resolve_direct_jmp_thunk_rva(*pe, raw_rva);
        if (resolved_rva != raw_rva) {
            std::println("Resolved marker thunk RVA 0x{:X} -> 0x{:X}", raw_rva, resolved_rva);
        }

        target_rvas.push_back(resolved_rva);
    }

    std::sort(target_rvas.begin(), target_rvas.end());
    target_rvas.erase(std::unique(target_rvas.begin(), target_rvas.end()), target_rvas.end());

    std::vector<std::pair<uint32_t, uint32_t>> regions;
    for (uint32_t rva : target_rvas) {
        uint32_t section_start = 0;
        uint32_t section_end = 0;

        for (const auto& section : pe->sections()) {
            uint32_t start = static_cast<uint32_t>(section.virtual_address());
            uint32_t size = (std::max)(static_cast<uint32_t>(section.virtual_size()),
                                       static_cast<uint32_t>(section.content().size()));
            uint32_t end = start + size;
            if (rva >= start && rva < end) {
                section_start = start;
                section_end = end;
                break;
            }
        }

        if (section_end == 0) {
            std::println("Skipping marker RVA 0x{:X}: no containing section", rva);
            continue;
        }

        uint32_t next_rva = section_end;
        for (uint32_t other : target_rvas) {
            if (other > rva && other < next_rva && other >= section_start && other < section_end) {
                next_rva = other;
            }
        }

        if (next_rva <= rva) {
            std::println("Skipping marker RVA 0x{:X}: invalid computed size", rva);
            continue;
        }

        uint32_t decoded_end = find_reachable_function_end_rva(*pe, rva, next_rva);
        if (decoded_end > rva && decoded_end < next_rva) {
            std::println("Trimmed marker RVA 0x{:X}: region 0x{:X} -> decoded function size 0x{:X}",
                         rva,
                         next_rva - rva,
                         decoded_end - rva);
            next_rva = decoded_end;
        }

        regions.push_back({ rva, next_rva - rva });
    }

    return regions;
}

std::vector<uint8_t> patcher::get_code_at_rva(uint32_t function_rva, uint32_t end_rva) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    LIEF::PE::Section* code_section = nullptr;
    for (auto& section : pe->sections()) {
        uint32_t section_rva = static_cast<uint32_t>(section.virtual_address());
        uint32_t section_size = static_cast<uint32_t>((std::max)(
            static_cast<uint64_t>(section.virtual_size()),
            static_cast<uint64_t>(section.content().size())));
        uint32_t section_end = section_rva + section_size;

        if (function_rva >= section_rva && function_rva < section_end) {
            code_section = &section;
            break;
        }
    }

    if (!code_section) {
        std::println("Could not find a section containing RVA 0x{:X}", function_rva);
        return {};
    }

    auto section_content = code_section->content();
    auto section_rva = static_cast<uint32_t>(code_section->virtual_address());
    uint32_t section_end_rva = section_rva + static_cast<uint32_t>(section_content.size());
    end_rva = (std::min)(end_rva, section_end_rva);

    std::println("Extracting code from {}: RVA 0x{:X}..0x{:X}",
                 code_section->name(),
                 function_rva,
                 end_rva);

    std::vector<uint8_t> all_opcodes;

    while (function_rva < end_rva) {
        uint32_t section_offset = function_rva - section_rva;

        if (section_offset >= section_content.size()) {
            break;
        }

        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
            section_content.data() + section_offset,
            end_rva - function_rva,
            &instr, operands))) {

            for (size_t i = 0; i < instr.length; ++i) {
                all_opcodes.push_back(section_content[section_offset + i]);
            }

            function_rva += instr.length;
        }
        else {
            all_opcodes.push_back(section_content[section_offset]);
            function_rva += 1;
        }
    }

    return all_opcodes;
}

bool patcher::output_pe() {
    for (const char* marker_name : { ".mark", ".vmpm" }) {
        if (auto* existing = pe->get_section(marker_name)) {
            pe->remove_section(existing->name().c_str());
        }
    }

    pe->write(output_path);
    return true;
}
