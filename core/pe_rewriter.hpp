#pragma once

#include <LIEF/LIEF.hpp>
#include <cstdint>
#include <string>
#include <vector>

class pe_rewriter {
public:
    explicit pe_rewriter(LIEF::PE::Binary& pe, std::string section_name = ".nctrn");

    uint32_t add_vm_section(const std::vector<uint8_t>& bytecode);
    bool patch_function(uint32_t function_rva, uint32_t end_rva, uint32_t bytecode_rva, uint32_t bytecode_size);

private:
    LIEF::PE::Binary& pe_;
    std::string section_name_;
    bool vm_section_created_ = false;
    uint32_t interpreter_rva_ = 0;
    uint32_t wrapper_rva_ = 0;
    uint32_t wrapper_offset_ = 0;
};
