#pragma once

#include <LIEF/LIEF.hpp>
#include <memory>
#include <utility>
#include <string>
#include <vector>

class pe_rewriter;

class patcher {
public:
    explicit patcher(const std::string& input_path, const std::string& output, std::vector<std::pair<uint32_t, uint32_t>> targets);
    patcher(const std::string& input_path, const std::string& output, uint32_t target_rva = 0x1950, uint32_t target_size = 0x12);
    ~patcher();
private:
    std::unique_ptr<LIEF::PE::Binary> pe;
    const std::string output_path;
    std::unique_ptr<pe_rewriter> rewriter_;
    std::vector<uint8_t> bytecode;
    uint32_t bytecode_size_ = 0;

    std::vector<uint8_t> get_code_at_rva(uint32_t function_rva, uint32_t end_rva);
    std::vector<std::pair<uint32_t, uint32_t>> grab_rvas_from_markers();
    bool virtualize_region(uint32_t target_rva, uint32_t target_size, uint64_t image_base, uint32_t image_size);
    bool output_pe();
};

