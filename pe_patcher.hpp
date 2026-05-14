#pragma once

#include <LIEF/LIEF.hpp>
#include <memory>
#include <utility>
#include <string>

class pe_patcher {
public:
    pe_patcher(const std::string& input_path, const std::string& output, uint32_t target_rva = 0x1950, uint32_t target_size = 0x12);
private:
    std::string section_name = ".nctrn";
    bool vm_section_created_ = false;
    uint32_t interpreter_rva_ = 0;
    uint32_t wrapper_rva_ = 0;
    uint32_t wrapper_offset_ = 0;
    std::unique_ptr<LIEF::PE::Binary> pe;
    const std::string output_path;
    std::vector<uint8_t> bytecode;
    uint32_t bytecode_size_ = 0;

    uint32_t add_vm_section(const std::vector<uint8_t>& bytecode);
    std::vector<uint8_t> get_code_at_rva(uint32_t function_rva, uint32_t end_rva);
    std::vector<std::vector<uint8_t>> get_code_at_marker();
    std::vector<std::pair<uint32_t, uint32_t>> grab_rvas_from_markers();
    std::vector<std::pair<uint32_t, uint32_t>> grab_rvas_from_pdb();
    bool virtualize_region(uint32_t target_rva, uint32_t target_size, uint64_t image_base, uint32_t image_size);
    bool patch_function(uint32_t function_rva, uint32_t end_rva, uint32_t bytecode_rva, uint32_t bytecode_size);
    bool overwrite_region(uint32_t start_rva, uint32_t end_rva, const std::vector<uint8_t>& replacement);
    bool output_pe();
};

