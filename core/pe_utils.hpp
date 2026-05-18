#pragma once

#include <LIEF/LIEF.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace pe_utils {

const uint8_t* resolve_direct_jmp_thunk(const uint8_t* ptr);
LIEF::PE::Section* find_section_containing_rva(LIEF::PE::Binary& pe, uint32_t rva);
bool read_rva_bytes(LIEF::PE::Binary& pe, uint32_t rva, uint32_t count, std::vector<uint8_t>& bytes);
uint32_t resolve_direct_jmp_thunk_rva(LIEF::PE::Binary& pe, uint32_t rva);
std::string choose_available_section_name(LIEF::PE::Binary& pe, const std::string& preferred);

} // namespace pe_utils
