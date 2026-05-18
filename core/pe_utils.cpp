#include "pe_utils.hpp"

#include <algorithm>
#include <stdexcept>

#include "byte_io.hpp"

namespace pe_utils {

const uint8_t* resolve_direct_jmp_thunk(const uint8_t* ptr) {
    for (uint32_t i = 0; i < 4 && ptr && ptr[0] == 0xE9; ++i) {
        int32_t rel = byte_io::read_i32_le(ptr + 1);
        ptr = ptr + 5 + rel;
    }

    return ptr;
}

LIEF::PE::Section* find_section_containing_rva(LIEF::PE::Binary& pe, uint32_t rva) {
    for (auto& section : pe.sections()) {
        uint32_t start = static_cast<uint32_t>(section.virtual_address());
        uint32_t size = (std::max)(static_cast<uint32_t>(section.virtual_size()),
                                   static_cast<uint32_t>(section.content().size()));
        uint32_t end = start + size;
        if (rva >= start && rva < end) {
            return &section;
        }
    }

    return nullptr;
}

bool read_rva_bytes(
    LIEF::PE::Binary& pe,
    uint32_t rva,
    uint32_t count,
    std::vector<uint8_t>& bytes) {
    auto* section = find_section_containing_rva(pe, rva);
    if (!section) {
        return false;
    }

    auto content = section->content();
    uint32_t section_rva = static_cast<uint32_t>(section->virtual_address());
    uint32_t offset = rva - section_rva;
    if (offset > content.size() || count > content.size() - offset) {
        return false;
    }

    bytes.assign(content.begin() + offset, content.begin() + offset + count);
    return true;
}

uint32_t resolve_direct_jmp_thunk_rva(LIEF::PE::Binary& pe, uint32_t rva) {
    uint32_t current = rva;

    for (uint32_t depth = 0; depth < 8; ++depth) {
        std::vector<uint8_t> bytes;
        if (!read_rva_bytes(pe, current, 5, bytes) || bytes[0] != 0xE9) {
            break;
        }

        int32_t rel = byte_io::read_i32_le(bytes.data() + 1);
        uint32_t target = static_cast<uint32_t>(
            static_cast<int64_t>(current) + 5 + static_cast<int64_t>(rel));
        if (target == current || !find_section_containing_rva(pe, target)) {
            break;
        }

        current = target;
    }

    return current;
}

std::string choose_available_section_name(LIEF::PE::Binary& pe, const std::string& preferred) {
    if (!pe.get_section(preferred)) {
        return preferred;
    }

    for (uint32_t i = 0; i < 100; ++i) {
        std::string candidate = preferred + std::to_string(i);
        if (candidate.size() > 8) {
            candidate = preferred.substr(0, 8 - std::to_string(i).size()) + std::to_string(i);
        }
        if (!pe.get_section(candidate)) {
            return candidate;
        }
    }

    throw std::runtime_error("No available PE section name for VM blob");
}

} // namespace pe_utils
