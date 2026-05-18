#pragma once

#include <cstddef>
#include <cstdint>

namespace alignment {

constexpr uint32_t align_up(uint32_t value, uint32_t align) {
    return (value + align - 1) / align * align;
}

inline size_t align_up_size(size_t value, size_t align) {
    return (value + align - 1) / align * align;
}

} // namespace alignment
