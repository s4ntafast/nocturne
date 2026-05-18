#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace byte_io {
    __forceinline void zero_u64_array(uint64_t* buffer, uint32_t count) {
        if (!buffer) {
            return;
        }
        volatile uint64_t* p = buffer;
        for (uint32_t i = 0; i < count; ++i) {
            p[i] = 0ULL;
        }
    }

    __forceinline void zero_u8_array(uint8_t* buffer, uint32_t count) {
        if (!buffer) {
            return;
        }
        volatile uint8_t* p = buffer;
        for (uint32_t i = 0; i < count; ++i) {
            p[i] = 0U;
        }
    }

    __forceinline uint32_t read_u32_le(const uint8_t* ptr) {
        return static_cast<uint32_t>(ptr[0]) |
               (static_cast<uint32_t>(ptr[1]) << 8) |
               (static_cast<uint32_t>(ptr[2]) << 16) |
               (static_cast<uint32_t>(ptr[3]) << 24);
    }

    __forceinline int32_t read_i32_le(const uint8_t* ptr) {
        return static_cast<int32_t>(read_u32_le(ptr));
    }

    __forceinline uint64_t read_u64_le(const uint8_t* ptr) {
        return static_cast<uint64_t>(ptr[0]) |
               (static_cast<uint64_t>(ptr[1]) << 8) |
               (static_cast<uint64_t>(ptr[2]) << 16) |
               (static_cast<uint64_t>(ptr[3]) << 24) |
               (static_cast<uint64_t>(ptr[4]) << 32) |
               (static_cast<uint64_t>(ptr[5]) << 40) |
               (static_cast<uint64_t>(ptr[6]) << 48) |
               (static_cast<uint64_t>(ptr[7]) << 56);
    }

    __forceinline void write_u64_le(uint8_t* ptr, uint64_t value) {
        ptr[0] = static_cast<uint8_t>(value & 0xFFULL);
        ptr[1] = static_cast<uint8_t>((value >> 8) & 0xFFULL);
        ptr[2] = static_cast<uint8_t>((value >> 16) & 0xFFULL);
        ptr[3] = static_cast<uint8_t>((value >> 24) & 0xFFULL);
        ptr[4] = static_cast<uint8_t>((value >> 32) & 0xFFULL);
        ptr[5] = static_cast<uint8_t>((value >> 40) & 0xFFULL);
        ptr[6] = static_cast<uint8_t>((value >> 48) & 0xFFULL);
        ptr[7] = static_cast<uint8_t>((value >> 56) & 0xFFULL);
    }

    __forceinline void write_u32_le(uint8_t* ptr, uint32_t value) {
        ptr[0] = static_cast<uint8_t>(value & 0xFFU);
        ptr[1] = static_cast<uint8_t>((value >> 8) & 0xFFU);
        ptr[2] = static_cast<uint8_t>((value >> 16) & 0xFFU);
        ptr[3] = static_cast<uint8_t>((value >> 24) & 0xFFU);
    }

    __forceinline void write_i32_le(uint8_t* ptr, int32_t value) {
        write_u32_le(ptr, static_cast<uint32_t>(value));
    }

    __forceinline void append_u32_le(std::vector<uint8_t>& out, uint32_t value) {
        out.push_back(static_cast<uint8_t>(value & 0xFFU));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFU));
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xFFU));
        out.push_back(static_cast<uint8_t>((value >> 24) & 0xFFU));
    }

    __forceinline void write_u32_le_at(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
        write_u32_le(out.data() + offset, value);
    }

    __forceinline void write_i32_le_at(std::vector<uint8_t>& out, size_t offset, int32_t value) {
        write_i32_le(out.data() + offset, value);
    }

} // namespace byte_io
