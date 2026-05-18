#pragma once

#include "byte_io.hpp"
#include "common.hpp"

#include <cstdint>

#ifndef vm_inline
#define vm_inline __forceinline
#endif

extern "C" const uint8_t vm_native_call_bridge_code[];

namespace vm_utils {
    constexpr uint8_t VM_REG_INDEX_RSP = 7;
    constexpr uint8_t VM_REG_INDEX_RBP = 6;

    vm_inline uint64_t call_native_bridge(uint64_t target, vm_state& vm) {
        using bridge_fn = uint64_t(*)(uint64_t, uint64_t*);
        auto bridge = reinterpret_cast<bridge_fn>(const_cast<uint8_t*>(vm_native_call_bridge_code));
        return bridge(target, vm.regs);
    }

    vm_inline bool add_overflows_u32(uint32_t a, uint32_t b) {
        return a > 0xFFFFFFFFu - b;
    }

    vm_inline bool configure_chunked_code(vm_state& vm, const uint8_t* code, uint32_t physical_size) {
        if (!code || physical_size < vm_chunked_code_header_size) {
            return false;
        }

        uint32_t magic = byte_io::read_u32_le(code + 0);
        uint32_t version = byte_io::read_u32_le(code + 4);
        uint32_t logical_size = byte_io::read_u32_le(code + 8);
        uint32_t chunk_count = byte_io::read_u32_le(code + 12);

        if (magic != vm_chunked_code_magic || version != vm_chunked_code_version) {
            return false;
        }

        if (chunk_count == 0 || logical_size == 0) {
            return false;
        }

        uint32_t table_size = chunk_count * vm_chunked_code_descriptor_size;
        if (chunk_count > (0xFFFFFFFFu / vm_chunked_code_descriptor_size) ||
            add_overflows_u32(vm_chunked_code_header_size, table_size) ||
            vm_chunked_code_header_size + table_size > physical_size) {
            return false;
        }

        for (uint32_t i = 0; i < chunk_count; ++i) {
            uint32_t desc = vm_chunked_code_header_size + (i * vm_chunked_code_descriptor_size);
            uint32_t logical_start = byte_io::read_u32_le(code + desc + 0);
            uint32_t chunk_size = byte_io::read_u32_le(code + desc + 4);
            uint32_t data_offset = byte_io::read_u32_le(code + desc + 8);

            if (chunk_size == 0 ||
                add_overflows_u32(logical_start, chunk_size) ||
                logical_start + chunk_size > logical_size ||
                add_overflows_u32(data_offset, chunk_size) ||
                data_offset + chunk_size > physical_size) {
                return false;
            }
        }

        vm.code = const_cast<uint8_t*>(code);
        vm.code_capacity = physical_size;
        vm.code_size = logical_size;
        vm.code_is_chunked = true;
        vm.chunked_code_blob = code;
        vm.chunked_code_blob_size = physical_size;
        vm.chunk_count = chunk_count;
        return true;
    }

    vm_inline bool read_code_u8_at(const vm_state& vm, uint32_t offset, uint8_t& value) {
        if (offset >= vm.code_size) {
            return false;
        }

        if (!vm.code_is_chunked) {
            if (!vm.code) {
                return false;
            }
            value = vm.code[offset];
            return true;
        }

        if (!vm.chunked_code_blob) {
            return false;
        }

        for (uint32_t i = 0; i < vm.chunk_count; ++i) {
            uint32_t desc = vm_chunked_code_header_size + (i * vm_chunked_code_descriptor_size);
            uint32_t logical_start = byte_io::read_u32_le(vm.chunked_code_blob + desc + 0);
            uint32_t chunk_size = byte_io::read_u32_le(vm.chunked_code_blob + desc + 4);
            uint32_t data_offset = byte_io::read_u32_le(vm.chunked_code_blob + desc + 8);

            if (offset >= logical_start && offset < logical_start + chunk_size) {
                uint32_t in_chunk = offset - logical_start;
                if (data_offset + in_chunk >= vm.chunked_code_blob_size) {
                    return false;
                }
                value = vm.chunked_code_blob[data_offset + in_chunk];
                return true;
            }
        }

        return false;
    }

    vm_inline bool fetch_code_u8(vm_state& vm, uint8_t& value) {
        if (!read_code_u8_at(vm, vm.ip, value)) {
            return false;
        }
        ++vm.ip;
        return true;
    }

    vm_inline bool fetch_code_u32(vm_state& vm, uint32_t& value) {
        uint8_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        if (!fetch_code_u8(vm, b0) || !fetch_code_u8(vm, b1) ||
            !fetch_code_u8(vm, b2) || !fetch_code_u8(vm, b3)) {
            return false;
        }

        value = static_cast<uint32_t>(b0) |
                (static_cast<uint32_t>(b1) << 8) |
                (static_cast<uint32_t>(b2) << 16) |
                (static_cast<uint32_t>(b3) << 24);
        return true;
    }

    vm_inline bool fetch_code_i32(vm_state& vm, int32_t& value) {
        uint32_t raw = 0;
        if (!fetch_code_u32(vm, raw)) {
            return false;
        }
        value = static_cast<int32_t>(raw);
        return true;
    }

    vm_inline bool fetch_code_u64(vm_state& vm, uint64_t& value) {
        value = 0;
        for (uint32_t i = 0; i < 8; ++i) {
            uint8_t b = 0;
            if (!fetch_code_u8(vm, b)) {
                return false;
            }
            value |= static_cast<uint64_t>(b) << (i * 8);
        }
        return true;
    }

    vm_inline bool halt_vm(vm_state& vm) {
        vm.halted = true;
        return false;
    }

    vm_inline bool ensure_code_bytes(const vm_state& vm, uint32_t offset, uint32_t needed) {
        return !add_overflows_u32(offset, needed) && (offset + needed) <= vm.code_size;
    }

    vm_inline bool require_code_bytes(vm_state& vm, uint32_t needed) {
        if (!ensure_code_bytes(vm, vm.ip, needed)) {
            return halt_vm(vm);
        }
        return true;
    }

    vm_inline bool fetch_u8_or_halt(vm_state& vm, uint8_t& value) {
        if (!fetch_code_u8(vm, value)) {
            return halt_vm(vm);
        }
        return true;
    }

    vm_inline bool fetch_i32_or_halt(vm_state& vm, int32_t& value) {
        if (!fetch_code_i32(vm, value)) {
            return halt_vm(vm);
        }
        return true;
    }

    vm_inline bool fetch_u64_or_halt(vm_state& vm, uint64_t& value) {
        if (!fetch_code_u64(vm, value)) {
            return halt_vm(vm);
        }
        return true;
    }

    vm_inline bool ensure_memory_range(const vm_state& vm, uint32_t offset, uint32_t length) {
        if (!vm.memory) {
            return false;
        }
        return !add_overflows_u32(offset, length) && (offset + length) <= vm.memory_size;
    }

    vm_inline uint8_t* vm_memory_ptr(vm_state& vm, uint64_t address, uint32_t length) {
        if (!vm.memory) {
            return nullptr;
        }

        if (address < vm.memory_size &&
            !add_overflows_u32(static_cast<uint32_t>(address), length) &&
            static_cast<uint32_t>(address) + length <= vm.memory_size) {
            return vm.memory + static_cast<uint32_t>(address);
        }

        uint64_t memory_base = reinterpret_cast<uint64_t>(vm.memory);
        uint64_t memory_end = memory_base + vm.memory_size;
        if (address >= memory_base &&
            address <= memory_end &&
            length <= memory_end - address) {
            return reinterpret_cast<uint8_t*>(address);
        }

        return nullptr;
    }

    vm_inline bool ensure_stack_space(const vm_state& vm, uint64_t sp, uint32_t needed) {
        if (sp < needed) {
            return false;
        }
        return vm_memory_ptr(const_cast<vm_state&>(vm), sp - needed, needed) != nullptr;
    }

    vm_inline bool ensure_stack_read(const vm_state& vm, uint64_t sp, uint32_t needed) {
        return vm_memory_ptr(const_cast<vm_state&>(vm), sp, needed) != nullptr;
    }
}
