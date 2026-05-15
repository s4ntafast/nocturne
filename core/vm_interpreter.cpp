#include "vm_interpreter.hpp"
#include "common.hpp"
#include "junk.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <intrin.h>

#pragma section(".vmb$a", read, execute)
#pragma section(".vmb$code", read, execute)
#pragma section(".vmb$m", read, execute)
#pragma section(".vmb$z", read, execute)
#pragma comment(linker, "/SECTION:.vmb,ERW")

extern "C" {
extern __declspec(allocate(".vmb$a")) const uint8_t __vmb_blob_start = 0;
extern __declspec(allocate(".vmb$z")) const uint8_t __vmb_blob_end = 0;
}

#pragma code_seg(push, ".vmb$m")

extern "C" __declspec(allocate(".vmb$m")) __declspec(align(16)) const uint8_t vm_native_call_bridge_code[] = {
    0x48, 0x83, 0xEC, 0x38,                   // sub rsp, 0x38
    0x48, 0x89, 0x54, 0x24, 0x20,             // mov [rsp+0x20], rdx
    0x48, 0x89, 0x4C, 0x24, 0x28,             // mov [rsp+0x28], rcx
    0x48, 0x8B, 0x02,                         // mov rax, [rdx]
    0x48, 0x8B, 0x4A, 0x10,                   // mov rcx, [rdx+0x10]
    0x4C, 0x8B, 0x42, 0x40,                   // mov r8,  [rdx+0x40]
    0x4C, 0x8B, 0x4A, 0x48,                   // mov r9,  [rdx+0x48]
    0x4C, 0x8B, 0x52, 0x50,                   // mov r10, [rdx+0x50]
    0x4C, 0x8B, 0x5A, 0x58,                   // mov r11, [rdx+0x58]
    0x48, 0x8B, 0x52, 0x18,                   // mov rdx, [rdx+0x18]
    0xFF, 0x54, 0x24, 0x28,                   // call qword ptr [rsp+0x28]
    0x4C, 0x89, 0x5C, 0x24, 0x30,             // mov [rsp+0x30], r11
    0x4C, 0x8B, 0x5C, 0x24, 0x20,             // mov r11, [rsp+0x20]
    0x49, 0x89, 0x03,                         // mov [r11], rax
    0x49, 0x89, 0x4B, 0x10,                   // mov [r11+0x10], rcx
    0x49, 0x89, 0x53, 0x18,                   // mov [r11+0x18], rdx
    0x4D, 0x89, 0x43, 0x40,                   // mov [r11+0x40], r8
    0x4D, 0x89, 0x4B, 0x48,                   // mov [r11+0x48], r9
    0x4D, 0x89, 0x53, 0x50,                   // mov [r11+0x50], r10
    0x4C, 0x8B, 0x54, 0x24, 0x30,             // mov r10, [rsp+0x30]
    0x4D, 0x89, 0x53, 0x58,                   // mov [r11+0x58], r10
    0x48, 0x83, 0xC4, 0x38,                   // add rsp, 0x38
    0xC3                                      // ret
};

#ifdef vm_interpreter_trace
#include <cstdio>
#define vm_trace(...) std::printf(__VA_ARGS__)
#else
#define vm_trace(...) ((void)0)
#endif

#define vm_inline __forceinline

template<bool enable>
vm_inline void vm_trace_helper(const char* fmt, ...) {
    if constexpr (enable) {
        va_list args;
        va_start(args, fmt);
        std::vprintf(fmt, args);
        va_end(args);
    }
}

namespace {
    constexpr uint8_t VM_REG_INDEX_RSP = 7;
    constexpr uint8_t VM_REG_INDEX_RBP = 6;
    constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550; // PE\0\0
    constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;

    __declspec(noinline) void zero_u64_array(uint64_t* buffer, uint32_t count) {
        if (!buffer) {
            return;
        }
        volatile uint64_t* p = buffer;
        for (uint32_t i = 0; i < count; ++i) {
            p[i] = 0ULL;
        }
    }

    __declspec(noinline) void zero_u8_array(uint8_t* buffer, uint32_t count) {
        if (!buffer) {
            return;
        }
        volatile uint8_t* p = buffer;
        for (uint32_t i = 0; i < count; ++i) {
            p[i] = 0U;
        }
    }

    vm_inline uint64_t read_u64_le(const uint8_t* ptr) {
        return static_cast<uint64_t>(ptr[0]) |
               (static_cast<uint64_t>(ptr[1]) << 8) |
               (static_cast<uint64_t>(ptr[2]) << 16) |
               (static_cast<uint64_t>(ptr[3]) << 24) |
               (static_cast<uint64_t>(ptr[4]) << 32) |
               (static_cast<uint64_t>(ptr[5]) << 40) |
               (static_cast<uint64_t>(ptr[6]) << 48) |
               (static_cast<uint64_t>(ptr[7]) << 56);
    }

    vm_inline int64_t read_i64_le(const uint8_t* ptr) {
        return static_cast<int64_t>(read_u64_le(ptr));
    }

    vm_inline void write_u64_le(uint8_t* ptr, uint64_t value) {
        ptr[0] = static_cast<uint8_t>(value & 0xFFULL);
        ptr[1] = static_cast<uint8_t>((value >> 8) & 0xFFULL);
        ptr[2] = static_cast<uint8_t>((value >> 16) & 0xFFULL);
        ptr[3] = static_cast<uint8_t>((value >> 24) & 0xFFULL);
        ptr[4] = static_cast<uint8_t>((value >> 32) & 0xFFULL);
        ptr[5] = static_cast<uint8_t>((value >> 40) & 0xFFULL);
        ptr[6] = static_cast<uint8_t>((value >> 48) & 0xFFULL);
        ptr[7] = static_cast<uint8_t>((value >> 56) & 0xFFULL);
    }

    vm_inline uint32_t read_u32_le(const uint8_t* ptr) {
        return static_cast<uint32_t>(ptr[0]) |
               (static_cast<uint32_t>(ptr[1]) << 8) |
               (static_cast<uint32_t>(ptr[2]) << 16) |
               (static_cast<uint32_t>(ptr[3]) << 24);
    }

    vm_inline int32_t read_i32_le(const uint8_t* ptr) {
        return static_cast<int32_t>(read_u32_le(ptr));
    }

    vm_inline void write_u32_le(uint8_t* ptr, uint32_t value) {
        ptr[0] = static_cast<uint8_t>(value & 0xFFU);
        ptr[1] = static_cast<uint8_t>((value >> 8) & 0xFFU);
        ptr[2] = static_cast<uint8_t>((value >> 16) & 0xFFU);
        ptr[3] = static_cast<uint8_t>((value >> 24) & 0xFFU);
    }

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

        uint32_t magic = read_u32_le(code + 0);
        uint32_t version = read_u32_le(code + 4);
        uint32_t logical_size = read_u32_le(code + 8);
        uint32_t chunk_count = read_u32_le(code + 12);

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
            uint32_t logical_start = read_u32_le(code + desc + 0);
            uint32_t chunk_size = read_u32_le(code + desc + 4);
            uint32_t data_offset = read_u32_le(code + desc + 8);

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
            uint32_t logical_start = read_u32_le(vm.chunked_code_blob + desc + 0);
            uint32_t chunk_size = read_u32_le(vm.chunked_code_blob + desc + 4);
            uint32_t data_offset = read_u32_le(vm.chunked_code_blob + desc + 8);

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

    vm_inline bool ensure_code_bytes(const vm_state& vm, uint32_t offset, uint32_t needed) {
        return !add_overflows_u32(offset, needed) && (offset + needed) <= vm.code_size;
    }

    vm_inline bool ensure_memory_range(const vm_state& vm, uint32_t offset, uint32_t length) {
        if (!vm.memory) {
            return false;
        }
        return (offset + length) <= vm.memory_size;
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

    vm_inline uint64_t get_process_image_base_runtime() {
#if defined(_MSC_VER) && defined(_M_X64)
        uint64_t peb = __readgsqword(0x60);
        if (!peb) {
            return 0;
        }
        return *reinterpret_cast<uint64_t*>(peb + 0x10);
#else
        return 0;
#endif
    }

    vm_inline uint64_t get_containing_image_base_runtime(uint64_t address) {
#if defined(_MSC_VER) && defined(_M_X64)
        uint64_t peb = __readgsqword(0x60);
        if (!peb || !address) {
            return 0;
        }

        uint64_t ldr = *reinterpret_cast<uint64_t*>(peb + 0x18);
        if (!ldr) {
            return 0;
        }

        uint64_t list_head = ldr + 0x20; // PEB_LDR_DATA.InMemoryOrderModuleList
        uint64_t link = *reinterpret_cast<uint64_t*>(list_head);
        for (uint32_t i = 0; i < 256 && link && link != list_head; ++i) {
            uint64_t entry = link - 0x10; // LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks
            uint64_t dll_base = *reinterpret_cast<uint64_t*>(entry + 0x30);
            uint32_t size_of_image = *reinterpret_cast<uint32_t*>(entry + 0x40);
            if (dll_base && size_of_image &&
                address >= dll_base &&
                address < (dll_base + static_cast<uint64_t>(size_of_image))) {
                return dll_base;
            }
            link = *reinterpret_cast<uint64_t*>(link);
        }
#else
        (void)address;
#endif
        return 0;
    }

    vm_inline uint64_t get_image_base_runtime() {
        uint64_t containing_base = get_containing_image_base_runtime(
            reinterpret_cast<uint64_t>(&__vmb_blob_start));
        if (containing_base) {
            return containing_base;
        }
        return get_process_image_base_runtime();
    }

    vm_inline uint32_t get_image_size_runtime(uint64_t image_base) {
        if (!image_base) {
            return 0;
        }
        const uint8_t* base = reinterpret_cast<const uint8_t*>(image_base);
        const uint16_t mz = *reinterpret_cast<const uint16_t*>(base);
        if (mz != IMAGE_DOS_SIGNATURE) {
            return 0;
        }
        const int32_t e_lfanew = *reinterpret_cast<const int32_t*>(base + 0x3C);
        if (e_lfanew <= 0) {
            return 0;
        }
        const uint32_t pe = *reinterpret_cast<const uint32_t*>(base + e_lfanew);
        if (pe != IMAGE_NT_SIGNATURE) {
            return 0;
        }
        const uint16_t magic = *reinterpret_cast<const uint16_t*>(base + e_lfanew + 0x18);
        if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            return 0;
        }
        return *reinterpret_cast<const uint32_t*>(base + e_lfanew + 0x18 + 0x38);
    }
}

vm_inline void vm_reset_state_internal(vm_state& vm) {
    zero_u64_array(vm.regs, static_cast<uint32_t>(vm_register_count));
    vm.ip = 0;
    vm.halted = false;
    zero_u8_array(vm.memory, vm.memory_size);
}

vm_inline void vm_initialize_state_internal(vm_state& vm, uint8_t* code_buffer, uint32_t code_capacity, uint8_t* memory_buffer, uint32_t memory_capacity) {
    vm.code = code_buffer;
    vm.code_capacity = code_capacity;
    vm.code_size = 0;
    vm.code_is_chunked = false;
    vm.chunked_code_blob = nullptr;
    vm.chunked_code_blob_size = 0;
    vm.chunk_count = 0;
    vm.memory = memory_buffer;
    vm.memory_size = memory_capacity;
    vm.image_base = 0;
    vm.image_size = 0;
    vm_reset_state_internal(vm);
}

/*
    TODO: replace massive switch statement with a handler table + implement a better flag system
*/

template<bool trace_enabled>
static vm_inline void run_vm_logic(vm_state& vm) {
    generator<500>::generate_junk();

    if (!vm.code || vm.code_size == 0 || !vm.memory || vm.memory_size == 0) {
        return;
    }

    if (!vm.code_is_chunked) {
        configure_chunked_code(vm, vm.code, vm.code_size);
    }

    vm.ip = 0;
    vm.halted = false;

    if (VM_REG_INDEX_RSP < vm_register_count) {
        vm.regs[VM_REG_INDEX_RSP] = reinterpret_cast<uint64_t>(vm.memory) + vm.memory_size;
    }
    if (VM_REG_INDEX_RBP < vm_register_count) {
        vm.regs[VM_REG_INDEX_RBP] = vm.regs[VM_REG_INDEX_RSP];
    }

    bool zero_flag = false;
    bool less_flag = false;
    bool greater_flag = false;

    int instruction_count = 0;
    const int MAX_INSTRUCTIONS = 1000000; 

    generator<20>::generate_junk();
    while (!vm.halted && vm.ip < vm.code_size && instruction_count < MAX_INSTRUCTIONS) {
        generator<20>::generate_junk();
        uint8_t op = 0;
        if (!fetch_code_u8(vm, op)) {
            vm.halted = true;
            break;
        }
        ++instruction_count;

        generator<10>::generate_junk();

        switch (op) {
        case op_mov_imm:
            if (!ensure_code_bytes(vm, vm.ip, 9)) { vm.halted = true; }
            else {
                uint8_t dst = 0;
                uint64_t imm = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u64(vm, imm)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = imm;
                        vm_trace_helper<trace_enabled>("MOV_IMM r%u = 0x%llX\n", dst, imm);
                    }
            }
            break;
        case op_mov_reg:
            if (!ensure_code_bytes(vm, vm.ip, 2)) { vm.halted = true; }
            else {
                uint8_t dst = 0, src = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, src)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || src >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = vm.regs[src];
                        vm_trace_helper<trace_enabled>("MOV_REG r%u = r%u (0x%llX)\n", dst, src, vm.regs[src]);
                    }
            }
            break;
        case op_add:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = vm.regs[a] + vm.regs[b];
                        vm_trace_helper<trace_enabled>("ADD r%u = r%u + r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_sub:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = vm.regs[a] - vm.regs[b];
                        vm_trace_helper<trace_enabled>("SUB r%u = r%u - r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_mul:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = vm.regs[a] * vm.regs[b];
                        vm_trace_helper<trace_enabled>("MUL r%u = r%u * r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_div:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        if (vm.regs[b] == 0) { vm.halted = true; }
                        else {
                            vm.regs[dst] = vm.regs[a] / vm.regs[b];
                            vm_trace_helper<trace_enabled>("DIV r%u = r%u / r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                        }
                    }
            }
            break;
        case op_and:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = vm.regs[a] & vm.regs[b];
                        vm_trace_helper<trace_enabled>("AND r%u = r%u & r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_or:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = vm.regs[a] | vm.regs[b];
                        vm_trace_helper<trace_enabled>("OR r%u = r%u | r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_xor:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = vm.regs[a] ^ vm.regs[b];
                        vm_trace_helper<trace_enabled>("XOR r%u = r%u ^ r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_not:
            if (!ensure_code_bytes(vm, vm.ip, 2)) { vm.halted = true; }
            else {
                uint8_t dst = 0, src = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, src)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || src >= vm_register_count) { vm.halted = true; }
                    else {
                        vm.regs[dst] = ~vm.regs[src];
                        vm_trace_helper<trace_enabled>("NOT r%u = ~r%u = 0x%llX\n", dst, src, vm.regs[dst]);
                    }
            }
            break;
        case op_shr:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t shift = vm.regs[b] & 0x3F;
                        vm.regs[dst] = vm.regs[a] >> shift;
                        vm_trace_helper<trace_enabled>("SHR r%u = r%u >> r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_shl:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t shift = vm.regs[b] & 0x3F;
                        vm.regs[dst] = vm.regs[a] << shift;
                        vm_trace_helper<trace_enabled>("SHL r%u = r%u << r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_sar:
            if (!ensure_code_bytes(vm, vm.ip, 3)) { vm.halted = true; }
            else {
                uint8_t dst = 0, a = 0, b = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t shift = vm.regs[b] & 0x3F;
                        int64_t value = static_cast<int64_t>(vm.regs[a]);
                        vm.regs[dst] = static_cast<uint64_t>(value >> shift);
                        vm_trace_helper<trace_enabled>("SAR r%u = r%u >> r%u = 0x%llX\n", dst, a, b, vm.regs[dst]);
                    }
            }
            break;
        case op_cmp:
            if (!ensure_code_bytes(vm, vm.ip, 2)) { vm.halted = true; }
            else {
                uint8_t a = 0, b = 0;
                if (!fetch_code_u8(vm, a) || !fetch_code_u8(vm, b)) { vm.halted = true; }
                else
                    if (a >= vm_register_count || b >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t va = vm.regs[a];
                        uint64_t vb = vm.regs[b];
                        zero_flag = (va == vb);
                        less_flag = (va < vb);
                        greater_flag = (va > vb);
                        vm_trace_helper<trace_enabled>("CMP r%u (0x%llX) vs r%u (0x%llX) -> Z:%d L:%d G:%d\n", a, va, b, vb, zero_flag, less_flag, greater_flag);
                    }
            }
            break;
        case op_jmp: 
        case op_jz: 
        case op_jnz:
        case op_jl: 
        case op_jg: 
        case op_jle: 
        case op_jge:
            if (!ensure_code_bytes(vm, vm.ip, 4)) { vm.halted = true; }
            else {
                int32_t offset = 0;
                if (!fetch_code_i32(vm, offset)) { vm.halted = true; }
                else {
                    uint32_t target = static_cast<uint32_t>(static_cast<int64_t>(vm.ip) + offset);
                    bool take = false;
                    if (op == op_jmp) take = true;
                    else if (op == op_jz)  take = zero_flag;
                    else if (op == op_jnz) take = !zero_flag;
                    else if (op == op_jl)  take = less_flag;
                    else if (op == op_jg)  take = greater_flag;
                    else if (op == op_jle) take = less_flag || zero_flag;
                    else if (op == op_jge) take = greater_flag || zero_flag;

                    if (take) {
                        if (target > vm.code_size) { vm.halted = true; }
                        else {
                            vm.ip = target;
                            vm_trace_helper<trace_enabled>("JUMP TAKEN to %u\n", vm.ip);
                        }
                    }
                    else {
                        vm_trace_helper<trace_enabled>("JUMP NOT TAKEN\n");
                    }
                }
            }
            break;
        case op_push:
            if (!ensure_code_bytes(vm, vm.ip, 1)) { vm.halted = true; }
            else {
                uint8_t src = 0;
                if (!fetch_code_u8(vm, src)) { vm.halted = true; }
                else
                    if (src >= vm_register_count || VM_REG_INDEX_RSP >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
                        if (!ensure_stack_space(vm, sp, 8)) { vm.halted = true; }
                        else {
                            sp -= 8;
                            write_u64_le(vm_memory_ptr(vm, sp, 8), vm.regs[src]);
                            vm_trace_helper<trace_enabled>("PUSH r%u (0x%llX) -> [RSP]=0x%llX\n", src, vm.regs[src], sp);
                        }
                    }
            }
            break;
        case op_pop:
            if (!ensure_code_bytes(vm, vm.ip, 1)) { vm.halted = true; }
            else {
                uint8_t dst = 0;
                if (!fetch_code_u8(vm, dst)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || VM_REG_INDEX_RSP >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
                        if (!ensure_stack_read(vm, sp, 8)) { vm.halted = true; }
                        else {
                            uint64_t value = read_u64_le(vm_memory_ptr(vm, sp, 8));
                            sp += 8;
                            vm.regs[dst] = value;
                            vm_trace_helper<trace_enabled>("POP -> r%u = 0x%llX (from [RSP]=0x%llX)\n", dst, value, sp);
                        }
                    }
            }
            break;
        case op_call:
            if (!ensure_code_bytes(vm, vm.ip, 4)) { vm.halted = true; }
            else {
                int32_t offset = 0;
                if (!fetch_code_i32(vm, offset)) { vm.halted = true; }
                else {
                    uint64_t return_addr = static_cast<uint64_t>(vm.ip);
                    if (VM_REG_INDEX_RSP >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
                        if (!ensure_stack_space(vm, sp, 8)) { vm.halted = true; }
                        else {
                            sp -= 8;
                            write_u64_le(vm_memory_ptr(vm, sp, 8), return_addr);
                            uint32_t target = static_cast<uint32_t>(static_cast<int64_t>(vm.ip) + offset);
                            if (target > vm.code_size) { vm.halted = true; }
                            else {
                                vm.ip = target;
                                vm_trace_helper<trace_enabled>("CALL -> return %llu, target %u\n", return_addr, target);
                            }
                        }
                    }
                }
            }
            break;
        case op_load_mem:
            if (!ensure_code_bytes(vm, vm.ip, 6)) { vm.halted = true; }
            else {
                uint8_t dst = 0, base = 0;
                int32_t offset = 0;
                if (!fetch_code_u8(vm, dst) || !fetch_code_u8(vm, base) || !fetch_code_i32(vm, offset)) { vm.halted = true; }
                else
                    if (dst >= vm_register_count || base >= vm_register_count) { vm.halted = true; }
                    else {
                        int64_t addr = static_cast<int64_t>(vm.regs[base]) + offset;
                        if (addr < 0) { vm.halted = true; }
                        else if (uint8_t* vm_ptr = vm_memory_ptr(vm, static_cast<uint64_t>(addr), 8)) {
                            vm.regs[dst] = read_u64_le(vm_ptr);
                            vm_trace_helper<trace_enabled>("LOAD_MEM r%u = [r%u + %d] -> 0x%llX\n", dst, base, offset, vm.regs[dst]);
                        }
                        else {
                            auto* ptr = reinterpret_cast<const uint8_t*>(static_cast<uint64_t>(addr));
                            vm.regs[dst] = read_u64_le(ptr);
                            vm_trace_helper<trace_enabled>("LOAD_MEM (native) r%u = [0x%llX] -> 0x%llX\n", dst, static_cast<uint64_t>(addr), vm.regs[dst]);
                        }
                    }
            }
            break;
        case op_store_mem:
            if (!ensure_code_bytes(vm, vm.ip, 6)) { vm.halted = true; }
            else {
                uint8_t base = 0, src = 0;
                int32_t offset = 0;
                if (!fetch_code_u8(vm, base) || !fetch_code_i32(vm, offset) || !fetch_code_u8(vm, src)) { vm.halted = true; }
                else
                    if (base >= vm_register_count || src >= vm_register_count) { vm.halted = true; }
                    else {
                        int64_t addr = static_cast<int64_t>(vm.regs[base]) + offset;
                        if (addr < 0) { vm.halted = true; }
                        else if (uint8_t* vm_ptr = vm_memory_ptr(vm, static_cast<uint64_t>(addr), 8)) {
                            write_u64_le(vm_ptr, vm.regs[src]);
                            vm_trace_helper<trace_enabled>("STORE_MEM [r%u + %d] = r%u (0x%llX)\n", base, offset, src, vm.regs[src]);
                        }
                        else {
                            auto* ptr = reinterpret_cast<uint8_t*>(static_cast<uint64_t>(addr));
                            write_u64_le(ptr, vm.regs[src]);
                            vm_trace_helper<trace_enabled>("STORE_MEM (native) [0x%llX] = r%u (0x%llX)\n", static_cast<uint64_t>(addr), src, vm.regs[src]);
                        }
                    }
            }
            break;
        case op_store_mem8:
            if (!ensure_code_bytes(vm, vm.ip, 6)) { vm.halted = true; }
            else {
                uint8_t base = 0, src = 0;
                int32_t offset = 0;
                if (!fetch_code_u8(vm, base) || !fetch_code_i32(vm, offset) || !fetch_code_u8(vm, src)) { vm.halted = true; }
                else
                    if (base >= vm_register_count || src >= vm_register_count) { vm.halted = true; }
                    else {
                        int64_t addr = static_cast<int64_t>(vm.regs[base]) + offset;
                        if (addr < 0) { vm.halted = true; }
                        else if (uint8_t* vm_ptr = vm_memory_ptr(vm, static_cast<uint64_t>(addr), 1)) {
                            *vm_ptr = static_cast<uint8_t>(vm.regs[src] & 0xFF);
                            vm_trace_helper<trace_enabled>("STORE_MEM8 [r%u + %d] = r%u low8\n", base, offset, src);
                        }
                        else {
                            auto* ptr = reinterpret_cast<uint8_t*>(static_cast<uint64_t>(addr));
                            *ptr = static_cast<uint8_t>(vm.regs[src] & 0xFF);
                            vm_trace_helper<trace_enabled>("STORE_MEM8 (native) [0x%llX] = r%u low8\n", static_cast<uint64_t>(addr), src);
                        }
                    }
            }
            break;
        case op_store_mem_zero128:
            if (!ensure_code_bytes(vm, vm.ip, 5)) { vm.halted = true; }
            else {
                uint8_t base = 0;
                int32_t offset = 0;
                if (!fetch_code_u8(vm, base) || !fetch_code_i32(vm, offset)) { vm.halted = true; }
                else
                    if (base >= vm_register_count) { vm.halted = true; }
                    else {
                        int64_t addr = static_cast<int64_t>(vm.regs[base]) + offset;
                        if (addr < 0) { vm.halted = true; }
                        else if (uint8_t* vm_ptr = vm_memory_ptr(vm, static_cast<uint64_t>(addr), 16)) {
                            for (uint32_t i = 0; i < 16; ++i) {
                                vm_ptr[i] = 0;
                            }
                            vm_trace_helper<trace_enabled>("STORE_MEM_ZERO128 [r%u + %d]\n", base, offset);
                        }
                        else {
                            auto* ptr = reinterpret_cast<uint8_t*>(static_cast<uint64_t>(addr));
                            for (uint32_t i = 0; i < 16; ++i) {
                                ptr[i] = 0;
                            }
                            vm_trace_helper<trace_enabled>("STORE_MEM_ZERO128 (native) [0x%llX]\n", static_cast<uint64_t>(addr));
                        }
                    }
            }
            break;
        case op_call_native:
            if (!ensure_code_bytes(vm, vm.ip, 8)) { vm.halted = true; }
            else {
                uint64_t target = 0;
                if (!fetch_code_u64(vm, target)) { vm.halted = true; }
                else {

                    uint64_t actual = target;
                    if (vm.image_base != 0 && vm.image_size != 0 && target < vm.image_size) {
                        actual = vm.image_base + target;
                    }

                    uint64_t ret = call_native_bridge(actual, vm);
                    vm.regs[0] = ret;
                    vm_trace_helper<trace_enabled>("CALL_NATIVE 0x%llX -> r0 = 0x%llX\n", actual, ret);
                }
            }
            break;
        case op_cmpxchg_mem64:
            if (!ensure_code_bytes(vm, vm.ip, 6)) { vm.halted = true; }
            else {
                uint8_t base = 0, src = 0;
                int32_t offset = 0;
                if (!fetch_code_u8(vm, base) || !fetch_code_i32(vm, offset) || !fetch_code_u8(vm, src)) { vm.halted = true; }
                else
                    if (base >= vm_register_count || src >= vm_register_count || VM_REG_INDEX_RSP >= vm_register_count) { vm.halted = true; }
                    else {
                        int64_t addr = static_cast<int64_t>(vm.regs[base]) + offset;
                        if (addr < 0) { vm.halted = true; }
                        else {
                            uint64_t expected = vm.regs[0];
                            uint64_t desired = vm.regs[src];
                            uint64_t old = 0;

                            if (uint8_t* vm_ptr = vm_memory_ptr(vm, static_cast<uint64_t>(addr), 8)) {
                                old = read_u64_le(vm_ptr);
                                if (old == expected) {
                                    write_u64_le(vm_ptr, desired);
                                }
                            }
                            else {
                                auto* ptr = reinterpret_cast<volatile long long*>(static_cast<uint64_t>(addr));
                                old = static_cast<uint64_t>(_InterlockedCompareExchange64(
                                    ptr,
                                    static_cast<long long>(desired),
                                    static_cast<long long>(expected)));
                            }

                            zero_flag = (old == expected);
                            less_flag = (expected < old);
                            greater_flag = (expected > old);
                            if (!zero_flag) {
                                vm.regs[0] = old;
                            }

                            vm_trace_helper<trace_enabled>(
                                "CMPXCHG_MEM64 [r%u + %d], r%u expected=0x%llX old=0x%llX Z:%d\n",
                                base, offset, src, expected, old, zero_flag);
                        }
                    }
            }
            break;
        case op_xchg_mem64:
            if (!ensure_code_bytes(vm, vm.ip, 6)) { vm.halted = true; }
            else {
                uint8_t base = 0, reg = 0;
                int32_t offset = 0;
                if (!fetch_code_u8(vm, base) || !fetch_code_i32(vm, offset) || !fetch_code_u8(vm, reg)) { vm.halted = true; }
                else
                    if (base >= vm_register_count || reg >= vm_register_count) { vm.halted = true; }
                    else {
                        int64_t addr = static_cast<int64_t>(vm.regs[base]) + offset;
                        if (addr < 0) { vm.halted = true; }
                        else {
                            uint64_t desired = vm.regs[reg];
                            uint64_t old = 0;

                            if (uint8_t* vm_ptr = vm_memory_ptr(vm, static_cast<uint64_t>(addr), 8)) {
                                old = read_u64_le(vm_ptr);
                                write_u64_le(vm_ptr, desired);
                            }
                            else {
                                auto* ptr = reinterpret_cast<volatile long long*>(static_cast<uint64_t>(addr));
                                old = static_cast<uint64_t>(_InterlockedExchange64(
                                    ptr,
                                    static_cast<long long>(desired)));
                            }

                            vm.regs[reg] = old;
                            vm_trace_helper<trace_enabled>(
                                "XCHG_MEM64 [r%u + %d], r%u old=0x%llX new=0x%llX\n",
                                base, offset, reg, old, desired);
                        }
                    }
            }
            break;
        case op_call_native_indirect:
            if (!ensure_code_bytes(vm, vm.ip, 8)) { vm.halted = true; }
            else {
                uint64_t target_slot = 0;
                if (!fetch_code_u64(vm, target_slot)) { vm.halted = true; }
                else {
                    uint64_t actual_slot = target_slot;
                    if (vm.image_base != 0 && vm.image_size != 0 && target_slot < vm.image_size) {
                        actual_slot = vm.image_base + target_slot;
                    }

                    uint64_t target = read_u64_le(reinterpret_cast<const uint8_t*>(static_cast<uintptr_t>(actual_slot)));
                    uint64_t ret = call_native_bridge(target, vm);
                    vm.regs[0] = ret;
                    vm_trace_helper<trace_enabled>("CALL_NATIVE_INDIRECT [0x%llX] -> r0 = 0x%llX\n", actual_slot, ret);
                }
            }
            break;
        case op_call_native_mem:
            if (!ensure_code_bytes(vm, vm.ip, 5)) { vm.halted = true; }
            else {
                uint8_t base = 0;
                int32_t offset = 0;
                if (!fetch_code_u8(vm, base) || !fetch_code_i32(vm, offset)) { vm.halted = true; }
                else
                    if (base >= vm_register_count) { vm.halted = true; }
                    else {
                        int64_t slot_addr = static_cast<int64_t>(vm.regs[base]) + offset;
                        if (slot_addr < 0) { vm.halted = true; }
                        else {
                            uint64_t target = 0;
                            if (uint8_t* vm_ptr = vm_memory_ptr(vm, static_cast<uint64_t>(slot_addr), 8)) {
                                target = read_u64_le(vm_ptr);
                            }
                            else {
                                target = read_u64_le(reinterpret_cast<const uint8_t*>(static_cast<uint64_t>(slot_addr)));
                            }

                            uint64_t ret = call_native_bridge(target, vm);
                            vm.regs[0] = ret;
                            vm_trace_helper<trace_enabled>("CALL_NATIVE_MEM [r%u + %d] -> r0 = 0x%llX\n", base, offset, ret);
                        }
                    }
            }
            break;
        case op_call_native_reg:
            if (!ensure_code_bytes(vm, vm.ip, 1)) { vm.halted = true; }
            else {
                uint8_t target_reg = 0;
                if (!fetch_code_u8(vm, target_reg)) { vm.halted = true; }
                else
                    if (target_reg >= vm_register_count) { vm.halted = true; }
                    else {
                        uint64_t target = vm.regs[target_reg];
                        if (vm.image_base != 0 && vm.image_size != 0 && target < vm.image_size) {
                            target += vm.image_base;
                        }

                        uint64_t ret = call_native_bridge(target, vm);
                        vm.regs[0] = ret;
                        vm_trace_helper<trace_enabled>("CALL_NATIVE_REG r%u=0x%llX -> r0 = 0x%llX\n", target_reg, target, ret);
                    }
            }
            break;
        case op_ret:
            if (VM_REG_INDEX_RSP >= vm_register_count) { vm.halted = true; }
            else {
                uint64_t& sp = vm.regs[VM_REG_INDEX_RSP];
                if (!ensure_stack_read(vm, sp, 8)) {
                    vm.halted = true;
                }
                else {
                    uint64_t return_addr = read_u64_le(vm_memory_ptr(vm, sp, 8));
                    sp += 8;
                    if (return_addr > vm.code_size) { vm.halted = true; }
                    else {
                        vm.ip = static_cast<uint32_t>(return_addr);
                        vm_trace_helper<trace_enabled>("RET to %u\n", vm.ip);
                    }
                }
            }
            break;
        case op_halt:
            vm.halted = true;
            vm_trace_helper<trace_enabled>("HALT\n");
            break;
        default:
            vm.halted = true;
            vm_trace_helper<trace_enabled>("UNKNOWN OPCODE: 0x%02X\n", op);
            break;
        }
    }

    if (instruction_count >= MAX_INSTRUCTIONS) {
        vm_trace_helper<trace_enabled>("*** EXECUTION STOPPED: instruction limit reached (%d) ***\n", MAX_INSTRUCTIONS);
    }
}

extern "C" void vm_initialize_state(vm_state& vm, uint8_t* code_buffer, uint32_t code_capacity, uint8_t* memory_buffer, uint32_t memory_capacity) {
    vm_initialize_state_internal(vm, code_buffer, code_capacity, memory_buffer, memory_capacity);
}

extern "C" void vm_reset_state(vm_state& vm) {
    vm_reset_state_internal(vm);
}

extern "C" __declspec(noinline) void run_advanced_vm(vm_state& vm) {
#ifdef vm_interpreter_trace
    run_vm_logic<true>(vm);
#else
    run_vm_logic<false>(vm);
#endif
}

extern "C" __declspec(noinline) __declspec(safebuffers) void run_vm_from_blob(
    const uint8_t* bytecode,
    uint32_t size,
    uint8_t* vm_memory,
    uint64_t arg_rcx,
    uint64_t arg_rdx,
    uint64_t arg_r8,
    uint64_t arg_r9) {
    if (!bytecode || size == 0 || size > vm_max_code_size || !vm_memory) {
        return;
    }

    auto* vm = reinterpret_cast<vm_state*>(vm_memory);
    uint8_t* memory_base = vm_memory + sizeof(vm_state);

    vm_initialize_state_internal(*vm, const_cast<uint8_t*>(bytecode), size, memory_base, vm_memory_size);
    if (!configure_chunked_code(*vm, bytecode, size)) {
        vm->code = const_cast<uint8_t*>(bytecode);
        vm->code_capacity = size;
        vm->code_size = size;
        vm->code_is_chunked = false;
        vm->chunked_code_blob = nullptr;
        vm->chunked_code_blob_size = 0;
        vm->chunk_count = 0;
    }
    vm->image_base = get_image_base_runtime();
    vm->image_size = get_image_size_runtime(vm->image_base);
    if (vm_image_base_register < vm_register_count) {
        vm->regs[vm_image_base_register] = vm->image_base;
    }
    vm->regs[2] = arg_rcx;
    vm->regs[3] = arg_rdx;
    vm->regs[8] = arg_r8;
    vm->regs[9] = arg_r9;

    generator<150>::generate_junk();
    run_vm_logic<false>(*vm);
}

#pragma code_seg(pop)
