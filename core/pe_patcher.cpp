#include <print>
#include <Zydis/Zydis.h>
#include <algorithm>
#include <deque>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

#include "pe_patcher.hpp"
#include "disassembler.hpp"
#include "x86_translator.hpp"
#include "vm_interpreter.hpp"
#include "pdb.hpp"

static constexpr uint64_t vmp_marker_magic = 0x314B52414D504D56ull; // "VMPMARK1"

static void append_u32_le(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFFU));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFFU));
}

static void write_u32_le_at(std::vector<uint8_t>& out, size_t offset, uint32_t value) {
    out[offset + 0] = static_cast<uint8_t>(value & 0xFFU);
    out[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFFU);
    out[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFFU);
    out[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFFU);
}

static uint64_t read_u64_le_local(const uint8_t* ptr) {
    return static_cast<uint64_t>(ptr[0]) |
           (static_cast<uint64_t>(ptr[1]) << 8) |
           (static_cast<uint64_t>(ptr[2]) << 16) |
           (static_cast<uint64_t>(ptr[3]) << 24) |
           (static_cast<uint64_t>(ptr[4]) << 32) |
           (static_cast<uint64_t>(ptr[5]) << 40) |
           (static_cast<uint64_t>(ptr[6]) << 48) |
           (static_cast<uint64_t>(ptr[7]) << 56);
}

static int32_t read_i32_le_local(const uint8_t* ptr) {
    return static_cast<int32_t>(
        static_cast<uint32_t>(ptr[0]) |
        (static_cast<uint32_t>(ptr[1]) << 8) |
        (static_cast<uint32_t>(ptr[2]) << 16) |
        (static_cast<uint32_t>(ptr[3]) << 24));
}

static const uint8_t* resolve_direct_jmp_thunk(const uint8_t* ptr) {
    for (uint32_t i = 0; i < 4 && ptr && ptr[0] == 0xE9; ++i) {
        int32_t rel = read_i32_le_local(ptr + 1);
        ptr = ptr + 5 + rel;
    }

    return ptr;
}

static LIEF::PE::Section* find_section_containing_rva(LIEF::PE::Binary& pe, uint32_t rva) {
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

static bool read_rva_bytes(
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

static uint32_t resolve_direct_jmp_thunk_rva(LIEF::PE::Binary& pe, uint32_t rva) {
    uint32_t current = rva;

    for (uint32_t depth = 0; depth < 8; ++depth) {
        std::vector<uint8_t> bytes;
        if (!read_rva_bytes(pe, current, 5, bytes) || bytes[0] != 0xE9) {
            break;
        }

        int32_t rel = read_i32_le_local(bytes.data() + 1);
        uint32_t target = static_cast<uint32_t>(
            static_cast<int64_t>(current) + 5 + static_cast<int64_t>(rel));
        if (target == current || !find_section_containing_rva(pe, target)) {
            break;
        }

        current = target;
    }

    return current;
}

static bool is_padding_byte(uint8_t byte) {
    return byte == 0x00 || byte == 0xCC;
}

static std::string choose_available_section_name(LIEF::PE::Binary& pe, const std::string& preferred) {
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

static uint32_t find_reachable_function_end_rva(
    LIEF::PE::Binary& pe,
    uint32_t start_rva,
    uint32_t limit_rva) {
    auto* section = find_section_containing_rva(pe, start_rva);
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

    append_u32_le(chunked, vm_chunked_code_magic);
    append_u32_le(chunked, vm_chunked_code_version);
    append_u32_le(chunked, logical_size);
    append_u32_le(chunked, chunk_count);
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
        write_u32_le_at(chunked, desc + 0, logical_start);
        write_u32_le_at(chunked, desc + 4, current_size);
        write_u32_le_at(chunked, desc + 8, data_offset);
    }

    return chunked;
}

static bool validate_blob(const uint8_t* blob, size_t size, uint32_t entry_offset) {
    if (!blob || size == 0) {
        std::println("Blob validation failed: empty blob");
        return false;
    }
    if (entry_offset >= size) {
        std::println("Blob validation failed: entry offset out of range");
        return false;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::vector<uint8_t> visited(size, 0);
    std::vector<uint32_t> worklist;
    worklist.push_back(entry_offset);

    while (!worklist.empty()) {
        uint32_t offset = worklist.back();
        worklist.pop_back();

        while (offset < size) {
            if (visited[offset]) {
                break;
            }
            visited[offset] = 1;

            ZydisDecodedInstruction instr;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, blob + offset, size - offset, &instr, operands))) {
                std::println("Blob validation failed: decode error at +0x{:X}", offset);
                return false;
            }

            const bool is_call = instr.meta.category == ZYDIS_CATEGORY_CALL;
            const bool is_branch =
                instr.meta.category == ZYDIS_CATEGORY_COND_BR ||
                instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
            const bool is_ret = instr.meta.category == ZYDIS_CATEGORY_RET;

            if (is_call || is_branch) {
                bool has_relative = false;
                int64_t rel = 0;
                for (uint8_t i = 0; i < instr.operand_count; ++i) {
                    const auto& op = operands[i];
                    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
                        rel = op.imm.value.s;
                        has_relative = true;
                        break;
                    }
                }

                if (!has_relative) {
                    bool uses_rip_mem = false;
                    for (uint8_t i = 0; i < instr.operand_count; ++i) {
                        const auto& op = operands[i];
                        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                            op.mem.base == ZYDIS_REGISTER_RIP) {
                            uses_rip_mem = true;
                            break;
                        }
                    }

                    if (uses_rip_mem) {
                        std::println("Blob validation failed: RIP-relative indirect control transfer at +0x{:X} ({})",
                                     offset, ZydisMnemonicGetString(instr.mnemonic));
                        return false;
                    }

                    // Indirect call/jmp via register or non-RIP memory is allowed.
                    offset += instr.length;
                    continue;
                }

                int64_t target = static_cast<int64_t>(offset) + instr.length + rel;
                if (target < 0 || target >= static_cast<int64_t>(size)) {
                    std::println(
                        "Blob validation failed: {} at +0x{:X} targets +0x{:X} (out of blob)",
                        ZydisMnemonicGetString(instr.mnemonic),
                        offset,
                        static_cast<uint64_t>(target));
                    return false;
                }

                worklist.push_back(static_cast<uint32_t>(target));

                if (instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR || instr.mnemonic == ZYDIS_MNEMONIC_JMP) {
                    break;
                }
            }

            if (is_ret) {
                break;
            }

            offset += instr.length;
        }
    }

    return true;
}

pe_patcher::pe_patcher(const std::string& input_path, const std::string& output, uint32_t target_rva, uint32_t target_size) : pe(LIEF::PE::Parser::parse(input_path)), output_path(output) {

    uint64_t image_base = pe->imagebase();
    uint32_t image_size = 0;
    uint32_t section_align = pe->optional_header().section_alignment();
    auto align_up_local = [](uint32_t value, uint32_t align) {
        return (value + align - 1) / align * align;
    };
    for (const auto& sect : pe->sections()) {
        uint32_t end = static_cast<uint32_t>(sect.virtual_address() + sect.virtual_size());
        if (end > image_size) {
            image_size = end;
        }
    }
    image_size = align_up_local(image_size, section_align);

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

bool pe_patcher::virtualize_region(uint32_t target_rva, uint32_t target_size, uint64_t image_base, uint32_t image_size) {
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

    uint32_t bytecode_rva = add_vm_section(bytecode);
    if (bytecode_rva == 0) {
        std::println("Failed to add VM section; aborting patch.");
        return false;
    }
    if (!patch_function(target_rva, target_rva + target_size, bytecode_rva, bytecode_size_)) {
        return false;
    }
    return true;
}

uint32_t pe_patcher::add_vm_section(const std::vector<uint8_t>& bytecode) {
    auto align = [](size_t value, size_t alignment) {
        return (value + alignment - 1) / alignment * alignment;
    };

    if (vm_section_created_) {
        auto* existing = pe->get_section(section_name);
        if (!existing) {
            std::println("Error: injected VM section {} disappeared", section_name);
            return 0;
        }

        auto current_content = existing->content();
        std::vector<uint8_t> new_content(current_content.begin(), current_content.end());

        size_t bytecode_offset = align(new_content.size(), 16);
        if (bytecode_offset > new_content.size()) {
            new_content.resize(bytecode_offset, 0x00);
        }

        new_content.insert(new_content.end(), bytecode.begin(), bytecode.end());

        uint32_t file_align = pe->optional_header().file_alignment();
        uint32_t section_align = pe->optional_header().section_alignment();
        uint32_t new_raw_size = static_cast<uint32_t>(align(new_content.size(), file_align));
        uint32_t new_virtual_size = static_cast<uint32_t>(align(new_content.size(), section_align));

        existing->content(new_content);
        existing->size(new_raw_size);
        existing->virtual_size(new_virtual_size);

        return existing->virtual_address() + static_cast<uint32_t>(bytecode_offset);
    }

    std::string preferred_name = section_name;
    section_name = choose_available_section_name(*pe, section_name);
    if (section_name != preferred_name) {
        std::println("Section {} already exists; using {} for injected VM blob", preferred_name, section_name);
    }

    LIEF::PE::Section section(section_name);
    section.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
    section.add_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);

    std::vector<uint8_t> vm_blob;

    const uint8_t* interpreter_begin = &__vmb_blob_start;
    const uint8_t* interpreter_end = &__vmb_blob_end;
    size_t interpreter_size = interpreter_end - interpreter_begin;
    const uint8_t* wrapper_thunk_ptr = reinterpret_cast<const uint8_t*>(&run_vm_from_blob);
    const uint8_t* wrapper_ptr = resolve_direct_jmp_thunk(wrapper_thunk_ptr);

    if (interpreter_begin >= interpreter_end) {
        std::println("Error: VM blob markers are invalid");
        return 0;
    }
    if (wrapper_ptr < interpreter_begin || wrapper_ptr >= interpreter_end) {
        std::println("Error: run_vm_from_blob is not inside VM blob section");
        std::println("       thunk: {}, resolved: {}, blob: {}..{}",
                     static_cast<const void*>(wrapper_thunk_ptr),
                     static_cast<const void*>(wrapper_ptr),
                     static_cast<const void*>(interpreter_begin),
                     static_cast<const void*>(interpreter_end));
        return 0;
    }

    size_t wrapper_offset = static_cast<size_t>(wrapper_ptr - interpreter_begin);
    wrapper_offset_ = static_cast<uint32_t>(wrapper_offset);

    std::println("Interpreter size: {} bytes", interpreter_size);
    std::println("Interpreter entry offset: 0x{:X}", static_cast<uint32_t>(wrapper_offset));

    if (!validate_blob(interpreter_begin, interpreter_size, wrapper_offset_)) {
        std::println("Error: VM blob contains external or invalid control flow.");
        std::println("Build the interpreter with optimizations and without tracing or stack probes.");
        return 0;
    }

    vm_blob.insert(vm_blob.end(), interpreter_begin, interpreter_end);

    std::print("VM Blob Head: ");
    for(size_t i=0; i<std::min((size_t)32, vm_blob.size()); ++i) {
        std::print("{:02X} ", vm_blob[i]);
    }
    std::println();

    size_t bytecode_offset = align(vm_blob.size(), 16);
    if (bytecode_offset > vm_blob.size()) {
        vm_blob.resize(bytecode_offset, 0x00);
    }

    vm_blob.insert(vm_blob.end(), bytecode.begin(), bytecode.end());

    section.content(vm_blob);

    section.characteristics(static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE) | 
                            static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ) | 
                            static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE) |
                            static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::CNT_CODE));

    uint32_t next_rva = 0x1000;
    uint32_t section_alignment = pe->optional_header().section_alignment();
    
    auto sections = pe->sections();
    if (sections.begin() != sections.end()) {
        LIEF::PE::Section* last_sect = nullptr;
        for (auto& sect : sections) {
            last_sect = &sect;
        }
        
        if (last_sect) {
            uint32_t last_va = static_cast<uint32_t>(last_sect->virtual_address());
            uint32_t last_vsize = static_cast<uint32_t>(last_sect->virtual_size());
            next_rva = align(last_va + last_vsize, section_alignment);
        }
    }

    std::println("Calculated next section RVA: 0x{:X} (alignment: 0x{:X})", next_rva, section_alignment);
    section.virtual_address(next_rva);

    pe->add_section(section);
    vm_section_created_ = true;

    auto* added = pe->get_section(section_name);
    interpreter_rva_ = added ? static_cast<uint32_t>(added->virtual_address())
                             : static_cast<uint32_t>(section.virtual_address());
    wrapper_rva_ = interpreter_rva_ + wrapper_offset_;
    std::println("Interpreter RVA: 0x{:X}", interpreter_rva_);
    std::println("Wrapper RVA: 0x{:X}", wrapper_rva_);

    return interpreter_rva_ + static_cast<uint32_t>(bytecode_offset);
}

std::vector<std::vector<uint8_t>> pe_patcher::get_code_at_marker() {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    
	auto vm_section = pe->get_section(".vmp");
	auto section_content = vm_section->content();
	auto base_rva = pe->imagebase();
	auto section_rva = vm_section->virtual_address();
    
    std::vector<std::vector<uint8_t>> marked_opcodes;

    size_t offset = 0x0;
    while (offset <= section_content.size()) {
        ZydisDecodedInstruction instr;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
            section_content.data() + offset,
            section_content.size() - offset,
            &instr, operands))) {

            uint64_t instr_rva = section_rva + offset;
			uint64_t instr_va = base_rva + instr_rva;

            std::vector<uint8_t> bytes(section_content.begin() + offset, section_content.begin() + offset + instr.length);

            for (auto c : bytes) {
                std::cout << std::hex << (int)c << " ";
            }
            std::cout << std::endl;

            marked_opcodes.push_back(bytes);

            offset += instr.length;
        }
        else {
            offset += 1;
        }
    }

    return marked_opcodes;
}

std::vector<std::pair<uint32_t, uint32_t>> pe_patcher::grab_rvas_from_markers() {
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
        uint64_t magic = read_u64_le_local(marker_content.data() + offset);
        if (magic != vmp_marker_magic) {
            continue;
        }

        uint64_t target = read_u64_le_local(marker_content.data() + offset + 8);
        uint64_t rva64 = target;
        if (target >= image_base) {
            rva64 = target - image_base;
        }

        if (rva64 == 0 || rva64 > (std::numeric_limits<uint32_t>::max)()) {
            continue;
        }

        uint32_t raw_rva = static_cast<uint32_t>(rva64);
        uint32_t resolved_rva = resolve_direct_jmp_thunk_rva(*pe, raw_rva);
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

std::vector<std::pair<uint32_t, uint32_t>> pe_patcher::grab_rvas_from_pdb() {
    return { {} };
}

std::vector<uint8_t> pe_patcher::get_code_at_rva(uint32_t function_rva, uint32_t end_rva) {
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
            section_content.size() - section_offset,
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

static constexpr uint32_t align_up(uint32_t value, uint32_t align) {
    return (value + align - 1) / align * align;
}

bool pe_patcher::patch_function(
    uint32_t fn_rva,
    uint32_t end_rva,
    uint32_t bytecode_rva,
    uint32_t bytecode_size)
{
    auto* virtualized_section = pe->get_section(section_name);
    if (!virtualized_section) {
        std::println("Error: {} section not found", section_name);
        return false;
    }

    uint32_t sect_rva = virtualized_section->virtual_address();
    uint64_t image_base = pe->optional_header().imagebase();

    // LIEF may adjust the section RVA when writing the PE.
    interpreter_rva_ = sect_rva;
    wrapper_rva_ = interpreter_rva_ + wrapper_offset_;

    uint64_t interpreter_va = image_base + interpreter_rva_;
    uint64_t entry_va = image_base + wrapper_rva_;
    uint64_t bytecode_va = image_base + bytecode_rva;

    std::println("Image Base: 0x{:X}", image_base);
    std::println("Interpreter VA: 0x{:X} (RVA: 0x{:X})", interpreter_va, interpreter_rva_);
    std::println("Entry VA: 0x{:X} (RVA: 0x{:X})", entry_va, wrapper_rva_);
    std::println("Bytecode VA: 0x{:X} (RVA: 0x{:X}, size: 0x{:X})", bytecode_va, bytecode_rva, bytecode_size);

    auto current_content = virtualized_section->content();
    std::vector<uint8_t> new_content(current_content.begin(), current_content.end());

    uint32_t stub_offset = static_cast<uint32_t>(current_content.size());
    uint32_t stub_rva = sect_rva + stub_offset;

    std::println("Trampoline stub will be at RVA: 0x{:X}", stub_rva);

    std::vector<uint8_t> stub;

    stub.insert(stub.end(), {
        0x53,                           // push rbx
        0x51,                           // push rcx  
        0x52,                           // push rdx
        0x41, 0x50,                     // push r8
        0x41, 0x51,                     // push r9
        0x41, 0x52,                     // push r10
        0x41, 0x53                      // push r11
        });

    static_assert(sizeof(vm_state) < 0x1000, "vm_state too large for stack probe tail");

    // Manual stack probing keeps large VM frames from jumping past guard pages.
    auto align16 = [](uint32_t v) { return (v + 0xF) & ~0xFu; };
    constexpr uint32_t call_frame_size = 0x40;
    uint32_t total_size = align16(call_frame_size + static_cast<uint32_t>(sizeof(vm_state)) + vm_memory_size);
    
    uint32_t page_count = total_size / 0x1000;
    uint32_t remainder = total_size % 0x1000;

    stub.push_back(0xB8); // mov eax, imm32
    size_t page_count_pos = stub.size();
    stub.resize(stub.size() + 4);
    *reinterpret_cast<uint32_t*>(&stub[page_count_pos]) = page_count;

    stub.insert(stub.end(), {
        0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00, // sub rsp, 4096
        0x48, 0x85, 0x24, 0x24,         // test [rsp], rsp (commit page)
        0xFF, 0xC8,                     // dec eax
        0x75, 0xF1                      // jnz loop (offset -15 bytes: 7+4+2+2=15)
    });

    if (remainder != 0) {
        stub.insert(stub.end(), { 0x48, 0x81, 0xEC, 0x00, 0x00, 0x00, 0x00 }); // sub rsp, imm32
        *reinterpret_cast<uint32_t*>(&stub[stub.size() - 4]) = remainder;
        stub.insert(stub.end(), { 0x48, 0x85, 0x24, 0x24 }); // test [rsp], rsp (commit final page)
    }

    auto append_lea_rip = [&](uint8_t modrm, uint32_t target_rva) {
        size_t instr_start = stub.size();
        stub.push_back(0x48);
        stub.push_back(0x8D);
        stub.push_back(modrm);
        size_t disp_offset = stub.size();
        stub.resize(stub.size() + 4);
        int64_t next_instr_rva = static_cast<int64_t>(stub_rva + instr_start + 7);
        int64_t disp = static_cast<int64_t>(target_rva) - next_instr_rva;
        if (disp < std::numeric_limits<int32_t>::min() || disp > std::numeric_limits<int32_t>::max()) {
            throw std::runtime_error("Relative displacement out of range for trampoline stub");
        }
        *reinterpret_cast<int32_t*>(&stub[disp_offset]) = static_cast<int32_t>(disp);
    };

    append_lea_rip(0x0D, bytecode_rva); // lea rcx, [rip + bytecode]

    stub.push_back(0xBA); // mov edx, imm32
    size_t size_pos = stub.size();
    stub.resize(stub.size() + 4);
    *reinterpret_cast<uint32_t*>(&stub[size_pos]) = bytecode_size;

    // vm_state starts above the shadow space and copied stack args.
    stub.insert(stub.end(), { 0x4C, 0x8D, 0x44, 0x24, static_cast<uint8_t>(call_frame_size) });
    stub.insert(stub.end(), { 0x4C, 0x89, 0xC3 }); // mov rbx, r8

    auto append_mov_rax_from_rsp = [&](uint32_t disp) {
        stub.insert(stub.end(), { 0x48, 0x8B, 0x84, 0x24 }); // mov rax, [rsp+disp32]
        size_t pos = stub.size();
        stub.resize(stub.size() + 4);
        *reinterpret_cast<uint32_t*>(&stub[pos]) = disp;
    };
    auto append_mov_rsp_from_rax = [&](uint8_t disp) {
        stub.insert(stub.end(), { 0x48, 0x89, 0x44, 0x24, disp }); // mov [rsp+disp8], rax
    };

    constexpr uint32_t saved_r9_offset = 16;
    constexpr uint32_t saved_r8_offset = 24;
    constexpr uint32_t saved_rdx_offset = 32;
    constexpr uint32_t saved_rcx_offset = 40;

    // Seed VM argument registers from the original Windows x64 call arguments.
    stub.insert(stub.end(), { 0x4C, 0x8B, 0x8C, 0x24 }); // mov r9, [rsp+disp32]
    size_t original_rcx_pos = stub.size();
    stub.resize(stub.size() + 4);
    *reinterpret_cast<uint32_t*>(&stub[original_rcx_pos]) = total_size + saved_rcx_offset;
    append_mov_rax_from_rsp(total_size + saved_rdx_offset);
    append_mov_rsp_from_rax(0x20);
    append_mov_rax_from_rsp(total_size + saved_r8_offset);
    append_mov_rsp_from_rax(0x28);
    append_mov_rax_from_rsp(total_size + saved_r9_offset);
    append_mov_rsp_from_rax(0x30);

    std::println("DEBUG TRAMPOLINE: stub_rva=0x{:X}, wrapper_rva_=0x{:X}, bytecode_rva=0x{:X}", 
                 stub_rva, wrapper_rva_, bytecode_rva);
    std::println("DEBUG TRAMPOLINE: About to calculate LEA for wrapper at RVA 0x{:X}", wrapper_rva_);
    std::println("DEBUG TRAMPOLINE: stub.size()={}, so LEA instr will be at stub_rva + {} = 0x{:X}", 
                 stub.size(), stub.size(), stub_rva + stub.size());

    size_t lea_position_before = stub.size();
    append_lea_rip(0x05, wrapper_rva_); // lea rax, [rip + wrapper]
    size_t lea_position_after = stub.size();
    
    std::print("DEBUG: LEA bytes: ");
    for (size_t i = lea_position_before; i < lea_position_after; ++i) {
        std::print("{:02X} ", stub[i]);
    }
    std::println("");

    stub.insert(stub.end(), { 0xFF, 0xD0 }); // call rax
    stub.insert(stub.end(), { 0x48, 0x8B, 0x03 }); // mov rax, [rbx]

    stub.insert(stub.end(), { 0x48, 0x81, 0xC4, 0x00, 0x00, 0x00, 0x00 });
    *reinterpret_cast<uint32_t*>(&stub[stub.size() - 4]) = total_size;

    stub.insert(stub.end(), {
        0x41, 0x5B,                     // pop r11
        0x41, 0x5A,                     // pop r10
        0x41, 0x59,                     // pop r9
        0x41, 0x58,                     // pop r8
        0x5A,                           // pop rdx
        0x59,                           // pop rcx
        0x5B                            // pop rbx
        });

    stub.push_back(0xC3); // ret

    std::println("Generated trampoline stub size: {} bytes", stub.size());

    std::print("Stub bytes: ");
    for (auto b : stub) {
        std::print("{:02X} ", b);
    }
    std::println();

    new_content.insert(new_content.end(), stub.begin(), stub.end());

    uint32_t file_align = pe->optional_header().file_alignment();
    uint32_t section_align = pe->optional_header().section_alignment();
    uint32_t new_raw_size = align_up(static_cast<uint32_t>(new_content.size()), file_align);
    uint32_t new_virtual_size = align_up(static_cast<uint32_t>(new_content.size()), section_align);

    std::println("New section sizes - Raw: 0x{:X}, Virtual: 0x{:X}", new_raw_size, new_virtual_size);

    virtualized_section->content(new_content);
    virtualized_section->size(new_raw_size);
    virtualized_section->virtual_size(new_virtual_size);

    int32_t jmp_rel = static_cast<int32_t>(stub_rva - (fn_rva + 5));

    std::println("Jump from RVA 0x{:X} to 0x{:X}, relative offset: 0x{:X}",
        fn_rva, stub_rva, static_cast<uint32_t>(jmp_rel));

    std::vector<uint8_t> jmp_patch = {
        0xE9,
        static_cast<uint8_t>(jmp_rel & 0xFF),
        static_cast<uint8_t>((jmp_rel >> 8) & 0xFF),
        static_cast<uint8_t>((jmp_rel >> 16) & 0xFF),
        static_cast<uint8_t>((jmp_rel >> 24) & 0xFF)
    };

    pe->patch_address(fn_rva, jmp_patch, LIEF::Binary::VA_TYPES::RVA);

    uint32_t fn_size = end_rva - fn_rva;
    if (fn_size > 5) {
        std::vector<uint8_t> nops(fn_size - 5, 0x90);
        pe->patch_address(fn_rva + 5, nops, LIEF::Binary::VA_TYPES::RVA);
    }

    std::println("Successfully patched function - calls embedded interpreter at 0x{:X}", interpreter_va);
    return true;
}

bool pe_patcher::output_pe() {
    for (const char* marker_name : { ".mark", ".vmpm" }) {
        if (auto* existing = pe->get_section(marker_name)) {
            pe->remove_section(existing->name().c_str());
        }
    }

    pe->write(output_path);
    return true;
}
