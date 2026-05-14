#include <iostream>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include "common.hpp"
#include "assembly_dumper.hpp"
#include "x86_to_vm_translator.hpp"
#include "vm_interpreter.hpp"
#include "pe_patcher.hpp"

struct VmContext {
    vm_state state{};
    std::vector<uint8_t> code;
    std::vector<uint8_t> memory;

    VmContext()
        : code(vm_max_code_size, 0), memory(vm_memory_size, 0) {
        vm_initialize_state(state, code.data(), static_cast<uint32_t>(code.size()),
                            memory.data(), static_cast<uint32_t>(memory.size()));
    }
};

static void dump_and_execute(assembly_dumper& dumper,
                             vm_state& vm,
                             const char* title) {
    dumper.dump_vm_bytecode(vm.code, vm.code_size, title);
    run_advanced_vm(vm);
}

void test_advanced_features() {
    printf("Advanced x86 to VM Translator Test Suite\n");
    printf("==========================================\n");

    assembly_dumper dumper;

    {
        printf("\n>>> TEST 1: Simple loop with conditional jump <<<\n");

        uint8_t correct_x86_code[] = {
            0xB8, 0x05, 0x00, 0x00, 0x00,
            0xBB, 0x01, 0x00, 0x00, 0x00,
            0x39, 0xD8,
            0x7C, 0x04,
            0x29, 0xD8,
            0xEB, 0xF8,
            0xC3
        };

        dumper.dump_x86_assembly(correct_x86_code, sizeof(correct_x86_code), "TEST 1: x86 LOOP CODE");

        VmContext ctx;
        advanced_x86_to_vm_translator translator(ctx.state, 0x401000);
        if (translator.translate_function(correct_x86_code, sizeof(correct_x86_code))) {
            dump_and_execute(dumper, ctx.state, "TEST 1: VM BYTECODE");
            printf("Final: EAX (r0) = %llu, EBX (r1) = %llu\n", ctx.state.regs[0], ctx.state.regs[1]);
            printf("Expected: EAX should be 0 after counting down 5->4->3->2->1->0\n");
        }
    }

    {
        printf("\n>>> TEST 2: Function call with stack <<<\n");

        uint8_t x86_code[] = {
            0xB8, 0x0A, 0x00, 0x00, 0x00,
            0xE8, 0x01, 0x00, 0x00, 0x00,
            0xC3,
            0x05, 0x20, 0x00, 0x00, 0x00,
            0xC3
        };

        dumper.dump_x86_assembly(x86_code, sizeof(x86_code), "TEST 2: x86 FUNCTION CALL");

        VmContext ctx;
        advanced_x86_to_vm_translator translator(ctx.state, 0x400000);
        if (translator.translate_function(x86_code, sizeof(x86_code))) {
            dump_and_execute(dumper, ctx.state, "TEST 2: VM BYTECODE");
            printf("Final: EAX (r0) = %llu (should be 42: 10 + 32)\n", ctx.state.regs[0]);
        }
    }

    {
        printf("\n>>> TEST 3: Memory operations <<<\n");
        uint8_t x86_code[] = {
            0xB8, 0x00, 0x10, 0x00, 0x00,
            0xBB, 0x2A, 0x00, 0x00, 0x00,
            0x89, 0x18,
            0x8B, 0x08,
            0x01, 0xD9,
            0xC3
        };

        dumper.dump_x86_assembly(x86_code, sizeof(x86_code), "TEST 3: x86 MEMORY OPS");

        VmContext ctx;
        advanced_x86_to_vm_translator translator(ctx.state);
        
        if (translator.translate_function(x86_code, sizeof(x86_code))) {
            dump_and_execute(dumper, ctx.state, "TEST 3: VM BYTECODE");
            printf("Final: EAX (r0) = %llu, EBX (r1) = %llu, ECX (r2) = %llu\n",
                ctx.state.regs[0], ctx.state.regs[1], ctx.state.regs[2]);
            printf("Expected: EAX = 4096, EBX = 42, ECX = 84\n");
        }
    }

    {
        printf("\n TEST 4\n");
        uint8_t x86_code[] = {
            0x89, 0x4C, 0x24, 0x08, 0x8B, 0x44, 0x24, 0x08,
            0x0F, 0xAF, 0x44, 0x24, 0x08, 0xC2, 0x00, 0x00
        };

        dumper.dump_x86_assembly(x86_code, sizeof(x86_code), "TEST 4");

        VmContext ctx;
        advanced_x86_to_vm_translator translator(ctx.state);
        if (translator.translate_function(x86_code, sizeof(x86_code))) {
            dump_and_execute(dumper, ctx.state, "TEST 4");
            printf("Final: EAX (r0) = %llu, EBX (r1) = %llu, ECX (r2) = %llu\n",
                ctx.state.regs[0], ctx.state.regs[1], ctx.state.regs[2]);
        }
    }

    {
        printf("\n TEST 5\n");
        uint8_t x86_code[] = {
            0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC0,
            0x48, 0xFF, 0xC0, 0x48, 0xFF, 0xC0,
            0x48, 0xFF, 0xC8
        };

        dumper.dump_x86_assembly(x86_code, sizeof(x86_code), "TEST 5");

        VmContext ctx;
        advanced_x86_to_vm_translator translator(ctx.state);
        if (translator.translate_function(x86_code, sizeof(x86_code))) {
            dump_and_execute(dumper, ctx.state, "TEST 5");
            printf("Final: EAX (r0) = %llu, EBX (r1) = %llu, ECX (r2) = %llu\n",
                ctx.state.regs[0], ctx.state.regs[1], ctx.state.regs[2]);
        }
    }
}

int main(int argc, char* argv[]) {
    uint8_t* blob_ptr = reinterpret_cast<uint8_t*>(&run_vm_from_blob);
    printf("DEBUG: run_vm_from_blob at %p\n", blob_ptr);
    printf("DEBUG: Bytes: ");
    for(int i=0; i<32; i++) printf("%02X ", blob_ptr[i]);
    printf("\n");
    if(blob_ptr[0] == 0xE9) {
        int32_t rel = *reinterpret_cast<int32_t*>(blob_ptr + 1);
        printf("DEBUG: Thunk detected! JMP relative %d. Target: %p\n", rel, blob_ptr + 5 + rel);
    }

    if (argc >= 4) {
        std::string input_pe = argv[1];
        std::string output_pe = argv[2];
        uint32_t rva = 0;
        uint32_t size = 0x50;

        try {
            std::string mode_or_rva = argv[3];
            if (mode_or_rva == "auto" || mode_or_rva == "markers") {
                size = 0;
            } else {
                rva = std::stoul(mode_or_rva, nullptr, 16);
                if (argc >= 5) {
                    size = std::stoul(argv[4], nullptr, 16);
                }
            }

            printf("Virtualizing %s -> %s\n", input_pe.c_str(), output_pe.c_str());
            if (rva == 0 && size == 0) {
                printf("Target mode: marker scan\n");
            } else {
                printf("Target Function RVA: 0x%X, Size: 0x%X\n", rva, size);
            }

            pe_patcher patcher(input_pe, output_pe, rva, size);
        }
        catch (const std::exception& e) {
            printf("Error: %s\n", e.what());
            return 1;
        }
    }
    else {
        printf("Usage: code_virtualizer.exe <input_pe> <output_pe> <rva_hex> [size_hex]\n");
        printf("   or: code_virtualizer.exe <input_pe> <output_pe> auto\n");
        printf("Running internal tests...\n");
        test_advanced_features();
    }
    return 0;
}

