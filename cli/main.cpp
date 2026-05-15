#include <iostream>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>

#include "core/common.hpp"
#include "core/assembly_dumper.hpp"
#include "core/x86_to_vm_translator.hpp"
#include "core/vm_interpreter.hpp"
#include "core/pe_patcher.hpp"

int main(int argc, char* argv[]) {
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
        printf("Usage: nocturne.exe <input_pe> <output_pe> <rva_hex> [size_hex]\n");
        printf("   or: nocturne.exe <input_pe> <output_pe> auto\n");
    }
    return 0;
}