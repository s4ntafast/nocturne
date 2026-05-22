#include <iostream>
#include <cstdint>
#include <string>
#include <vector>
#include <print>
#include <cctype>

#include <argparse/argparse.hpp>

#include "core/common.hpp"
#include "core/disassembler.hpp"
#include "core/x86_translator.hpp"
#include "core/vm_interpreter.hpp"
#include "core/patcher.hpp"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::println("Please use {} -h for help", argv[0]);
        return 1;
    }

    argparse::ArgumentParser parser("nocturne");

    parser.add_description("A bin2bin code virtualizer for x86-64 PEs");
    parser.add_epilog("For more information, visit https://github.com/nodiuus/nocturne");

    parser.add_argument("-i", "--input")
        .required()
        .help("Path to the input PE file to be patched");

    parser.add_argument("-o", "--output")
        .required()
        .help("Path to the output PE file to be generated");

    parser.add_argument("-m", "--mode")
        .default_value(std::string("auto"))
        .help("Mode: auto, markers, pdb, or rva");

    parser.add_argument("--pdb")
        .default_value(std::string(""))
        .help("Path to the PDB file; required when --mode pdb is used");

    parser.add_argument("mode_args")
        .remaining()
        .help("Extra args for mode. For rva: <start_rva> <end_rva>");

    try {
        parser.parse_args(argc, argv);

        const auto input_pe = parser.get<std::string>("--input");
        const auto output_pe = parser.get<std::string>("--output");
        const auto target_mode = parser.get<std::string>("--mode");
        const auto pdb_path = parser.get<std::string>("--pdb");

        std::vector<std::string> mode_args;
        if (auto args = parser.present<std::vector<std::string>>("mode_args")) {
            mode_args = *args;
        }

        std::println("Virtualizing {} -> {}", input_pe, output_pe);

        if (target_mode == "auto" || target_mode == "markers") {
            if (!mode_args.empty()) {
                std::println("Error: --mode {} takes no extra arguments", target_mode);
                return 1;
            }

            std::println("Target mode: {}", target_mode == "auto" ? "auto-detect" : "marker scan");

            patcher binary_patcher(input_pe, output_pe, 0, 0);
        }
        else if (target_mode == "pdb") {
            if (!mode_args.empty()) {
                std::println("Error: --mode pdb takes no extra RVA arguments");
                return 1;
            }

            if (pdb_path.empty()) {
                std::println("Error: --pdb is required when --mode pdb is used");
                return 1;
            }

            std::println("Using PDB: {}", pdb_path);

            // TODO: PDB patcher logic
        }
        else if (target_mode == "rva") {
            if (mode_args.size() != 2) {
                std::println("Error: --mode rva requires <start_rva> <end_rva>");
                std::println("Usage: nocturne -i input.exe -o output.exe --mode rva 401000 402000");
                return 1;
            }

            const auto& start_arg = mode_args[0];
            const auto& end_arg = mode_args[1];

            const uint32_t start_rva = std::stoul(start_arg, nullptr, 16);
            const uint32_t end_rva = std::stoul(end_arg, nullptr, 16);

            if (end_rva <= start_rva) {
                std::println("Error: end RVA must be greater than start RVA");
                return 1;
            }

            const uint32_t size = end_rva - start_rva + 1;

            std::println("Target RVA range: 0x{:X} -> 0x{:X}, Size: 0x{:X}", start_rva, end_rva, size);

            patcher binary_patcher(input_pe, output_pe, start_rva, size);
        }
        else {
            std::println("Error: invalid --mode '{}'", target_mode);
            std::println("Expected: auto, markers, pdb, or rva");
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::println("Error: {}", e.what());
        return 1;
    }

    return 0;
}