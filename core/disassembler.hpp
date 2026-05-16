#pragma once

#include <cstdint>
#include <vector>
#include <Zydis/Zydis.h>

class disassembler {
private:
    ZydisDecoder decoder;
    ZydisFormatter formatter;

public:
    disassembler();
    void dump_x86_assembly(const uint8_t* code, size_t length, const char* title);
    void dump_vm_bytecode(const uint8_t* code, size_t length, const char* title);
};