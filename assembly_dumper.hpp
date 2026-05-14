#pragma once

#include <cstdint>
#include <vector>
#include <Zydis/Zydis.h>

class assembly_dumper {
private:
    ZydisDecoder decoder;
    ZydisFormatter formatter;

public:
    assembly_dumper();
    void dump_x86_assembly(const uint8_t* code, size_t length, const char* title);
    void dump_vm_bytecode(const uint8_t* code, size_t length, const char* title);
};