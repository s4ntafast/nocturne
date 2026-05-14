#pragma once


#include <cstdint>
#include <map>
#include <Zydis/Zydis.h>

class register_mapper {
private:
    std::map<ZydisRegister, uint8_t> reg_map;

public:
    register_mapper();
    uint8_t get_vm_register(ZydisRegister x86_reg);
};



