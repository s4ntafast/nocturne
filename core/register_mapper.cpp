#include "common.hpp"
#include "register_mapper.hpp"

register_mapper::register_mapper() {
    auto assign = [this](ZydisRegister reg, uint8_t vm_reg) {
        reg_map[reg] = vm_reg;
    };

    assign(ZYDIS_REGISTER_RAX, 0); assign(ZYDIS_REGISTER_RBX, 1);
    assign(ZYDIS_REGISTER_RCX, 2); assign(ZYDIS_REGISTER_RDX, 3);
    assign(ZYDIS_REGISTER_RSI, 4); assign(ZYDIS_REGISTER_RDI, 5);
    assign(ZYDIS_REGISTER_RBP, 6); assign(ZYDIS_REGISTER_RSP, 7);
    assign(ZYDIS_REGISTER_R8, 8);  assign(ZYDIS_REGISTER_R9, 9);
    assign(ZYDIS_REGISTER_R10, 10); assign(ZYDIS_REGISTER_R11, 11);
    assign(ZYDIS_REGISTER_R12, 12); assign(ZYDIS_REGISTER_R13, 13);
    assign(ZYDIS_REGISTER_R14, 14); assign(ZYDIS_REGISTER_R15, 15);
}

uint8_t register_mapper::get_vm_register(ZydisRegister x86_reg) {
    if (x86_reg == ZYDIS_REGISTER_NONE) {
        return vm_scratch_register;
    }

    ZydisRegister canonical = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, x86_reg);
    auto it = reg_map.find(canonical);
    if (it != reg_map.end()) {
        return it->second;
    }

    it = reg_map.find(x86_reg);
    if (it != reg_map.end()) {
        return it->second;
    }

    return 0;
}