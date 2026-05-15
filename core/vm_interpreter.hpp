#pragma once


#include "common.hpp"

extern "C" __declspec(noinline) void run_vm_from_blob(
    const uint8_t* bytecode,
    uint32_t size,
    uint8_t* vm_memory,
    uint64_t arg_rcx = 0,
    uint64_t arg_rdx = 0,
    uint64_t arg_r8 = 0,
    uint64_t arg_r9 = 0);
extern "C" const uint8_t __vmb_blob_start;
extern "C" const uint8_t __vmb_blob_end;

extern "C" void vm_initialize_state(vm_state& vm, uint8_t* code_buffer, uint32_t code_capacity, uint8_t* memory_buffer, uint32_t memory_capacity);
extern "C" void vm_reset_state(vm_state& vm);

extern "C" __declspec(noinline) void run_advanced_vm(vm_state& vm);

