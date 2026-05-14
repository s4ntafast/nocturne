/*
    Honestly, can't really call this an "SDK".
*/

#include <cstdint>

#pragma section(".nctrn", read, execute)
#pragma section(".mark", read)

#define VIRTUALIZE __declspec(noinline) __declspec(code_seg(".nctrn"))

struct vmp_marker_record {
    uint64_t magic;
    const void* function;
};

#define VMP_MARKER_MAGIC 0x314B52414D504D56ull
#define VMP_CAT2(a, b) a##b
#define VMP_CAT(a, b) VMP_CAT2(a, b)

#define VIRTUALIZE_MARK(fn) \
    extern "C" __declspec(allocate(".mark")) __declspec(dllexport) \
    const vmp_marker_record VMP_CAT(__vmp_marker_, __LINE__) = { VMP_MARKER_MAGIC, reinterpret_cast<const void*>(&fn) }