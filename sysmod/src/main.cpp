#include <cstring>
#include <span>
#include <algorithm> // for std::min
#include <bit> // for std::byteswap
#include <utility> // std::unreachable
#include <switch.h>
#include "minIni/minIni.h"

namespace {

constexpr u64 INNER_HEAP_SIZE = 0x1000; // Size of the inner heap (adjust as necessary).
constexpr u64 READ_BUFFER_SIZE = 0x1000; // size of static buffer which memory is read into
constexpr u32 FW_VER_ANY = 0x0;
constexpr u16 REGEX_SKIP = 0x100;

u32 FW_VERSION{}; // set on startup
u32 AMS_VERSION{}; // set on startup
u32 AMS_TARGET_VERSION{}; // set on startup
u8 AMS_KEYGEN{}; // set on startup
u64 AMS_HASH{}; // set on startup
bool VERSION_SKIP{}; // set on startup

struct DebugEventInfo {
    u32 event_type;
    u32 flags;
    u64 thread_id;
    u64 title_id;
    u64 process_id;
    char process_name[12];
    u32 mmu_flags;
    u8 _0x30[0x10];
};

template<typename T>
constexpr void str2hex(const char* s, T* data, u8& size) {
    // skip leading 0x (if any)
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }

    // invalid string will cause a compile-time error due to no return
    constexpr auto hexstr_2_nibble = [](char c) -> u8 {
        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
        if (c >= '0' && c <= '9') { return c - '0'; }
    };

    // parse and convert string
    while (*s != '\0') {
        if (sizeof(T) == sizeof(u16) && *s == '.') {
            data[size] = REGEX_SKIP;
            s++;
        } else {
            data[size] |= hexstr_2_nibble(*s++) << 4;
            data[size] |= hexstr_2_nibble(*s++) << 0;
        }
        size++;
    }
}

struct PatternData {
    constexpr PatternData(const char* s) {
        str2hex(s, data, size);
    }

    u16 data[60]{}; // reasonable max pattern length, adjust as needed
    u8 size{};
};

struct PatchData {
    constexpr PatchData(const char* s) {
        str2hex(s, data, size);
    }

    template<typename T>
    constexpr PatchData(T v) {
        for (u32 i = 0; i < sizeof(T); i++) {
            data[size++] = v & 0xFF;
            v >>= 8;
        }
    }

    constexpr auto cmp(const void* _data) -> bool {
        return !std::memcmp(data, _data, size);
    }

    u8 data[20]{}; // reasonable max patch length, adjust as needed
    u8 size{};
};

struct IPSPatch {
    u32 offset;
    u8 size;
    u8 data[20];
};

enum class PatchResult {
    NOT_FOUND,
    SKIPPED,
    DISABLED,
    PATCHED_FILE,
    PATCHED_SYSPATCH,
    FAILED_WRITE,
};



// Helper function to write a 24-bit big-endian value
auto write_be24(u8* dst, u32 value) -> void {
    dst[0] = (value >> 16) & 0xFF;
    dst[1] = (value >> 8) & 0xFF;
    dst[2] = value & 0xFF;
}

// Helper function to write a 16-bit big-endian value
auto write_be16(u8* dst, u16 value) -> void {
    dst[0] = (value >> 8) & 0xFF;
    dst[1] = value & 0xFF;
}

struct Patterns {
    const char* patch_name; // name of patch
    const PatternData byte_pattern; // the pattern to search

    const s32 inst_offset; // instruction offset relative to byte pattern
    const s32 patch_offset; // patch offset relative to inst_offset

    bool (*const cond)(u32 inst); // check condition of the instruction
    PatchData (*const patch)(u32 inst); // the patch data to be applied
    bool (*const applied)(const u8* data, u32 inst); // check to see if patch already applied

    bool enabled; // controlled by config.ini

    const u32 min_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 max_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 min_ams_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 max_ams_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore

    PatchResult result{PatchResult::NOT_FOUND};
    
    // Cache for IPS file generation
    u32 cached_offset{0};
    u8 cached_patch_size{0};
    u8 cached_patch_data[20]{};
};

struct PatchEntry {
    const char* name; // name of the system title
    const u64 title_id; // title id of the system title
    const std::span<Patterns> patterns; // list of patterns to find
    const u32 min_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 max_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
};

using ModuleID = std::array<u8, 32>;

// naming convention should if possible adhere to either an arm instruction + _cond,
// example: "bl_cond"
// or naming it specific to what is being patched, and including all possible bytes within the address being tested for the given patch.
// example: "ctest_cond"

constexpr auto sub_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xD1; // sub sp, sp, #0x150
}

constexpr auto cmp_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0x6B || // cmp w0, w1
           type == 0xF1;   // cmp x0, #0x1
}

constexpr auto bl_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0x25 ||
           type == 0x94 ||
           type == 0x97;
}

constexpr auto tbz_cond(u32 inst) -> bool {
    return ((inst >> 24) & 0x7F) == 0x36;
}

constexpr auto adr_cond(u32 inst) -> bool {
    return (inst >> 24) == 0x10; // adr x2, LAB
}

constexpr auto block_fw_updates_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xA8 ||
           type == 0xA9 ||
           type == 0xF8 ||
           type == 0xF9;
}

constexpr auto es_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xD1 ||
           type == 0xA9 ||
           type == 0xAA ||
           type == 0x2A ||
           type == 0x92;
}

constexpr auto ctest_cond(u32 inst) -> bool {
    const auto type = inst >> 24;
    return type == 0xF9 ||
           type == 0xA9 ||
           type == 0xF8;
}


// to view patches, use https://armconverter.com/?lock=arm64
constexpr PatchData ret0_patch_data{ "0xE0031F2A" };
constexpr PatchData ret1_patch_data{ "0x200080D2" };
constexpr PatchData mov0_ret_patch_data{ "0xE0031F2AC0035FD6" };
constexpr PatchData nop_patch_data{ "0x1F2003D5" };
//mov x0, xzr
constexpr PatchData mov0_patch_data{ "0xE0031FAA" };
//mov x2, xzr
constexpr PatchData mov2_patch_data{ "0xE2031FAA" };
constexpr PatchData cmp_patch_data{ "0x00" };
constexpr PatchData ctest_patch_data{ "0x00309AD2001EA1F2610100D4E0031FAAC0035FD6" };

constexpr auto ret0_patch(u32 inst) -> PatchData { return ret0_patch_data; }
constexpr auto ret1_patch(u32 inst) -> PatchData { return ret1_patch_data; }
constexpr auto mov0_ret_patch(u32 inst) -> PatchData { return mov0_ret_patch_data; }
constexpr auto nop_patch(u32 inst) -> PatchData { return nop_patch_data; }
constexpr auto mov0_patch(u32 inst) -> PatchData { return mov0_patch_data; }
constexpr auto mov2_patch(u32 inst) -> PatchData { return mov2_patch_data; }
constexpr auto cmp_patch(u32 inst) -> PatchData { return cmp_patch_data; }
constexpr auto ctest_patch(u32 inst) -> PatchData { return ctest_patch_data; }

constexpr auto ret0_applied(const u8* data, u32 inst) -> bool {
    return ret0_patch(inst).cmp(data);
}

constexpr auto ret1_applied(const u8* data, u32 inst) -> bool {
    return ret1_patch(inst).cmp(data);
}

constexpr auto nop_applied(const u8* data, u32 inst) -> bool {
    return nop_patch(inst).cmp(data);
}

constexpr auto cmp_applied(const u8* data, u32 inst) -> bool {
    return cmp_patch(inst).cmp(data);
}

constexpr auto mov0_ret_applied(const u8* data, u32 inst) -> bool {
    return mov0_ret_patch(inst).cmp(data);
}

constexpr auto mov0_applied(const u8* data, u32 inst) -> bool {
    return mov0_patch(inst).cmp(data);
}

constexpr auto mov2_applied(const u8* data, u32 inst) -> bool {
    return mov2_patch(inst).cmp(data);
}

constexpr auto ctest_applied(const u8* data, u32 inst) -> bool {
    return ctest_patch(inst).cmp(data);
}

constinit Patterns fs_patterns[] = {
    { "noacidsigchk_1.0.0-9.2.0", "0xC8FE4739", -24, 0, bl_cond, ret0_patch, ret0_applied, true, FW_VER_ANY, MAKEHOSVERSION(9,2,0) }, // moved to loader 10.0.0
    { "noacidsigchk_1.0.0-9.2.0", "0x0210911F000072", -5, 0, bl_cond, ret0_patch, ret0_applied, true, FW_VER_ANY, MAKEHOSVERSION(9,2,0) }, // moved to loader 10.0.0
    { "noncasigchk_10.0.0-16.1.0", "0x1E48391F.0071..0054", -17, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(16,1,0) },
    { "noncasigchk_17.0.0+", "0x0694..00.42.0091", -18, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY },
    { "nocntchk_10.0.0-18.1.0", "0x00..0240F9....08.....00...00...0037", 6, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(10,0,0), MAKEHOSVERSION(18,1,0) },
    { "nocntchk_19.0.0-20.5.0", "0x00..0240F9....08.....00...00...0054", 6, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(19,0,0), MAKEHOSVERSION(20,5,0) },
    { "nocntchk_21.0.0+", "0x00..0240F9....E8.....00...00...0054", 6, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(21,0,0), FW_VER_ANY },
};

constinit Patterns ldr_patterns[] = {
    { "noacidsigchk_10.0.0+", "0x009401C0BE121F00", 6, 2, cmp_cond, cmp_patch, cmp_applied, true, FW_VER_ANY }, // 1F00016B - cmp w0, w1 patched to 1F00006B - cmp w0, w0
};

constinit Patterns erpt_patterns[] = {
    { "no_erpt", "0x...D1FD7B02A9FD830091F76305A9", 0, 0, sub_cond, mov0_ret_patch, mov0_ret_applied, true, FW_VER_ANY }, // FF4305D1 - sub sp, sp, #0x150 patched to E0031F2AC0035FD6 - mov w0, wzr, ret 
};

constinit Patterns es_patterns[] = {
    { "es_1.0.0-8.1.1", "0x....E8.00...FF97.0300AA..00.....E0.0091..0094.7E4092.......A9", 36, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(8,1,1) },
    { "es_9.0.0-11.0.1", "0x00...............00.....A0..D1...97.......A9", 30, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(9,0,0), MAKEHOSVERSION(11,0,1) },
    { "es_12.0.0-18.1.0", "0x02.00...........00...00.....A0..D1...97.......A9", 32, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(12,0,0), MAKEHOSVERSION(18,1,0) },
    { "es_19.0.0+", "0xA1.00...........00...00.....A0..D1...97.......A9", 32, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
};

constinit Patterns olsc_patterns[] = {
    { "olsc_6.0.0-14.1.2", "0x00.73..F968024039..00...00", 42, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(6,0,0), MAKEHOSVERSION(14,1,2) },
    { "olsc_15.0.0-18.1.0", "0x00.73..F968024039..00...00", 38, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(15,0,0), MAKEHOSVERSION(18,1,0) },
    { "olsc_19.0.0+", "0x00.73..F968024039..00...00", 42, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
};

constinit Patterns nifm_patterns[] = {
    { "ctest_1.0.0-19.0.1", "0x03.AAE003.AA...39..04F8....E0", -29, 0, ctest_cond, ctest_patch, ctest_applied, true, FW_VER_ANY, MAKEHOSVERSION(18,1,0) },
    { "ctest_20.0.0+", "0x03.AA...AA.........0314AA..14AA", -17, 0, ctest_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(20,0,0), FW_VER_ANY },
};

constinit Patterns nim_patterns[] = {
    { "blankcal0crashfix_17.0.0+", "0x00351F2003D5...............97..0094..00.....61", 6, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY },
    { "blockfirmwareupdates_1.0.0-5.1.0", "0x1139F30301AA81.40F9E0.1191", -30, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(5,1,0) },
    { "blockfirmwareupdates_6.0.0-6.2.0", "0xF30301AA.4E40F9E0..91", -40, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(6,0,0), MAKEHOSVERSION(6,2,0) },
    { "blockfirmwareupdates_7.0.0-11.0.1", "0xF30301AA014C40F9F40300AAE0..91", -36, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(7,0,0), MAKEHOSVERSION(11,0,1) },
    { "blockfirmwareupdates_12.0.0+", "0x280841F9084C00F9E0031F.C0035FD6", 16, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(12,0,0), FW_VER_ANY },
};

// NOTE: add system titles that you want to be patched to this table.
// a list of system titles can be found here https://switchbrew.org/wiki/Title_list
constinit PatchEntry patches[] = {
    { "fs", 0x0100000000000000, fs_patterns },
    // ldr needs to be patched in fw 10+
    { "ldr", 0x0100000000000001, ldr_patterns, MAKEHOSVERSION(10,0,0) },
    // erpt no write patch
    { "erpt", 0x010000000000002B, erpt_patterns, MAKEHOSVERSION(10,0,0) },
    // es was added in fw 2
    { "es", 0x0100000000000033, es_patterns, MAKEHOSVERSION(2,0,0) },
    // olsc was added in fw 6
    { "olsc", 0x010000000000003E, olsc_patterns, MAKEHOSVERSION(6,0,0) },
    { "nifm", 0x010000000000000F, nifm_patterns },
    { "nim", 0x0100000000000025, nim_patterns },
};

struct EmummcPaths {
    char unk[0x80];
    char nintendo[0x80];
};

void smcAmsGetEmunandConfig(EmummcPaths* out_paths) {
    SecmonArgs args{};
    args.X[0] = 0xF0000404; /* smcAmsGetEmunandConfig */
    args.X[1] = 0; /* EXO_EMUMMC_MMC_NAND*/
    args.X[2] = (u64)out_paths; /* out path */
    svcCallSecureMonitor(&args);
}

auto is_emummc() -> bool {
    EmummcPaths paths{};
    smcAmsGetEmunandConfig(&paths);
    return (paths.unk[0] != '\0') || (paths.nintendo[0] != '\0');
}

auto create_dir(const char* path) -> bool;
auto read_ips_file(const char* path, u8* out_data, u64* out_size) -> bool;
auto write_ips_file(const char* path, const u8* data, u64 size) -> bool;
auto create_directories(const char* path) -> bool;
auto extract_module_id(Handle handle, u64 title_id) -> ModuleID;
auto generate_ips_files(const PatchEntry& patch, const ModuleID& module_id) -> void;
auto apply_patch(const PatchEntry& patch, ModuleID& out_module_id) -> bool;

void patcher(Handle handle, const u8* data, size_t data_size, u64 addr, std::span<Patterns> patterns) {
    for (auto& p : patterns) {
        if (p.result == PatchResult::DISABLED) {
            continue;
        }

        if (VERSION_SKIP &&
            ((p.min_fw_ver && p.min_fw_ver > FW_VERSION) ||
            (p.max_fw_ver && p.max_fw_ver < FW_VERSION) ||
            (p.min_ams_ver && p.min_ams_ver > AMS_VERSION) ||
            (p.max_ams_ver && p.max_ams_ver < AMS_VERSION))) {
            p.result = PatchResult::SKIPPED;
            continue;
        }

        if (p.result == PatchResult::PATCHED_FILE || p.result == PatchResult::PATCHED_SYSPATCH) {
            continue;
        }

        for (u32 i = 0; i < data_size; i++) {
            if (i + p.byte_pattern.size >= data_size) {
                break;
            }

            u32 count{};
            while (count < p.byte_pattern.size) {
                if (p.byte_pattern.data[count] != data[i + count] && p.byte_pattern.data[count] != REGEX_SKIP) {
                    break;
                }
                count++;
            }

            if (count == p.byte_pattern.size) {
                u32 inst{};
                const auto inst_offset = i + p.inst_offset;
                std::memcpy(&inst, data + inst_offset, sizeof(inst));

                if (p.cond(inst)) {
                    const auto patch_data = p.patch(inst);
                    const auto patch_offset = addr + inst_offset + p.patch_offset;

                    p.cached_offset = patch_offset;
                    p.cached_patch_size = patch_data.size;
                    std::memcpy(p.cached_patch_data, patch_data.data, patch_data.size);

                    if (R_FAILED(svcWriteDebugProcessMemory(handle, &patch_data, patch_offset, patch_data.size))) {
                        p.result = PatchResult::FAILED_WRITE;
                    } else {
                        p.result = PatchResult::PATCHED_SYSPATCH;
                    }
                    break;
                } else if (p.applied(data + inst_offset + p.patch_offset, inst)) {
                    // patch already applied by sigpatches
                    p.result = PatchResult::PATCHED_FILE;
                    break;
                }
            }
        }
    }
}

auto extract_module_id(Handle handle, u64 title_id) -> ModuleID {
    ModuleID module_id{};
    bool is_fs_or_loader = (title_id == 0x0100000000000000ULL || title_id == 0x0100000000000001ULL);
    
    if (!is_fs_or_loader) {
        MemoryInfo mem_info{};
        u32 page_info{};
        u64 addr = 0;

        while (R_SUCCEEDED(svcQueryDebugProcessMemory(&mem_info, &page_info, handle, addr))) {
            addr = mem_info.addr + mem_info.size;

            if (mem_info.type == MemType_CodeStatic && (mem_info.perm & Perm_Rx) == Perm_Rx && mem_info.size > 0x60) {
                if (R_SUCCEEDED(svcReadDebugProcessMemory(module_id.data(), handle, mem_info.addr + 0x40, module_id.size()))) {
                    break;
                }
            }
        }
    }
    
    return module_id;
}

auto generate_ips_files(const PatchEntry& patch, const ModuleID& module_id) -> void {
    // Check if module_id is empty (all zeros)
    if (std::all_of(module_id.begin(), module_id.end(), [](u8 b) { return b == 0; })) {
        return;
    }

    const char* patch_dir = nullptr;
    if (patch.title_id == 0x0100000000000033ULL) {
        patch_dir = "/atmosphere/exefs_patches/es_patches/";
    } else if (patch.title_id == 0x0100000000000025ULL) {
        patch_dir = "/atmosphere/exefs_patches/nim_ctest/";
    } else if (patch.title_id == 0x010000000000000FULL) {
        patch_dir = "/atmosphere/exefs_patches/nifm_ctest/";
    }

    if (!patch_dir) {
        return;
    }

    char hex_str[65]{};
    for (int i = 0; i < 32; ++i) {
        snprintf(hex_str + i * 2, 3, "%02x", module_id[i]);
    }

    char file_path[FS_MAX_PATH]{};
    snprintf(file_path, sizeof(file_path), "%s%s.ips", patch_dir, hex_str);

    // Generate IPS data with fixed buffer (256 bytes max for 100 byte IPS files)
    constexpr u64 IPS_MAX_SIZE = 256;
    u8 ips_data[IPS_MAX_SIZE]{};
    u64 ips_size = 0;

    // Write header
    ips_data[0] = 'P';
    ips_data[1] = 'A';
    ips_data[2] = 'T';
    ips_data[3] = 'C';
    ips_data[4] = 'H';
    ips_size = 5;

    // Write patch entries
    for (const auto& p : patch.patterns) {
        if (p.cached_patch_size > 0) {
            if (ips_size + 3 + 2 + p.cached_patch_size + 3 > IPS_MAX_SIZE) {
                return; // Buffer overflow protection
            }

            u8 offset_bytes[3];
            write_be24(offset_bytes, p.cached_offset);
            std::memcpy(ips_data + ips_size, offset_bytes, 3);
            ips_size += 3;

            u8 size_bytes[2];
            write_be16(size_bytes, p.cached_patch_size);
            std::memcpy(ips_data + ips_size, size_bytes, 2);
            ips_size += 2;

            std::memcpy(ips_data + ips_size, p.cached_patch_data, p.cached_patch_size);
            ips_size += p.cached_patch_size;
        }
    }

    // Write footer
    ips_data[ips_size] = 'E';
    ips_data[ips_size + 1] = 'O';
    ips_data[ips_size + 2] = 'F';
    ips_size += 3;

    // Check if file exists and matches
    u8 existing_data[IPS_MAX_SIZE]{};
    u64 existing_size = 0;
    bool file_exists_and_matches = read_ips_file(file_path, existing_data, &existing_size) &&
                                  existing_size == ips_size &&
                                  std::memcmp(existing_data, ips_data, ips_size) == 0;

    if (!file_exists_and_matches) {
        create_directories(patch_dir);
        write_ips_file(file_path, ips_data, ips_size);
    }
}

auto apply_patch(const PatchEntry& patch, ModuleID& out_module_id) -> bool {
    Handle handle{};
    DebugEventInfo event_info{};

    u64 pids[0x50]{};
    s32 process_count{};
    constexpr u64 overlap_size = 0x4f;
    static u8 buffer[READ_BUFFER_SIZE + overlap_size];

    std::memset(buffer, 0, sizeof(buffer));
    out_module_id.fill(0);

    // skip if version isn't valid
    if (VERSION_SKIP &&
        ((patch.min_fw_ver && patch.min_fw_ver > FW_VERSION) ||
        (patch.max_fw_ver && patch.max_fw_ver < FW_VERSION))) {
        for (auto& p : patch.patterns) {
            p.result = PatchResult::SKIPPED;
        }
        return true;
    }

    if (R_FAILED(svcGetProcessList(&process_count, pids, 0x50))) {
        return false;
    }

    for (s32 i = 0; i < (process_count - 1); i++) {
        if (R_SUCCEEDED(svcDebugActiveProcess(&handle, pids[i])) &&
            R_SUCCEEDED(svcGetDebugEvent(&event_info, handle)) &&
            patch.title_id == event_info.title_id) {
            
            // Extract module ID for non-FS/Loader modules
            out_module_id = extract_module_id(handle, patch.title_id);
            std::memset(buffer, 0, sizeof(buffer));
            
            MemoryInfo mem_info{};

            u64 addr{};
            u32 page_info{};

            for (;;) {
                if (R_FAILED(svcQueryDebugProcessMemory(&mem_info, &page_info, handle, addr))) {
                    break;
                }
                addr = mem_info.addr + mem_info.size;

                // if addr=0 then we hit the reserved memory section
                if (!addr) {
                    break;
                }
                // skip memory that we don't want
                if (!mem_info.size || (mem_info.perm & Perm_Rx) != Perm_Rx || ((mem_info.type & 0xFF) != MemType_CodeStatic)) {
                    continue;
                }

                for (u64 sz = 0; sz < mem_info.size; sz += READ_BUFFER_SIZE - overlap_size) {
                    const auto actual_size = std::min(READ_BUFFER_SIZE, mem_info.size - sz);
                    if (R_FAILED(svcReadDebugProcessMemory(buffer + overlap_size, handle, mem_info.addr + sz, actual_size))) {
                        break;
                    } else {
                        patcher(handle, buffer, actual_size + overlap_size, mem_info.addr + sz - overlap_size, patch.patterns);
                        if (actual_size >= overlap_size) {
                            memcpy(buffer, buffer + READ_BUFFER_SIZE, overlap_size);
                            std::memset(buffer + overlap_size, 0, READ_BUFFER_SIZE);
                        } else {
                            std::memset(buffer, 0, sizeof(buffer));
                        }
                    }
                }
            }
            svcCloseHandle(handle);
            return true;
        } else if (handle) {
            svcCloseHandle(handle);
            handle = 0;
        }
    }

    return false;
}

auto create_dir(const char* path) -> bool {
    Result rc{};
    FsFileSystem fs{};
    char path_buf[FS_MAX_PATH]{};

    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    strcpy(path_buf, path);
    rc = fsFsCreateDirectory(&fs, path_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

struct IpsFile {
    FsFileSystem system{};
    FsFile file{};
};

static void ips_tempname(char* dest, const char* source, int maxlength) {
    int len = snprintf(dest, maxlength, "%s.tmp", source);
    if (len < 0 || len >= maxlength) {
        dest[0] = '\0';
    }
}

static bool ips_rename(const char* src, const char* dst) {
    Result rc = {};
    FsFileSystem fs = {};
    char src_buf[FS_MAX_PATH] = {};
    char dst_buf[FS_MAX_PATH] = {};

    if (R_FAILED(rc = fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    strcpy(src_buf, src);
    strcpy(dst_buf, dst);
    rc = fsFsRenameFile(&fs, src_buf, dst_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

static bool ips_delete(const char* filename) {
    Result rc = {};
    FsFileSystem fs = {};
    char filename_buf[FS_MAX_PATH] = {};

    if (R_FAILED(rc = fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    strncpy(filename_buf, filename, sizeof(filename_buf) - 1);
    rc = fsFsDeleteFile(&fs, filename_buf);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc);
}

static void ips_close(IpsFile* f) {
    fsFileClose(&f->file);
    fsFsClose(&f->system);

    f->file = {};
    f->system = {};
}

static bool ips_open(const char* path, IpsFile* out, u32 mode) {
    Result rc = 0;
    char path_buf[FS_MAX_PATH] = {0};

    if (R_FAILED(rc = fsOpenSdCardFileSystem(&out->system))) {
        return false;
    }

    strncpy(path_buf, path, sizeof(path_buf) - 1);

    rc = fsFsOpenFile(&out->system, path_buf, mode, &out->file);
    if (R_SUCCEEDED(rc)) {
        return true;
    }

    if ((mode & FsOpenMode_Write)) {
        if (R_FAILED(fsFsCreateFile(&out->system, path_buf, 0, 0))) {
            fsFsClose(&out->system);
            out->system = {};
            return false;
        }
        if (R_FAILED(rc = fsFsOpenFile(&out->system, path_buf, mode, &out->file))) {
            fsFsClose(&out->system);  // ← Close on failure
            out->system = {};
            return false;
        }
    } else {
        fsFsClose(&out->system);
        out->system = {};
        return false;
    }
    
    return true;
}

auto read_ips_file(const char* path, u8* out_data, u64* out_size) -> bool {
    IpsFile ips{};
    if (!ips_open(path, &ips, FsOpenMode_Read)) {
        return false;
    }

    s64 file_size = 0;
    if (R_FAILED(fsFileGetSize(&ips.file, &file_size)) || file_size <= 0 || file_size > 256) {
        ips_close(&ips);
        return false;
    }

    u64 bytes_read = 0;
    Result rc = fsFileRead(&ips.file, 0, out_data, static_cast<u64>(file_size), FsReadOption_None, &bytes_read);

    ips_close(&ips);

    if (R_SUCCEEDED(rc) && bytes_read == static_cast<u64>(file_size)) {
        *out_size = bytes_read;
        return true;
    }
    return false;
}

auto write_ips_file(const char* path, const u8* data, u64 size) -> bool {
    if (size == 0 || !path || path[0] == '\0') {
        return false;
    }

    char temp_path[FS_MAX_PATH] = {};
    ips_tempname(temp_path, path, sizeof(temp_path));
    if (temp_path[0] == '\0') {
        return false;
    }

    IpsFile ips{};
    if (!ips_open(temp_path, &ips, FsOpenMode_Write | FsOpenMode_Append)) {
        return false;
    }

    if (R_FAILED(fsFileSetSize(&ips.file, size))) {
        ips_close(&ips);
        ips_delete(temp_path);
        return false;
    }

    Result rc = fsFileWrite(&ips.file, 0, const_cast<u8*>(data), size, FsWriteOption_Flush);
    ips_close(&ips);

    if (!R_SUCCEEDED(rc)) {
        ips_delete(temp_path);
        return false;
    }

    if (!ips_rename(temp_path, path)) {
        ips_delete(temp_path);
        return false;
    }

    return true;
}

auto create_directories(const char* path) -> bool {
    if (!path || path[0] != '/') return false;

    FsFileSystem fs{};
    if (R_FAILED(fsOpenSdCardFileSystem(&fs))) {
        return false;
    }

    char tmp[FS_MAX_PATH]{};
    strncpy(tmp, path, sizeof(tmp) - 1);

    char* p = tmp + 1;
    while (*p) {
        if (*p == '/') {
            *p = '\0';
            fsFsCreateDirectory(&fs, tmp);
            *p = '/';
        }
        p++;
    }


    Result rc = fsFsCreateDirectory(&fs, tmp);
    fsFsClose(&fs);
    return R_SUCCEEDED(rc) || rc == 0x402;
}

auto ini_load_or_write_default(const char* section, const char* key, long _default, const char* path) -> long {
    if (!ini_haskey(section, key, path)) {
        ini_putl(section, key, _default, path);
        return _default;
    } else {
        return ini_getbool(section, key, _default, path);
    }
}

auto patch_result_to_str(PatchResult result) -> const char* {
    switch (result) {
        case PatchResult::NOT_FOUND: return "Unpatched";
        case PatchResult::SKIPPED: return "Skipped";
        case PatchResult::DISABLED: return "Disabled";
        case PatchResult::PATCHED_FILE: return "Patched (file)";
        case PatchResult::PATCHED_SYSPATCH: return "Patched (sys-patch)";
        case PatchResult::FAILED_WRITE: return "Failed (svcWriteDebugProcessMemory)";
    }

    std::unreachable();
}

void num_2_str(char*& s, u16 num) {
    u16 max_v = 1000;
    if (num > 9) {
        while (max_v >= 10) {
            if (num >= max_v) {
                while (max_v != 1) {
                    *s++ = '0' + (num / max_v);
                    num -= (num / max_v) * max_v;
                    max_v /= 10;
                }
            } else {
                max_v /= 10;
            }
        }
    }
    *s++ = '0' + (num); // always add 0 or 1's
}

void ms_2_str(char* s, u32 num) {
    u32 max_v = 100;
    *s++ = '0' + (num / 1000); // add seconds
    num -= (num / 1000) * 1000;
    *s++ = '.';

    while (max_v >= 10) {
        if (num >= max_v) {
            while (max_v != 1) {
                *s++ = '0' + (num / max_v);
                num -= (num / max_v) * max_v;
                max_v /= 10;
            }
        }
        else {
           *s++ = '0'; // append 0
           max_v /= 10;
        }
    }
    *s++ = '0' + (num); // always add 0 or 1's
    *s++ = 's'; // in seconds
}

// eg, 852481 -> 13.2.1
void version_to_str(char* s, u32 ver) {
    for (int i = 0; i < 3; i++) {
        num_2_str(s, (ver >> 16) & 0xFF);
        if (i != 2) {
            *s++ = '.';
        }
        ver <<= 8;
    }
}

// eg, 0xAF66FF99 -> AF66FF99
void hash_to_str(char* s, u32 hash) {
    for (int i = 0; i < 4; i++) {
        const auto num = (hash >> 24) & 0xFF;
        const auto top = (num >> 4) & 0xF;
        const auto bottom = (num >> 0) & 0xF;

        constexpr auto a = [](u8 nib) -> char {
            if (nib >= 0 && nib <= 9) { return '0' + nib; }
            return 'a' + nib - 10;
        };

        *s++ = a(top);
        *s++ = a(bottom);

        hash <<= 8;
    }
}

void keygen_to_str(char* s, u8 keygen) {
    num_2_str(s, keygen);
}

} // namespace

int main(int argc, char* argv[]) {
    constexpr auto ini_path = "/config/sys-patch/config.ini";
    constexpr auto log_path = "/config/sys-patch/log.ini";

    create_dir("/config/");
    create_dir("/config/sys-patch/");
    ini_remove(log_path);

    // load options
    const auto patch_sysmmc = ini_load_or_write_default("options", "patch_sysmmc", 1, ini_path);
    const auto patch_emummc = ini_load_or_write_default("options", "patch_emummc", 1, ini_path);
    const auto enable_logging = ini_load_or_write_default("options", "enable_logging", 1, ini_path);
    VERSION_SKIP = ini_load_or_write_default("options", "version_skip", 1, ini_path);

    // load patch toggles
    for (auto& patch : patches) {
        for (auto& p : patch.patterns) {
            p.enabled = ini_load_or_write_default(patch.name, p.patch_name, p.enabled, ini_path);
            if (!p.enabled) {
                p.result = PatchResult::DISABLED;
            }
        }
    }

    const auto emummc = is_emummc();
    bool enable_patching = true;

    // check if we should patch sysmmc
    if (!patch_sysmmc && !emummc) {
        enable_patching = false;
    }

    // check if we should patch emummc
    if (!patch_emummc && emummc) {
        enable_patching = false;
    }

    // speedtest
    const auto ticks_start = armGetSystemTick();

    if (enable_patching) {
        ModuleID module_ids[std::size(patches)]{};
        for (u32 i = 0; i < std::size(patches); i++) {
            apply_patch(patches[i], module_ids[i]);
        }
        
        // Post-processing phase: generate IPS files
        for (u32 i = 0; i < std::size(patches); i++) {
            generate_ips_files(patches[i], module_ids[i]);
        }
    }

    const auto ticks_end = armGetSystemTick();
    const auto diff_ns = armTicksToNs(ticks_end) - armTicksToNs(ticks_start);

    if (enable_logging) {
        for (auto& patch : patches) {
            for (auto& p : patch.patterns) {
                if (!enable_patching) {
                    p.result = PatchResult::SKIPPED;
                }
                ini_puts(patch.name, p.patch_name, patch_result_to_str(p.result), log_path);
            }
        }

        // fw of the system
        char fw_version[12]{};
        // atmosphere version
        char ams_version[12]{};
        // lowest fw supported by atmosphere
        char ams_target_version[12]{};
        // ???
        char ams_keygen[3]{};
        // git commit hash
        char ams_hash[9]{};
        // how long it took to patch
        char patch_time[20]{};

        version_to_str(fw_version, FW_VERSION);
        version_to_str(ams_version, AMS_VERSION);
        version_to_str(ams_target_version, AMS_TARGET_VERSION);
        keygen_to_str(ams_keygen, AMS_KEYGEN);
        hash_to_str(ams_hash, AMS_HASH >> 32);
        ms_2_str(patch_time, diff_ns/1000ULL/1000ULL);

        // defined in the Makefile
        #define DATE (DATE_DAY "." DATE_MONTH "." DATE_YEAR " " DATE_HOUR ":" DATE_MIN ":" DATE_SEC)

        ini_puts("stats", "version", VERSION_WITH_HASH, log_path);
        ini_puts("stats", "build_date", DATE, log_path);
        ini_puts("stats", "fw_version", fw_version, log_path);
        ini_puts("stats", "ams_version", ams_version, log_path);
        ini_puts("stats", "ams_target_version", ams_target_version, log_path);
        ini_puts("stats", "ams_keygen", ams_keygen, log_path);
        ini_puts("stats", "ams_hash", ams_hash, log_path);
        ini_putl("stats", "is_emummc", emummc, log_path);
        ini_putl("stats", "heap_size", INNER_HEAP_SIZE, log_path);
        ini_putl("stats", "buffer_size", READ_BUFFER_SIZE, log_path);
        ini_puts("stats", "patch_time", patch_time, log_path);
    }

    // note: sysmod exits here.
    // to keep it running, add a for (;;) loop (remember to sleep!)
    return 0;
}

// libnx stuff goes below
extern "C" {

// Sysmodules should not use applet*.
u32 __nx_applet_type = AppletType_None;

// Sysmodules will normally only want to use one FS session.
u32 __nx_fs_num_sessions = 1;

// Newlib heap configuration function (makes malloc/free work).
void __libnx_initheap(void) {
    static char inner_heap[INNER_HEAP_SIZE];
    extern char* fake_heap_start;
    extern char* fake_heap_end;

    // Configure the newlib heap.
    fake_heap_start = inner_heap;
    fake_heap_end   = inner_heap + sizeof(inner_heap);
}

// Service initialization.
void __appInit(void) {
    Result rc{};

    // Open a service manager session.
    if (R_FAILED(rc = smInitialize()))
        fatalThrow(rc);

    // Retrieve the current version of Horizon OS.
    if (R_SUCCEEDED(rc = setsysInitialize())) {
        SetSysFirmwareVersion fw{};
        if (R_SUCCEEDED(rc = setsysGetFirmwareVersion(&fw))) {
            FW_VERSION = MAKEHOSVERSION(fw.major, fw.minor, fw.micro);
            hosversionSet(FW_VERSION);
        }
        setsysExit();
    }

    // get ams version
    if (R_SUCCEEDED(rc = splInitialize())) {
        u64 v{};
        u64 hash{};
        if (R_SUCCEEDED(rc = splGetConfig((SplConfigItem)65000, &v))) {
            AMS_VERSION = (v >> 40) & 0xFFFFFF;
            AMS_KEYGEN = (v >> 32) & 0xFF;
            AMS_TARGET_VERSION = v & 0xFFFFFF;
        }
        if (R_SUCCEEDED(rc = splGetConfig((SplConfigItem)65003, &hash))) {
            AMS_HASH = hash;
        }

        splExit();
    }

    if (R_FAILED(rc = fsInitialize()))
        fatalThrow(rc);

    // Add other services you want to use here.
    if (R_FAILED(rc = pmdmntInitialize()))
        fatalThrow(rc);

    // Close the service manager session.
    smExit();
}

// Service deinitialization.
void __appExit(void) {
    pmdmntExit();
    fsExit();
}

} // extern "C"
