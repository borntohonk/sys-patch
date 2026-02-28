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

template<typename T>
constexpr void hex_to_bytes(const char* s, T* data, u8& size) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;

    constexpr auto nibble = [](char c) -> u8 {
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= '0' && c <= '9') return c - '0';
        return 0;
    };

    while (*s) {
        u8 high = nibble(*s++);
        u8 low  = nibble(*s++);
        data[size++] = (high << 4) | low;
    }
}

template<typename T>
constexpr void pattern_to_bytes(const char* s, T* data, u8& size) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;

    constexpr auto nibble = [](char c) -> u8 {
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= '0' && c <= '9') return c - '0';
        return 0xFF; // invalid → will fail match
    };

    while (*s) {
        if (*s == '.') {
            u8 dot_count = 0;
            while (s[dot_count] == '.') ++dot_count;

            u8 wildcards = dot_count / 2;

            for (u8 i = 0; i < wildcards; ++i) {
                data[size++] = REGEX_SKIP;
            }

            s += dot_count;

        } else {
            u16 value = 0;
            bool is_wild_high = false;
            bool is_wild_low  = false;

            // High nibble
            if (*s == '?') {
                is_wild_high = true;
                ++s;
            } else {
                value |= nibble(*s++) << 8;
            }

            // Low nibble
            if (*s == '?') {
                is_wild_low = true;
                ++s;
            } else {
                value |= nibble(*s++);
            }

            if (is_wild_high && is_wild_low) {
                // ?? → full byte wildcard (same as ..)
                data[size++] = REGEX_SKIP;
            } else if (is_wild_high || is_wild_low) {
                // Partial match: store value with high bit set to indicate mask needed
                // We'll use: if value >= 0x100 → it's a masked byte
                // value & 0xFF = actual byte, value >> 8 = mask (0xF0 or 0x0F)
                u8 actual = value & 0xFF;
                u8 mask   = is_wild_high ? 0x0F : 0xF0;
                data[size++] = actual | (static_cast<u16>(mask) << 8);
            } else {
                // Exact byte
                data[size++] = value;
            }
        }
    }
}

struct PatternData {
    constexpr PatternData(const char* s) {
        pattern_to_bytes(s, data, size);
    }

    u16 data[60]{};
    u8 size{};
};

struct PatchData {
    constexpr PatchData(const char* s) {
        hex_to_bytes(s, data, size);
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

    u8 data[20]{};
    u8 size{};
};

enum class PatchResult {
    NOT_FOUND,
    SKIPPED,
    DISABLED,
    PATCHED_FILE,
    PATCHED_SYSPATCH,
    FAILED_WRITE,
};

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
};

struct PatchEntry {
    const char* name; // name of the system title
    const u64 title_id; // title id of the system title
    const std::span<Patterns> patterns; // list of patterns to find
    const u32 min_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
    const u32 max_fw_ver{FW_VER_ANY}; // set to FW_VER_ANY to ignore
};

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

// Note: Patterns can compose of byte wildcards represented as ".." or "??". Patterns can also consist of high, or low nibble wildcarding, represented, with the example being wildcarded being "A9" as "A?" or "?9".
// example 1: just byte wildcarding:
// C8FE4739 -> C8....39 = 2 bytes wildcarded
// C8FE4739 -> C8????39 = 2 bytes wildcarded
// C8FE4739 -> C?F?4??9 = 4 nibbles wildcarded
// nibble wildcarding must be done with "?", and must not be mixed with ".", ".." should be used when wildcarding an entire byte, or "??", but not a mix of "?." or ".?"
// a pattern can contain both "..", "??", or nibble wildcarding, as long as one does not mix "?." or "?."
// patterns should be optimized in such a manner that they yield only one result.
// patterns might yield results for more firmware versions, but if it yields more than one result (per firmware version), it should be condensed to near similar versions instead which only yields one result.
// a pattern should not contain the bytes being patched, they should be wildcarded.
// if the bytes being patched align with the patch partially, then the partial bytes can be in the pattern, the same applies to if the pattern contains the length of the patch.
// the bytes being tested are defined by the _cond, and does not need to be in the pattern, and shouldn't be in the pattern, if the bytes being tested are also the bytes being patched.
// () indicate testing, {} indicate what is being patched
// example:
// "0x00....0240F9........E8", 6, 0,
// the bytes being tested, and patch size is the same, 6 from start of pattern, then patch 0 from start of where the test was designated:
// "0x00....0240F9{(........)}E8"
// if moving the head from what is being tested, the bytes, if in pattern, should be wildcarded by the length of the patch being applied
// "0x00....0240F9........E8C8FE4739", 6, 4,
// example {} should be wildcarded, as those are the bytes being patched, the bytes being tested can in that context contain bytes in the pattern:
// "0x00....0240F9(......94){E8C8FE47}39", 6, 4,
// example with wildcarding:
// "0x00....0240F9(......94){........}39", 6, 4,
//
// designing new patterns should ideally conform to specification above.

constinit Patterns fs_patterns[] = {
    { "noacidsigchk_1.0.0-9.2.0", "0xC8FE4739", -24, 0, bl_cond, ret0_patch, ret0_applied, true, FW_VER_ANY, MAKEHOSVERSION(9,2,0) }, // moved to loader 10.0.0
    { "noacidsigchk_1.0.0-9.2.0", "0x0210911F000072", -5, 0, bl_cond, ret0_patch, ret0_applied, true, FW_VER_ANY, MAKEHOSVERSION(9,2,0) }, // moved to loader 10.0.0
    { "noncasigchk_1.0.0-3.0.2", "0x88..42..58", -4, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(3,0,2) },
    { "noncasigchk_4.0.0-16.1.0", "0x1E4839....00......0054", -17, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(4,0,0), MAKEHOSVERSION(16,1,0) },
    { "noncasigchk_17.0.0+", "0x0694....00..42..0091", -18, 0, tbz_cond, nop_patch, nop_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY },
    { "nocntchk_1.0.0-18.1.0", "0x40F9........081C00121F05", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(18,1,0) },
    { "nocntchk_19.0.0+", "0x40F9............40B9091C", 2, 0, bl_cond, ret0_patch, ret0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
};

constinit Patterns ldr_patterns[] = {
    { "noacidsigchk_10.0.0+", "0x009401C0BE121F00", 6, 2, cmp_cond, cmp_patch, cmp_applied, true, FW_VER_ANY }, // 1F00016B - cmp w0, w1 patched to 1F00006B - cmp w0, w0
};

constinit Patterns erpt_patterns[] = {
    { "no_erpt", "0xFD7B02A9FD830091F76305A9", -4, 0, sub_cond, mov0_ret_patch, mov0_ret_applied, true, FW_VER_ANY }, // FF4305D1 - sub sp, sp, #0x150 patched to E0031F2AC0035FD6 - mov w0, wzr, ret 
};

constinit Patterns es_patterns[] = {
    { "es_1.0.0-8.1.1", "0x0091....0094..7E4092", 10, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(8,1,1) },
    { "es_9.0.0-11.0.1", "0x00..........A0....D1....FF97", 14, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(9,0,0), MAKEHOSVERSION(11,0,1) },
    { "es_12.0.0-18.1.0", "0x02........D2..52....0091", 32, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(12,0,0), MAKEHOSVERSION(18,1,0) },
    { "es_19.0.0+", "0xA1........031F2A....0091", 32, 0, es_cond, mov0_patch, mov0_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
};

constinit Patterns olsc_patterns[] = {
    { "olsc_6.0.0-14.1.2", "0x00..73....F9....4039", 42, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(6,0,0), MAKEHOSVERSION(14,1,2) },
    { "olsc_15.0.0-18.1.0", "0x00..73....F9....4039", 38, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(15,0,0), MAKEHOSVERSION(18,1,0) },
    { "olsc_19.0.0+", "0x00..73....F9....4039", 42, 0, bl_cond, ret1_patch, ret1_applied, true, MAKEHOSVERSION(19,0,0), FW_VER_ANY },
};

constinit Patterns nifm_patterns[] = {
    { "ctest_1.0.0-19.0.1", "0x03..AAE003..AA......39....04F8........E0", -29, 0, ctest_cond, ctest_patch, ctest_applied, true, FW_VER_ANY, MAKEHOSVERSION(19,0,1) },
    { "ctest_20.0.0+", "0x03..AA......AA..................0314AA....14AA", -17, 0, ctest_cond, ctest_patch, ctest_applied, true, MAKEHOSVERSION(20,0,0), FW_VER_ANY },
};

constinit Patterns nim_patterns[] = {
    { "blankcal0crashfix_17.0.0+", "0x00351F2003D5..............................97....0094....00..........61", 6, 0, adr_cond, mov2_patch, mov2_applied, true, MAKEHOSVERSION(17,0,0), FW_VER_ANY },
    { "blockfirmwareupdates_1.0.0-5.1.0", "0x1139F3", -30, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(1,0,0), MAKEHOSVERSION(5,1,0) },
    { "blockfirmwareupdates_6.0.0-6.2.0", "0xF30301AA..4E", -40, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(6,0,0), MAKEHOSVERSION(6,2,0) },
    { "blockfirmwareupdates_7.0.0-10.2.0", "0xF30301AA014C", -36, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(7,0,0), MAKEHOSVERSION(10,2,0) },
    { "blockfirmwareupdates_11.0.0-11.0.1", "0x9AF0....................C0035FD6", 16, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(11,0,0), MAKEHOSVERSION(11,0,1) },
    { "blockfirmwareupdates_12.0.0+", "0x41....4C............C0035FD6", 14, 0, block_fw_updates_cond, mov0_ret_patch, mov0_ret_applied, true, MAKEHOSVERSION(12,0,0), FW_VER_ANY },
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

void patcher(Handle handle, const u8* data, size_t data_size, u64 addr, std::span<Patterns> patterns) {
    for (auto& p : patterns) {
        // skip if disabled (controller by config.ini)
        if (p.result == PatchResult::DISABLED) {
            continue;
        }

        // skip if version isn't valid
        if (VERSION_SKIP &&
            ((p.min_fw_ver && p.min_fw_ver > FW_VERSION) ||
            (p.max_fw_ver && p.max_fw_ver < FW_VERSION) ||
            (p.min_ams_ver && p.min_ams_ver > AMS_VERSION) ||
            (p.max_ams_ver && p.max_ams_ver < AMS_VERSION))) {
            p.result = PatchResult::SKIPPED;
            continue;
        }

        // skip if already patched
        if (p.result == PatchResult::PATCHED_FILE || p.result == PatchResult::PATCHED_SYSPATCH) {
            continue;
        }

        // Try to find and apply this pattern
        bool found = false;
        for (u32 i = 0; i < data_size && !found; i++) {
            if (i + p.byte_pattern.size >= data_size) {
                break;
            }

            // loop through every byte of the pattern data to find a match
            // skipping over any bytes if the value is REGEX_SKIP
            u32 count{};
            while (count < p.byte_pattern.size) {
                u16 pattern_entry = p.byte_pattern.data[count];
                u8 memory_byte    = data[i + count];

                if (pattern_entry == REGEX_SKIP) {
                    // full wildcard — always matches
                } else if (pattern_entry > 0xFF) {
                    // masked nibble match
                    u8 expected = pattern_entry & 0xFF;
                    u8 mask     = pattern_entry >> 8;
                    if ((memory_byte & mask) != (expected & mask)) {
                        break;
                    }
                } else {
                    if (memory_byte != pattern_entry) {
                        break;
                    }
                }
                count++;
            }

            // if we have found a matching pattern
            if (count == p.byte_pattern.size) {
                // fetch the instruction
                u32 inst{};
                const auto inst_offset = i + p.inst_offset;
                std::memcpy(&inst, data + inst_offset, sizeof(inst));

                // check if the instruction is the one that we want
                if (p.cond(inst)) {
                    const auto patch_data = p.patch(inst);
                    const auto patch_offset = addr + inst_offset + p.patch_offset;

                    // todo: log failed writes, although this should in theory never fail
                    if (R_FAILED(svcWriteDebugProcessMemory(handle, &patch_data, patch_offset, patch_data.size))) {
                        p.result = PatchResult::FAILED_WRITE;
                    } else {
                        p.result = PatchResult::PATCHED_SYSPATCH;
                    }
                    found = true;
                } else if (p.applied(data + inst_offset + p.patch_offset, inst)) {
                    // patch already applied by sigpatches
                    p.result = PatchResult::PATCHED_FILE;
                    found = true;
                }
            }
        }
    }
}

// Check if a patch entry is valid for the current firmware version
auto is_patch_version_valid(const PatchEntry& patch) -> bool {
    if (!VERSION_SKIP) {
        return true;
    }
    return !(patch.min_fw_ver && patch.min_fw_ver > FW_VERSION) &&
           !(patch.max_fw_ver && patch.max_fw_ver < FW_VERSION);
}




// Find and open the process with the given title_id
auto find_process_by_title_id(u64 title_id, Handle& out_handle) -> bool {
    u64 pids[0x50]{};
    s32 process_count{};

    if (R_FAILED(svcGetProcessList(&process_count, pids, 0x50))) {
        return false;
    }

    for (s32 i = 0; i < process_count; i++) {
        Handle handle{};
        #ifdef USE_DEBUG_EVENT
            DebugEvent event{};
        #else
            DebugEventInfo event{};
        #endif

        if (R_FAILED(svcDebugActiveProcess(&handle, pids[i]))) {
            continue;
        }

        if (R_SUCCEEDED(svcGetDebugEvent(&event, handle))) {
            if (event.type == DebugEventType_CreateProcess &&
                event.info.create_process.program_id == title_id) {
                out_handle = handle;
                return true;
            }
        }

        svcCloseHandle(handle);
    }

    return false;
}

// Patch all executable memory regions in a process
auto patch_process_memory(Handle handle, const PatchEntry& patch, u8* buffer, u64 overlap_size) -> void {
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

        // Process this memory region in chunks
        for (u64 sz = 0; sz < mem_info.size; sz += READ_BUFFER_SIZE - overlap_size) {
            const auto actual_size = std::min(READ_BUFFER_SIZE, mem_info.size - sz);
            if (R_FAILED(svcReadDebugProcessMemory(buffer + overlap_size, handle, mem_info.addr + sz, actual_size))) {
                break;
            } else {
                patcher(handle, buffer, actual_size + overlap_size, mem_info.addr + sz - overlap_size, patch.patterns);
                
                // Manage overlap buffer for next iteration
                if (actual_size >= overlap_size) {
                    memcpy(buffer, buffer + READ_BUFFER_SIZE, overlap_size);
                    std::memset(buffer + overlap_size, 0, READ_BUFFER_SIZE);
                } else {
                    const auto bytes_to_overlap = std::min<u64>(overlap_size, actual_size);
                    memcpy(buffer, buffer + READ_BUFFER_SIZE + (actual_size - bytes_to_overlap), bytes_to_overlap);
                    std::memset(buffer + bytes_to_overlap, 0, sizeof(buffer) - bytes_to_overlap);
                }
            }
        }
    }
}

auto apply_patch(PatchEntry& patch) -> bool {
    // skip if version isn't valid
    if (!is_patch_version_valid(patch)) {
        for (auto& p : patch.patterns) {
            p.result = PatchResult::SKIPPED;
        }
        return true;
    }

    Handle handle{};

    if (!find_process_by_title_id(patch.title_id, handle)) {
        return false;
    }

    constexpr u64 overlap_size = 0x4f;
    static u8 buffer[READ_BUFFER_SIZE + overlap_size];
    std::memset(buffer, 0, sizeof(buffer));

    patch_process_memory(handle, patch, buffer, overlap_size);
    
    svcCloseHandle(handle);
    return true;
}

// creates a directory, non-recursive!
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

// same as ini_get but writes out the default value instead
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
        for (auto& patch : patches) {
            apply_patch(patch);
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
