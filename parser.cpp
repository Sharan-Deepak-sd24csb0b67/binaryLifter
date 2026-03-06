#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <map>
#include <set>

enum Opcode {
    IR_NOP,
    IR_ADD,
    IR_SUB,
    IR_MOV,
    IR_LDR,
    IR_STR,
    IR_B,
    IR_BL,
    IR_RET,
    IR_CBZ,
    IR_CBNZ,
    IR_OTHER
};

struct IRInst {
    Opcode op;
    uint64_t addr;
    int dst;
    int src1;
    int src2;
    int64_t imm;
    bool block_end;
};

static std::map<uint64_t,std::string> symbol_table;
static std::set<uint64_t> taint_addresses;

static const std::set<std::string> taint_funcs = {
    "strcpy","gets","memcpy","sprintf","strcat","scanf",
    "strncpy","strncat","vsprintf","_strcpy", "_gets", "_memcpy", "_sprintf", "_strcat",
    "_scanf", "_strncpy", "_strncat", "_vsprintf"};

#define LC_SYMTAB 0x2

struct symtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
};

struct nlist_64 {
    union { uint32_t n_strx; } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

#ifdef __has_include
  #if __has_include(<capstone/capstone.h>) || \
      __has_include("/opt/homebrew/include/capstone/capstone.h")
    #include <capstone/capstone.h>
    #define HAVE_CAPSTONE 1
  #else
    #warning "Capstone header not found; disassembly will be disabled"
  #endif
#else
  #include <capstone/capstone.h>
  #define HAVE_CAPSTONE 1
#endif

#ifdef HAVE_CAPSTONE
static int regmap(unsigned reg) {
    switch(reg) {
        case ARM64_REG_X0: return 0;
        case ARM64_REG_X1: return 1;
        case ARM64_REG_X2: return 2;
        case ARM64_REG_X3: return 3;
        case ARM64_REG_X4: return 4;
        case ARM64_REG_X5: return 5;
        case ARM64_REG_X6: return 6;
        case ARM64_REG_X7: return 7;
        case ARM64_REG_X8: return 8;
        case ARM64_REG_X9: return 9;
        case ARM64_REG_X10: return 10;
        case ARM64_REG_X11: return 11;
        case ARM64_REG_X12: return 12;
        case ARM64_REG_X13: return 13;
        case ARM64_REG_X14: return 14;
        case ARM64_REG_X15: return 15;
        case ARM64_REG_X16: return 16;
        case ARM64_REG_X17: return 17;
        case ARM64_REG_X18: return 18;
        case ARM64_REG_X19: return 19;
        case ARM64_REG_X20: return 20;
        case ARM64_REG_X21: return 21;
        case ARM64_REG_X22: return 22;
        case ARM64_REG_X23: return 23;
        case ARM64_REG_X24: return 24;
        case ARM64_REG_X25: return 25;
        case ARM64_REG_X26: return 26;
        case ARM64_REG_X27: return 27;
        case ARM64_REG_X28: return 28;
        case ARM64_REG_X29: return 29;
        case ARM64_REG_X30: return 30;
        case ARM64_REG_SP: return 31;
        default: return -1;
    }
}
#else
static int regmap(unsigned) { return -1; }
#endif

#ifdef HAVE_CAPSTONE
struct IRInst lift_one(const cs_insn &insn);
#endif

#define MH_MAGIC_64 0xfeedfacf
#define LC_SEGMENT_64 0x19
#define LC_MAIN 0x80000028

using namespace std;

struct mach_header_64 {
    uint32_t magic;
    int32_t  cputype;
    int32_t  cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

struct segment_command_64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    int32_t  maxprot;
    int32_t  initprot;
    uint32_t nsects;
    uint32_t flags;
};

struct section_64 {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
};

struct entry_point_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;
    uint64_t stacksize;
};

#if defined(HAVE_CAPSTONE)
vector<IRInst> disassemble_text_section(const vector<uint8_t>& code, uint64_t address) {
    vector<IRInst> irlist;
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        cerr << "[-] Failed to initialize Capstone Engine" << endl;
        return irlist;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cout << "\n[+] Disassembling __text section..." << endl;
    cout << "---------------------------------------------------------------" << endl;
    cout << " Address        | Mnemonic      | Operands" << endl;
    cout << "---------------------------------------------------------------" << endl;

    count = cs_disasm(handle, code.data(), code.size(), address, 0, &insn);
    
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            cout << " 0x" << hex << insn[i].address << " | " 
                      << setw(13) << left << insn[i].mnemonic << " | " 
                      << insn[i].op_str << endl;
            irlist.push_back(lift_one(insn[i]));
        }
        cs_free(insn, count);
    } else {
        cerr << "[-] Failed to disassemble code! (Count: 0)" << endl;
    }

    cs_close(&handle);
    return irlist;
}
#else
vector<IRInst> disassemble_text_section(const vector<uint8_t>&, uint64_t) {
    cerr << "[!] Capstone unavailable; skipping disassembly." << endl;
    return {};
}
#endif

IRInst lift_one(const cs_insn &insn) {
    IRInst inst{};
    inst.addr = insn.address;
    inst.dst = inst.src1 = inst.src2 = -1;
    inst.imm = 0;
    inst.block_end = false;

    string mnem(insn.mnemonic);
    if (mnem == "add") inst.op = IR_ADD;
    else if (mnem == "sub") inst.op = IR_SUB;
    else if (mnem == "mov") inst.op = IR_MOV;
    else if (mnem == "ldr") inst.op = IR_LDR;
    else if (mnem == "str") inst.op = IR_STR;
    else if (mnem == "b") { inst.op = IR_B; inst.block_end = true; }
    else if (mnem == "bl") { inst.op = IR_BL; inst.block_end = true; }
    else if (mnem == "ret") { inst.op = IR_RET; inst.block_end = true; }
    else if (mnem == "cbz") { inst.op = IR_CBZ; inst.block_end = true; }
    else if (mnem == "cbnz") { inst.op = IR_CBNZ; inst.block_end = true; }
    else inst.op = IR_OTHER;

    if (insn.detail && insn.detail->arm64.op_count > 0) {
        int opcount = insn.detail->arm64.op_count;
        const cs_arm64_op *ops = insn.detail->arm64.operands;
        if (opcount > 0 && ops[0].type == ARM64_OP_REG)
            inst.dst = regmap(ops[0].reg);
        if (opcount > 1) {
            if (ops[1].type == ARM64_OP_REG)
                inst.src1 = regmap(ops[1].reg);
            else if (ops[1].type == ARM64_OP_IMM)
                inst.imm = ops[1].imm;
        }
        if (opcount > 2 && ops[2].type == ARM64_OP_REG)
            inst.src2 = regmap(ops[2].reg);
    }

    if (inst.op == IR_BL) {
        uint64_t target = 0;
        if (insn.detail && insn.detail->arm64.op_count > 0 &&
            insn.detail->arm64.operands[0].type == ARM64_OP_IMM) {
            target = insn.detail->arm64.operands[0].imm;
        }
        if (taint_addresses.count(target)) {
            cout << "[!] Tainted branch to 0x" << hex << target << dec << endl;
        } else {
            auto it = symbol_table.find(target);
            if (it != symbol_table.end() && taint_funcs.count(it->second)) {
                cout << "[!] Taint source call to " << it->second
                     << " at 0x" << hex << target << dec << endl;
            }
        }
    }
    return inst;
}

void parse_symbol_table(ifstream& file, const symtab_command& st) {
    vector<char> strtab(st.strsize);
    file.seekg(st.stroff);
    file.read(strtab.data(), st.strsize);

    file.seekg(st.symoff);
    for (uint32_t i = 0; i < st.nsyms; ++i) {
        nlist_64 nl;
        file.read(reinterpret_cast<char*>(&nl), sizeof(nl));
        if (nl.n_un.n_strx < st.strsize) {
            const char* name = strtab.data() + nl.n_un.n_strx;
            string sname(name);
            symbol_table[nl.n_value] = sname;
            if (taint_funcs.count(sname)) {
                cout << "[!] Taint symbol present: " << sname << endl;
                if (nl.n_value != 0)
                    taint_addresses.insert(nl.n_value);
            }
        }
    }
    cout << "[+] Loaded " << st.nsyms << " symbols from symbol table." << endl;
}

void print_ir(const vector<IRInst>& ir) {
    cout << "\n[+] IR listing (simple)" << endl;
    cout << "Addr        | Op    | dst src1 src2 imm" << endl;
    cout << "----------------------------------------" << endl;
    for (const auto &i : ir) {
        if (i.block_end) cout << "[BB END]" << endl;
        cout << "0x" << hex << i.addr << dec << " | " << i.op
             << " | " << i.dst << " " << i.src1 << " " << i.src2
             << " " << i.imm << endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <path_to_macho_binary>" << endl;
        return 1;
    }

    ifstream file(argv[1], ios::binary);
    if (!file) {
        cerr << "Error: Could not open file." << endl;
        return 1;
    }

    mach_header_64 header;
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (header.magic != MH_MAGIC_64) {
        cerr << "Error: Not a valid 64-bit Mach-O file." << endl;
        return 1;
    }

    cout << "--- Mach-O Header Parsed ---" << endl;
    cout << "Number of Load Commands: " << header.ncmds << endl;

    uint64_t target_offset = 0;
    uint64_t target_size = 0;
    uint64_t target_addr = 0;
    bool found_code = false;

    for (uint32_t i = 0; i < header.ncmds; ++i) {
        load_command lc;
        streampos currentPos = file.tellg();
        file.read(reinterpret_cast<char*>(&lc), sizeof(lc));

        if (lc.cmd == LC_SEGMENT_64) {
            file.seekg(currentPos);
            segment_command_64 seg;
            file.read(reinterpret_cast<char*>(&seg), sizeof(seg));

            cout << "\n[+] Found LC_SEGMENT_64" << endl;
            cout << "    Segment Name: " << seg.segname << endl;
            cout << "    VM Address:   0x" << hex << seg.vmaddr << dec << endl;
            cout << "    File Offset:  " << seg.fileoff << endl;
            cout << "    File Size:    " << seg.filesize << endl;

            if (strcmp(seg.segname, "__TEXT") == 0) {
                cout << "    >> TARGET IDENTIFIED: This contains executable instructions." << endl;

                for (uint32_t j = 0; j < seg.nsects; ++j) {
                    section_64 sect;
                    file.read(reinterpret_cast<char*>(&sect), sizeof(sect));

                    if (strcmp(sect.sectname, "__text") == 0) {
                        target_offset = sect.offset;
                        target_size = sect.size;
                        target_addr = sect.addr;
                        found_code = true;
                    }
                }
            }
            file.seekg(currentPos + (streampos)lc.cmdsize);
        }
        else if (lc.cmd == LC_SYMTAB) {
            file.seekg(currentPos);
            symtab_command st;
            file.read(reinterpret_cast<char*>(&st), sizeof(st));
            parse_symbol_table(file, st);
            file.seekg(currentPos + (streampos)lc.cmdsize);
        }
        else if (lc.cmd == LC_MAIN) {
            file.seekg(currentPos);
            entry_point_command ep;
            file.read(reinterpret_cast<char*>(&ep), sizeof(ep));

            cout << "\n[+] Found LC_MAIN" << endl;
            cout << "    Entry Point Offset: " << ep.entryoff << endl;
            cout << "    >> ENTRY POINT LOCATED: Start disassembly here." << endl;

            file.seekg(currentPos + (streampos)lc.cmdsize);
        }
        else {
            file.seekg(currentPos + (streampos)lc.cmdsize);
        }
    }
    if (found_code) {
        file.seekg(target_offset);
        vector<uint8_t> buffer(target_size);
        file.read(reinterpret_cast<char*>(buffer.data()), target_size);

        vector<IRInst> ir = disassemble_text_section(buffer, target_addr);
        print_ir(ir);
    }

    file.close();
    return 0;
}
