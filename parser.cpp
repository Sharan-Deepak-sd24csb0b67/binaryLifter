#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <algorithm>
#include <cstdint>
#include <sstream>

using namespace std;

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
    Opcode   op;
    uint64_t addr;
    int      dst;
    int      src1;
    int      src2;
    int64_t  imm;
    bool     block_end;
};

static map<uint64_t, string> symbol_table;
static set<uint64_t>         taint_addresses;

static const set<string> taint_funcs = {
    "strcpy","gets","memcpy","sprintf","strcat","scanf",
    "strncpy","strncat","vsprintf","read","fgets","sscanf"
};

static set<int>     tainted_registers;
static set<int64_t> tainted_stack_offsets;

#define MH_MAGIC_64   0xfeedfacf
#define LC_SEGMENT_64 0x19
#define LC_SYMTAB     0x2
#define LC_DYSYMTAB   0xb
#define LC_MAIN       0x80000028

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
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
};

struct dysymtab_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;   

    uint32_t nindirectsyms;    

    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
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
    switch (reg) {
        case ARM64_REG_X0:  return 0;  case ARM64_REG_X1:  return 1;
        case ARM64_REG_X2:  return 2;  case ARM64_REG_X3:  return 3;
        case ARM64_REG_X4:  return 4;  case ARM64_REG_X5:  return 5;
        case ARM64_REG_X6:  return 6;  case ARM64_REG_X7:  return 7;
        case ARM64_REG_X8:  return 8;  case ARM64_REG_X9:  return 9;
        case ARM64_REG_X10: return 10; case ARM64_REG_X11: return 11;
        case ARM64_REG_X12: return 12; case ARM64_REG_X13: return 13;
        case ARM64_REG_X14: return 14; case ARM64_REG_X15: return 15;
        case ARM64_REG_X16: return 16; case ARM64_REG_X17: return 17;
        case ARM64_REG_X18: return 18; case ARM64_REG_X19: return 19;
        case ARM64_REG_X20: return 20; case ARM64_REG_X21: return 21;
        case ARM64_REG_X22: return 22; case ARM64_REG_X23: return 23;
        case ARM64_REG_X24: return 24; case ARM64_REG_X25: return 25;
        case ARM64_REG_X26: return 26; case ARM64_REG_X27: return 27;
        case ARM64_REG_X28: return 28; case ARM64_REG_X29: return 29;
        case ARM64_REG_X30: return 30; case ARM64_REG_SP:  return 31;
        default: return -1;
    }
}

struct IRInst lift_one(const cs_insn &insn);
#else
static int regmap(unsigned) { return -1; }
#endif

void parse_symbol_table(ifstream& file, const symtab_command& st) {
    vector<char> strtab(st.strsize);
    file.seekg(st.stroff);
    file.read(strtab.data(), st.strsize);

    file.seekg(st.symoff);
    for (uint32_t i = 0; i < st.nsyms; ++i) {
        nlist_64 nl;
        file.read(reinterpret_cast<char*>(&nl), sizeof(nl));
        if (nl.n_un.n_strx < st.strsize) {
            string sname(strtab.data() + nl.n_un.n_strx);
            if (!sname.empty() && sname[0] == '_')
                sname = sname.substr(1);

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

#ifdef HAVE_CAPSTONE
IRInst lift_one(const cs_insn &insn) {
    IRInst inst{};
    inst.addr      = insn.address;
    inst.dst       = inst.src1 = inst.src2 = -1;
    inst.imm       = 0;
    inst.block_end = false;

    string mnem(insn.mnemonic);
    if      (mnem == "add")  inst.op = IR_ADD;
    else if (mnem == "sub")  inst.op = IR_SUB;
    else if (mnem == "mov")  inst.op = IR_MOV;
    else if (mnem == "ldr")  inst.op = IR_LDR;
    else if (mnem == "str")  inst.op = IR_STR;
    else if (mnem == "b")  { inst.op = IR_B;    inst.block_end = true; }
    else if (mnem == "bl") { inst.op = IR_BL;   inst.block_end = true; }
    else if (mnem == "ret"){ inst.op = IR_RET;  inst.block_end = true; }
    else if (mnem == "cbz") { inst.op = IR_CBZ;  inst.block_end = true; }
    else if (mnem == "cbnz"){ inst.op = IR_CBNZ; inst.block_end = true; }
    else inst.op = IR_OTHER;

    if (insn.detail && insn.detail->arm64.op_count > 0) {
        int opcount          = insn.detail->arm64.op_count;
        const cs_arm64_op *ops = insn.detail->arm64.operands;

        if (opcount > 0 && ops[0].type == ARM64_OP_REG)
            inst.dst = regmap(ops[0].reg);

        if (opcount > 1) {
            if      (ops[1].type == ARM64_OP_REG) inst.src1 = regmap(ops[1].reg);
            else if (ops[1].type == ARM64_OP_IMM) inst.imm  = ops[1].imm;
            else if (ops[1].type == ARM64_OP_MEM) inst.src1 = regmap(ops[1].mem.base);
        }

        if (opcount > 2 && ops[2].type == ARM64_OP_REG)
            inst.src2 = regmap(ops[2].reg);
    }

    if (inst.op == IR_BL) {
        uint64_t target = 0;
        if (insn.detail && insn.detail->arm64.op_count > 0 &&
            insn.detail->arm64.operands[0].type == ARM64_OP_IMM) {
            target   = insn.detail->arm64.operands[0].imm;
            inst.imm = (int64_t)target;
        }
        if (taint_addresses.count(target)) {
            cout << "[!] Tainted branch to 0x" << hex << target << dec << endl;
        } else {
            auto it = symbol_table.find(target);
            if (it != symbol_table.end() && taint_funcs.count(it->second))
                cout << "[!] Taint source call to " << it->second
                     << " at 0x" << hex << target << dec << endl;
        }
    }
    return inst;
}
#endif

#ifdef HAVE_CAPSTONE
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
            cout << " 0x" << hex << insn[i].address
                 << " | " << setw(13) << left << insn[i].mnemonic
                 << " | " << insn[i].op_str << dec << endl;
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

void print_ir(const vector<IRInst>& ir) {
    cout << "\n[+] IR listing (simple)" << endl;
    cout << "Addr        | Op    | dst src1 src2 imm" << endl;
    cout << "----------------------------------------" << endl;
    for (const auto &i : ir) {
        if (i.block_end) cout << "[BB END]" << endl;
        cout << "0x" << hex << i.addr << dec
             << " | " << i.op
             << " | " << i.dst << " " << i.src1 << " " << i.src2
             << " " << hex << i.imm << dec << endl;
    }
}

void run_taint_analysis(const vector<IRInst>& ir) {
    cout << "\n[+] Taint Analysis — tracking " << ir.size() << " instructions." << endl;
    cout << "------------------------------------------------------------" << endl;

    tainted_registers.clear();
    tainted_stack_offsets.clear();

    bool found_sink = false;

    for (const auto& inst : ir) {
        bool   activity = false;
        string log;

        if (inst.op == IR_BL) {
            uint64_t target = (uint64_t)inst.imm;
            string   name;
            auto it = symbol_table.find(target);
            if (it != symbol_table.end()) name = it->second;

            bool is_taint_source = taint_funcs.count(name) ||
                                   taint_addresses.count(target);

            if (is_taint_source) {

                tainted_registers.insert(0);
                activity = true;
                log = "SOURCE: call to [" + (name.empty() ? "0x" + to_string(target) : name)
                    + "] — X0 marked TAINTED";
            }
        }

        switch (inst.op) {

            case IR_STR:
                if (tainted_registers.count(inst.dst)) {
                    tainted_stack_offsets.insert(inst.imm);
                    activity = true;
                    log = "STORE: X" + to_string(inst.dst)
                        + " → stack[" + to_string(inst.imm) + "] (tainted)";
                }
                break;

            case IR_LDR:
                if (tainted_stack_offsets.count(inst.imm)) {
                    tainted_registers.insert(inst.dst);
                    activity = true;
                    log = "LOAD: stack[" + to_string(inst.imm)
                        + "] → X" + to_string(inst.dst) + " (now tainted)";
                }
                break;

            case IR_MOV:
            case IR_ADD:
            case IR_SUB:  // FIX: SUB was missing
                if (inst.dst >= 0) {
                    bool src1_tainted = (inst.src1 >= 0 && tainted_registers.count(inst.src1));
                    bool src2_tainted = (inst.src2 >= 0 && tainted_registers.count(inst.src2));
                    if (src1_tainted || src2_tainted) {
                        tainted_registers.insert(inst.dst);
                        activity = true;
                        int src = src1_tainted ? inst.src1 : inst.src2;
                        log = "SPREAD: X" + to_string(src)
                            + " → X" + to_string(inst.dst);
                    }
                }
                break;

            case IR_RET:
                if (tainted_registers.count(0)) {
                    found_sink = true;
                    activity   = true;
                    log = "!!! CRITICAL SINK: Tainted value in X0 reaches RET !!!";
                }
                break;

            case IR_OTHER:
                if (inst.src1 >= 0 && tainted_registers.count(inst.src1)) {
                    if (inst.dst >= 0) {
                        tainted_registers.insert(inst.dst);
                        activity = true;
                        log = "GENERIC SPREAD: [X" + to_string(inst.src1)
                            + "] → X" + to_string(inst.dst);
                    }
                }
                break;

            default: break;
        }

        if (activity)
            cout << " [T] 0x" << hex << inst.addr << dec << " | " << log << endl;
    }

    cout << "------------------------------------------------------------" << endl;
    if (found_sink)
        cout << "[!!!] VULNERABILITY DETECTED: Tainted data reaches a critical sink!" << endl;
    else
        cout << "[OK] No critical sink reached by tainted data." << endl;
}

struct RopGadget {
    uint64_t        start_addr;
    vector<uint64_t> insn_addrs;  

    string          category;
    string          description;
};

static string classify_gadget(const vector<IRInst>& window) {
    bool loads_x0  = false, loads_x1  = false, loads_x2  = false;
    bool pops_sp   = false;
    bool has_store = false;
    bool has_arith = false;

    for (const auto& i : window) {

        if (i.op == IR_LDR) {
            if (i.dst == 0)  loads_x0 = true;
            if (i.dst == 1)  loads_x1 = true;
            if (i.dst == 2)  loads_x2 = true;

            if (i.dst == 29 || i.dst == 30) pops_sp = true;
        }
        if (i.op == IR_STR)  has_store = true;
        if (i.op == IR_ADD || i.op == IR_SUB) has_arith = true;
    }

    if (pops_sp)            return "STACK_PIVOT";
    if (loads_x0 && loads_x1 && loads_x2) return "LOAD_ARGS_X0_X1_X2";
    if (loads_x0 && loads_x1) return "LOAD_ARGS_X0_X1";
    if (loads_x0)           return "LOAD_ARG_X0";
    if (has_store && has_arith) return "STORE_WITH_ARITH";
    if (has_store)          return "STORE_GADGET";
    if (has_arith)          return "ARITHMETIC";
    return "GENERIC";
}

vector<RopGadget> scan_rop_gadgets(const vector<IRInst>& ir,
                                    size_t max_window = 5) {
    vector<RopGadget> gadgets;

    for (size_t i = 0; i < ir.size(); ++i) {
        if (ir[i].op != IR_RET) continue;

        size_t start = (i >= max_window) ? (i - max_window) : 0;

        vector<IRInst> window(ir.begin() + start, ir.begin() + i);

        RopGadget g;
        g.start_addr = ir[start].addr;
        for (size_t k = start; k <= i; ++k)
            g.insn_addrs.push_back(ir[k].addr);
        g.category    = classify_gadget(window);
        g.description = "RET at 0x" + [&](){
            ostringstream oss;
            oss << hex << ir[i].addr;
            return oss.str();
        }();
        gadgets.push_back(g);
    }
    return gadgets;
}

void print_rop_gadgets(const vector<RopGadget>& gadgets) {
    cout << "\n[+] ROP Gadget Scan Results — " << gadgets.size() << " gadget(s) found." << endl;
    cout << "------------------------------------------------------------" << endl;

    if (gadgets.empty()) {
        cout << "    No gadgets found." << endl;
        return;
    }

    map<string, vector<const RopGadget*>> by_cat;
    for (const auto& g : gadgets)
        by_cat[g.category].push_back(&g);

    for (const auto& [cat, list] : by_cat) {
        cout << "\n  Category: " << cat << " (" << list.size() << " gadget(s))" << endl;
        for (const auto* g : list) {
            cout << "    Start: 0x" << hex << g->start_addr
                 << "  Addrs: ["; 
            for (size_t k = 0; k < g->insn_addrs.size(); ++k) {
                if (k) cout << ", ";
                cout << "0x" << hex << g->insn_addrs[k];
            }
            cout << "]" << dec << endl;
        }
    }

    cout << "\n  [!] Dangerous gadget categories detected:" << endl;
    for (const auto& [cat, list] : by_cat) {
        if (cat == "STACK_PIVOT" || cat == "LOAD_ARG_X0" ||
            cat == "LOAD_ARGS_X0_X1" || cat == "LOAD_ARGS_X0_X1_X2") {
            cout << "    *** " << cat << " x" << list.size()
                 << " — usable in ROP chain! ***" << endl;
        }
    }
}

bool is_false_positive(const vector<IRInst>& ir) {

    bool has_bounded_source   = false;
    bool has_unbounded_source = false;
    bool has_ret_sink         = false;

    for (const auto& inst : ir) {
        if (inst.op == IR_BL) {
            uint64_t target = (uint64_t)inst.imm;
            auto it = symbol_table.find(target);
            string name = (it != symbol_table.end()) ? it->second : "";
            if (name == "fgets" || name == "strncpy" || name == "strncat")
                has_bounded_source = true;
            else if (taint_funcs.count(name) || taint_addresses.count(target))
                has_unbounded_source = true;
        }
        if (inst.op == IR_RET && tainted_registers.count(0))
            has_ret_sink = true;
    }

    if (has_bounded_source && !has_unbounded_source && !has_ret_sink)
        return true;

    return false;
}

void print_analysis_verdict(const vector<IRInst>& ir,
                             const vector<RopGadget>& gadgets) {
    cout << "\n=========================================================" << endl;
    cout << "  VULNERABILITY ANALYSIS VERDICT" << endl;
    cout << "=========================================================" << endl;

    bool taint_vuln = tainted_registers.count(0) > 0 ||
                      !tainted_stack_offsets.empty();
    bool rop_risk   = !gadgets.empty();
    bool fp         = is_false_positive(ir);

    if (taint_vuln && !fp) {
        cout << "  [HIGH] Taint analysis found potentially exploitable data flow." << endl;
        cout << "         Tainted registers  : ";
        for (int r : tainted_registers) cout << "X" << r << " ";
        cout << endl;
        cout << "         Tainted stack slots: ";
        for (int64_t o : tainted_stack_offsets) cout << "[sp+" << o << "] ";
        cout << endl;
    } else if (taint_vuln && fp) {
        cout << "  [LOW/FP] Taint flow detected but likely a false positive." << endl;
        cout << "           (Only bounded-length sources found; no critical sink reached.)" << endl;
    } else {
        cout << "  [OK] No dangerous taint flow detected." << endl;
    }

    if (rop_risk) {
        cout << "  [WARN] " << gadgets.size()
             << " ROP gadget(s) found — binary may be exploitable via ROP chain." << endl;
    } else {
        cout << "  [OK] No ROP gadgets identified." << endl;
    }

    cout << "=========================================================" << endl;
}

void resolve_stubs(ifstream& file,
                   const dysymtab_command& dysym,
                   const symtab_command&   symtab_cmd,
                   uint64_t stubs_addr,
                   uint32_t stubs_first_indirect_idx,
                   uint32_t stubs_num_slots)
{
    if (stubs_num_slots == 0) return;

    vector<uint32_t> indirect(dysym.nindirectsyms);
    file.seekg(dysym.indirectsymoff);
    file.read(reinterpret_cast<char*>(indirect.data()),
              dysym.nindirectsyms * sizeof(uint32_t));

    vector<char> strtab(symtab_cmd.strsize);
    file.seekg(symtab_cmd.stroff);
    file.read(strtab.data(), symtab_cmd.strsize);

    vector<nlist_64> syms(symtab_cmd.nsyms);
    file.seekg(symtab_cmd.symoff);
    file.read(reinterpret_cast<char*>(syms.data()),
              symtab_cmd.nsyms * sizeof(nlist_64));

    cout << "\n[+] Resolving " << stubs_num_slots << " stub(s)..." << endl;

    const uint64_t STUB_STRIDE = 12; 

    for (uint32_t slot = 0; slot < stubs_num_slots; ++slot) {
        uint32_t indirect_idx = stubs_first_indirect_idx + slot;
        if (indirect_idx >= dysym.nindirectsyms) continue;

        uint32_t sym_idx = indirect[indirect_idx];

        if (sym_idx == 0x80000000 || sym_idx == 0x40000000) continue;
        if (sym_idx >= symtab_cmd.nsyms) continue;

        const nlist_64& nl = syms[sym_idx];
        if (nl.n_un.n_strx >= symtab_cmd.strsize) continue;

        string name(strtab.data() + nl.n_un.n_strx);
        if (!name.empty() && name[0] == '_')
            name = name.substr(1);

        uint64_t stub_addr = stubs_addr + slot * STUB_STRIDE;
        symbol_table[stub_addr] = name;

        if (taint_funcs.count(name)) {
            taint_addresses.insert(stub_addr);
            cout << "    [!] Taint stub: " << name
                 << " → 0x" << hex << stub_addr << dec << endl;
        } else {
            cout << "    [ ] " << name
                 << " → 0x" << hex << stub_addr << dec << endl;
        }
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

    uint64_t text_offset = 0, text_size = 0, text_addr = 0;
    bool     found_text  = false;

    uint64_t stubs_addr  = 0;
    uint32_t stubs_first_indirect = 0;
    uint32_t stubs_num_slots      = 0;
    bool     found_stubs = false;

    symtab_command   symtab_cmd{};
    dysymtab_command dysym_cmd{};
    bool has_symtab  = false;
    bool has_dysymtab = false;

    for (uint32_t i = 0; i < header.ncmds; ++i) {
        streampos cur = file.tellg();
        load_command lc;
        file.read(reinterpret_cast<char*>(&lc), sizeof(lc));

        if (lc.cmd == LC_SEGMENT_64) {
            file.seekg(cur);
            segment_command_64 seg;
            file.read(reinterpret_cast<char*>(&seg), sizeof(seg));

            for (uint32_t j = 0; j < seg.nsects; ++j) {
                section_64 sect;
                file.read(reinterpret_cast<char*>(&sect), sizeof(sect));

                if (strcmp(sect.sectname, "__text") == 0) {
                    text_offset = sect.offset;
                    text_size   = sect.size;
                    text_addr   = sect.addr;
                    found_text  = true;
                }

                if (strcmp(sect.sectname, "__stubs") == 0) {
                    stubs_addr            = sect.addr;
                    stubs_first_indirect  = sect.reserved1;
                    stubs_num_slots       = (uint32_t)(sect.size / 12);
                    found_stubs           = true;
                }
            }
        }
        else if (lc.cmd == LC_SYMTAB) {
            file.seekg(cur);
            file.read(reinterpret_cast<char*>(&symtab_cmd), sizeof(symtab_cmd));
            has_symtab = true;
        }
        else if (lc.cmd == LC_DYSYMTAB) {
            file.seekg(cur);
            file.read(reinterpret_cast<char*>(&dysym_cmd), sizeof(dysym_cmd));
            has_dysymtab = true;
        }

        file.seekg(cur + (streampos)lc.cmdsize);
    }

    if (has_symtab)
        parse_symbol_table(file, symtab_cmd);

    if (found_stubs && has_symtab && has_dysymtab) {
        resolve_stubs(file, dysym_cmd, symtab_cmd,
                      stubs_addr, stubs_first_indirect, stubs_num_slots);
    } else {
        if (!found_stubs)   cout << "[!] No __stubs section found." << endl;
        if (!has_dysymtab)  cout << "[!] No LC_DYSYMTAB found — stub resolution skipped." << endl;
    }

    if (!found_text) {
        cerr << "[-] Could not locate __text section." << endl;
        return 1;
    }

    file.seekg(text_offset);
    vector<uint8_t> buffer(text_size);
    file.read(reinterpret_cast<char*>(buffer.data()), text_size);

    vector<IRInst> ir = disassemble_text_section(buffer, text_addr);
    print_ir(ir);

    run_taint_analysis(ir);

    vector<RopGadget> gadgets = scan_rop_gadgets(ir);
    print_rop_gadgets(gadgets);

    print_analysis_verdict(ir, gadgets);

    file.close();
    return 0;
}
