// ─────────────────────────────────────────────────────────
//  main.cpp  —  Phase 4 entry point
//  Wraps parser.cpp logic with CLI (Week 13) and structured
//  report output (JSON / Text).  Week 14: final integration.
//  
//  Build (macOS, with Capstone via Homebrew):
//    clang++ -std=c++17 -O2 \
//      -I/opt/homebrew/include -I../include \
//      -L/opt/homebrew/lib -lcapstone \
//      main.cpp reporter.cpp -o lifter
//
//  Build (Linux, system Capstone):
//    g++ -std=c++17 -O2 -I../include \
//      main.cpp reporter.cpp -lcapstone -o lifter
// ─────────────────────────────────────────────────────────
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <cstdint>

#include "reporter.h"

using namespace std;

// ─────────────────────────────────────────────────────────
//  Global State
// ─────────────────────────────────────────────────────────
static map<uint64_t, string> symbol_table;
static set<uint64_t>         taint_addresses;

static const set<string> taint_funcs = {
    "strcpy","gets","memcpy","sprintf","strcat","scanf",
    "strncpy","strncat","vsprintf","read","fgets","sscanf"
};

static set<int>     tainted_registers;
static set<int64_t> tainted_stack_offsets;

// ─────────────────────────────────────────────────────────
//  Mach-O Structures
// ─────────────────────────────────────────────────────────
#define MH_MAGIC_64   0xfeedfacf
#define LC_SEGMENT_64 0x19
#define LC_SYMTAB     0x2
#define LC_DYSYMTAB   0xb
#define LC_MAIN       0x80000028

struct mach_header_64    { uint32_t magic,cputype_u,cpusubtype_u,filetype,ncmds,sizeofcmds,flags,reserved; };
struct load_command      { uint32_t cmd, cmdsize; };
struct segment_command_64{
    uint32_t cmd,cmdsize; char segname[16];
    uint64_t vmaddr,vmsize,fileoff,filesize;
    int32_t maxprot,initprot; uint32_t nsects,flags;
};
struct section_64 {
    char sectname[16],segname[16];
    uint64_t addr,size;
    uint32_t offset,align,reloff,nreloc,flags,reserved1,reserved2,reserved3;
};
struct symtab_command  { uint32_t cmd,cmdsize,symoff,nsyms,stroff,strsize; };
struct nlist_64        { union{uint32_t n_strx;}n_un; uint8_t n_type,n_sect; uint16_t n_desc; uint64_t n_value; };
struct dysymtab_command{
    uint32_t cmd,cmdsize,ilocalsym,nlocalsym,iextdefsym,nextdefsym,
             iundefsym,nundefsym,tocoff,ntoc,modtaboff,nmodtab,
             extrefsymoff,nextrefsyms,indirectsymoff,nindirectsyms,
             extreloff,nextrel,locreloff,nlocrel;
};

// ─────────────────────────────────────────────────────────
//  Capstone
// ─────────────────────────────────────────────────────────
#ifdef __has_include
  #if __has_include(<capstone/capstone.h>) || \
      __has_include("/opt/homebrew/include/capstone/capstone.h")
    #include <capstone/capstone.h>
    #define HAVE_CAPSTONE 1
  #else
    #warning "Capstone not found — disassembly disabled"
  #endif
#else
  #include <capstone/capstone.h>
  #define HAVE_CAPSTONE 1
#endif

#ifdef HAVE_CAPSTONE
static int regmap(unsigned r) {
    switch(r){
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

IRInst lift_one(const cs_insn& insn) {
    IRInst inst{}; inst.addr=insn.address;
    inst.dst=inst.src1=inst.src2=-1; inst.imm=0; inst.block_end=false;
    string m(insn.mnemonic);
    if      (m=="add")  inst.op=IR_ADD;
    else if (m=="sub")  inst.op=IR_SUB;
    else if (m=="mov")  inst.op=IR_MOV;
    else if (m=="ldr")  inst.op=IR_LDR;
    else if (m=="str")  inst.op=IR_STR;
    else if (m=="b")  { inst.op=IR_B;   inst.block_end=true; }
    else if (m=="bl") { inst.op=IR_BL;  inst.block_end=true; }
    else if (m=="ret"){ inst.op=IR_RET; inst.block_end=true; }
    else if (m=="cbz") { inst.op=IR_CBZ;  inst.block_end=true; }
    else if (m=="cbnz"){ inst.op=IR_CBNZ; inst.block_end=true; }
    else inst.op=IR_OTHER;

    if (insn.detail && insn.detail->arm64.op_count>0) {
        int n=insn.detail->arm64.op_count;
        const cs_arm64_op* ops=insn.detail->arm64.operands;
        if (n>0 && ops[0].type==ARM64_OP_REG) inst.dst=regmap(ops[0].reg);
        if (n>1){
            if      (ops[1].type==ARM64_OP_REG) inst.src1=regmap(ops[1].reg);
            else if (ops[1].type==ARM64_OP_IMM) inst.imm =ops[1].imm;
            else if (ops[1].type==ARM64_OP_MEM) inst.src1=regmap(ops[1].mem.base);
        }
        if (n>2 && ops[2].type==ARM64_OP_REG) inst.src2=regmap(ops[2].reg);
    }
    if (inst.op==IR_BL){
        uint64_t target=0;
        if (insn.detail&&insn.detail->arm64.op_count>0&&
            insn.detail->arm64.operands[0].type==ARM64_OP_IMM)
            target=inst.imm=(int64_t)insn.detail->arm64.operands[0].imm;
        if (taint_addresses.count(target)){
            cerr<<"[!] Tainted branch to 0x"<<hex<<target<<dec<<"\n";
        } else {
            auto it=symbol_table.find(target);
            if (it!=symbol_table.end()&&taint_funcs.count(it->second))
                cerr<<"[!] Taint source call to "<<it->second
                    <<" at 0x"<<hex<<target<<dec<<"\n";
        }
    }
    return inst;
}
#else
static int regmap(unsigned){ return -1; }
#endif

// ─────────────────────────────────────────────────────────
//  Symbol Table
// ─────────────────────────────────────────────────────────
void parse_symbol_table(ifstream& file, const symtab_command& st) {
    vector<char> strtab(st.strsize);
    file.seekg(st.stroff); file.read(strtab.data(), st.strsize);
    file.seekg(st.symoff);
    for (uint32_t i=0;i<st.nsyms;++i){
        nlist_64 nl; file.read(reinterpret_cast<char*>(&nl),sizeof(nl));
        if (nl.n_un.n_strx<st.strsize){
            string sn(strtab.data()+nl.n_un.n_strx);
            if (!sn.empty()&&sn[0]=='_') sn=sn.substr(1);
            symbol_table[nl.n_value]=sn;
            if (taint_funcs.count(sn)){
                cerr<<"[!] Taint symbol: "<<sn<<"\n";
                if (nl.n_value) taint_addresses.insert(nl.n_value);
            }
        }
    }
    cerr<<"[+] Loaded "<<st.nsyms<<" symbols.\n";
}

// ─────────────────────────────────────────────────────────
//  Disassembler
// ─────────────────────────────────────────────────────────
#ifdef HAVE_CAPSTONE
vector<IRInst> disassemble_text_section(const vector<uint8_t>& code,
                                         uint64_t address,
                                         bool show_asm) {
    vector<IRInst> irlist;
    csh handle; cs_insn* insn; size_t count;
    if (cs_open(CS_ARCH_ARM64,CS_MODE_ARM,&handle)!=CS_ERR_OK){
        cerr<<"[-] Capstone init failed\n"; return irlist;
    }
    cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON);

    if (show_asm){
        cerr<<"\n[+] Disassembling __text section...\n";
        cerr<<"---------------------------------------------------------------\n";
        cerr<<" Address        | Mnemonic      | Operands\n";
        cerr<<"---------------------------------------------------------------\n";
    }

    count=cs_disasm(handle,code.data(),code.size(),address,0,&insn);
    if (count>0){
        for (size_t i=0;i<count;i++){
            if (show_asm)
                cerr<<" 0x"<<hex<<insn[i].address
                    <<" | "<<setw(13)<<left<<insn[i].mnemonic
                    <<" | "<<insn[i].op_str<<dec<<"\n";
            irlist.push_back(lift_one(insn[i]));
        }
        cs_free(insn,count);
    } else {
        cerr<<"[-] Disassembly failed (count=0)\n";
    }
    cs_close(&handle);
    return irlist;
}
#else
vector<IRInst> disassemble_text_section(const vector<uint8_t>&, uint64_t, bool){
    cerr<<"[!] Capstone unavailable.\n"; return {};
}
#endif

// ─────────────────────────────────────────────────────────
//  IR printer
// ─────────────────────────────────────────────────────────
void print_ir(const vector<IRInst>& ir) {
    cerr<<"\n[+] IR listing\nAddr        | Op | dst src1 src2 imm\n";
    cerr<<"-------------------------------------------\n";
    for (const auto& i:ir){
        if (i.block_end) cerr<<"[BB END]\n";
        cerr<<"0x"<<hex<<i.addr<<dec<<" | "<<i.op
            <<" | "<<i.dst<<" "<<i.src1<<" "<<i.src2
            <<" "<<hex<<i.imm<<dec<<"\n";
    }
}

// ─────────────────────────────────────────────────────────
//  Taint Analysis
// ─────────────────────────────────────────────────────────
bool run_taint_analysis(const vector<IRInst>& ir) {
    tainted_registers.clear();
    tainted_stack_offsets.clear();
    bool found_sink=false;

    cerr<<"\n[+] Taint Analysis — "<<ir.size()<<" instructions.\n";
    cerr<<"------------------------------------------------------------\n";

    for (const auto& inst:ir){
        bool activity=false; string log;

        if (inst.op==IR_BL){
            uint64_t target=(uint64_t)inst.imm; string name;
            auto it=symbol_table.find(target);
            if (it!=symbol_table.end()) name=it->second;
            bool is_src=taint_funcs.count(name)||taint_addresses.count(target);
            if (is_src){
                tainted_registers.insert(0);
                activity=true;
                log="SOURCE: ["+( name.empty()?"0x"+to_string(target):name )
                    +"] — X0 TAINTED";
            }
        }

        switch(inst.op){
            case IR_STR:
                if (tainted_registers.count(inst.dst)){
                    tainted_stack_offsets.insert(inst.imm);
                    activity=true;
                    log="STORE: X"+to_string(inst.dst)
                        +" → stack["+to_string(inst.imm)+"]";
                }
                break;
            case IR_LDR:
                if (tainted_stack_offsets.count(inst.imm)){
                    tainted_registers.insert(inst.dst);
                    activity=true;
                    log="LOAD: stack["+to_string(inst.imm)
                        +"] → X"+to_string(inst.dst);
                }
                break;
            case IR_MOV: case IR_ADD: case IR_SUB:
                if (inst.dst>=0){
                    bool s1=inst.src1>=0&&tainted_registers.count(inst.src1);
                    bool s2=inst.src2>=0&&tainted_registers.count(inst.src2);
                    if (s1||s2){
                        tainted_registers.insert(inst.dst);
                        activity=true;
                        int src=s1?inst.src1:inst.src2;
                        log="SPREAD: X"+to_string(src)+" → X"+to_string(inst.dst);
                    }
                }
                break;
            case IR_RET:
                if (tainted_registers.count(0)){
                    found_sink=true; activity=true;
                    log="!!! CRITICAL SINK: Tainted X0 reaches RET !!!";
                }
                break;
            case IR_OTHER:
                if (inst.src1>=0&&tainted_registers.count(inst.src1)&&inst.dst>=0){
                    tainted_registers.insert(inst.dst);
                    activity=true;
                    log="GENERIC SPREAD: [X"+to_string(inst.src1)+"] → X"+to_string(inst.dst);
                }
                break;
            default: break;
        }
        if (activity)
            cerr<<" [T] 0x"<<hex<<inst.addr<<dec<<" | "<<log<<"\n";
    }
    cerr<<"------------------------------------------------------------\n";
    if (found_sink)
        cerr<<"[!!!] VULNERABILITY DETECTED: Tainted data reaches critical sink!\n";
    else
        cerr<<"[OK] No critical sink reached by tainted data.\n";
    return found_sink;
}

// ─────────────────────────────────────────────────────────
//  ROP Gadget Scanner
// ─────────────────────────────────────────────────────────

static string classify_gadget(const vector<IRInst>& w){
    bool lx0=false,lx1=false,lx2=false,sp=false,st=false,ar=false;
    for (const auto& i:w){
        if (i.op==IR_LDR){
            if (i.dst==0) lx0=true; if (i.dst==1) lx1=true;
            if (i.dst==2) lx2=true; if (i.dst==29||i.dst==30) sp=true;
        }
        if (i.op==IR_STR) st=true;
        if (i.op==IR_ADD||i.op==IR_SUB) ar=true;
    }
    if (sp) return "STACK_PIVOT";
    if (lx0&&lx1&&lx2) return "LOAD_ARGS_X0_X1_X2";
    if (lx0&&lx1)      return "LOAD_ARGS_X0_X1";
    if (lx0)           return "LOAD_ARG_X0";
    if (st&&ar)        return "STORE_WITH_ARITH";
    if (st)            return "STORE_GADGET";
    if (ar)            return "ARITHMETIC";
    return "GENERIC";
}

vector<RopGadget> scan_rop_gadgets(const vector<IRInst>& ir,
                                    size_t max_window=5) {
    vector<RopGadget> gadgets;
    for (size_t i=0;i<ir.size();++i){
        if (ir[i].op!=IR_RET) continue;
        size_t start=(i>=max_window)?(i-max_window):0;
        vector<IRInst> window(ir.begin()+start,ir.begin()+i);
        RopGadget g;
        g.start_addr=ir[start].addr;
        for (size_t k=start;k<=i;++k) g.insn_addrs.push_back(ir[k].addr);
        g.category=classify_gadget(window);
        ostringstream oss; oss<<"RET at 0x"<<hex<<ir[i].addr;
        g.description=oss.str();
        gadgets.push_back(g);
    }
    return gadgets;
}

// ─────────────────────────────────────────────────────────
//  False-positive heuristics
// ─────────────────────────────────────────────────────────
bool is_false_positive(const vector<IRInst>& ir){
    bool bounded=false,unbounded=false,ret_sink=false;
    for (const auto& inst:ir){
        if (inst.op==IR_BL){
            uint64_t t=(uint64_t)inst.imm;
            auto it=symbol_table.find(t);
            string n=(it!=symbol_table.end())?it->second:"";
            if (n=="fgets"||n=="strncpy"||n=="strncat") bounded=true;
            else if (taint_funcs.count(n)||taint_addresses.count(t)) unbounded=true;
        }
        if (inst.op==IR_RET&&tainted_registers.count(0)) ret_sink=true;
    }
    return bounded&&!unbounded&&!ret_sink;
}

// ─────────────────────────────────────────────────────────
//  Stub Resolver
// ─────────────────────────────────────────────────────────
void resolve_stubs(ifstream& file,
                   const dysymtab_command& dysym,
                   const symtab_command& sc,
                   uint64_t stubs_addr,
                   uint32_t stubs_first,
                   uint32_t stubs_slots)
{
    if (!stubs_slots) return;
    vector<uint32_t> indirect(dysym.nindirectsyms);
    file.seekg(dysym.indirectsymoff);
    file.read(reinterpret_cast<char*>(indirect.data()),
              dysym.nindirectsyms*sizeof(uint32_t));
    vector<char> strtab(sc.strsize);
    file.seekg(sc.stroff); file.read(strtab.data(),sc.strsize);
    vector<nlist_64> syms(sc.nsyms);
    file.seekg(sc.symoff);
    file.read(reinterpret_cast<char*>(syms.data()),sc.nsyms*sizeof(nlist_64));

    cerr<<"\n[+] Resolving "<<stubs_slots<<" stub(s)...\n";
    const uint64_t STRIDE=12;
    for (uint32_t slot=0;slot<stubs_slots;++slot){
        uint32_t ii=stubs_first+slot;
        if (ii>=dysym.nindirectsyms) continue;
        uint32_t si=indirect[ii];
        if (si==0x80000000||si==0x40000000) continue;
        if (si>=sc.nsyms) continue;
        const nlist_64& nl=syms[si];
        if (nl.n_un.n_strx>=sc.strsize) continue;
        string name(strtab.data()+nl.n_un.n_strx);
        if (!name.empty()&&name[0]=='_') name=name.substr(1);
        uint64_t addr=stubs_addr+slot*STRIDE;
        symbol_table[addr]=name;
        if (taint_funcs.count(name)){
            taint_addresses.insert(addr);
            cerr<<"    [!] Taint stub: "<<name<<" → 0x"<<hex<<addr<<dec<<"\n";
        } else {
            cerr<<"    [ ] "<<name<<" → 0x"<<hex<<addr<<dec<<"\n";
        }
    }
}

// ─────────────────────────────────────────────────────────
//  main()
// ─────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    // ── CLI ──────────────────────────────────────────────
    CliOptions opts = parse_args(argc, argv);
    if (opts.help) { print_usage(argv[0]); return 0; }

    // ── Open binary ──────────────────────────────────────
    ifstream file(opts.input_binary, ios::binary);
    if (!file){
        cerr<<"Error: Cannot open '"<<opts.input_binary<<"'\n";
        return 1;
    }

    // ── Parse Mach-O header ──────────────────────────────
    mach_header_64 header;
    file.read(reinterpret_cast<char*>(&header),sizeof(header));
    if (header.magic!=MH_MAGIC_64){
        cerr<<"Error: Not a 64-bit Mach-O file.\n"; return 1;
    }
    cerr<<"--- Mach-O Header Parsed --- Load commands: "<<header.ncmds<<"\n";

    uint64_t text_offset=0,text_size=0,text_addr=0;
    bool found_text=false;
    uint64_t stubs_addr=0; uint32_t stubs_first=0,stubs_slots=0;
    bool found_stubs=false;
    symtab_command sc{}; dysymtab_command dc{};
    bool has_sym=false,has_dysym=false;

    for (uint32_t i=0;i<header.ncmds;++i){
        streampos cur=file.tellg();
        load_command lc;
        file.read(reinterpret_cast<char*>(&lc),sizeof(lc));
        if (lc.cmd==LC_SEGMENT_64){
            file.seekg(cur);
            segment_command_64 seg;
            file.read(reinterpret_cast<char*>(&seg),sizeof(seg));
            for (uint32_t j=0;j<seg.nsects;++j){
                section_64 sect;
                file.read(reinterpret_cast<char*>(&sect),sizeof(sect));
                if (!strcmp(sect.sectname,"__text")){
                    text_offset=sect.offset; text_size=sect.size;
                    text_addr=sect.addr; found_text=true;
                }
                if (!strcmp(sect.sectname,"__stubs")){
                    stubs_addr=sect.addr; stubs_first=sect.reserved1;
                    stubs_slots=(uint32_t)(sect.size/12); found_stubs=true;
                }
            }
        } else if (lc.cmd==LC_SYMTAB){
            file.seekg(cur);
            file.read(reinterpret_cast<char*>(&sc),sizeof(sc));
            has_sym=true;
        } else if (lc.cmd==LC_DYSYMTAB){
            file.seekg(cur);
            file.read(reinterpret_cast<char*>(&dc),sizeof(dc));
            has_dysym=true;
        }
        file.seekg(cur+(streampos)lc.cmdsize);
    }

    if (has_sym) parse_symbol_table(file,sc);
    if (found_stubs&&has_sym&&has_dysym)
        resolve_stubs(file,dc,sc,stubs_addr,stubs_first,stubs_slots);
    if (!found_text){ cerr<<"[-] __text section not found.\n"; return 1; }

    // ── Disassemble + Lift ───────────────────────────────
    file.seekg(text_offset);
    vector<uint8_t> buf(text_size);
    file.read(reinterpret_cast<char*>(buf.data()),text_size);

    vector<IRInst> ir = disassemble_text_section(buf, text_addr, opts.show_asm);
    if (opts.show_ir) print_ir(ir);

    // ── Analysis ─────────────────────────────────────────
    run_taint_analysis(ir);
    vector<RopGadget> gadgets = scan_rop_gadgets(ir);

    // Print ROP summary to stderr
    cerr<<"\n[+] ROP scan: "<<gadgets.size()<<" gadget(s) found.\n";
    if (!gadgets.empty()){
        map<string,int> cnt;
        for (const auto& g:gadgets) cnt[g.category]++;
        for (const auto& [cat,n]:cnt)
            cerr<<"  "<<cat<<" x"<<n<<"\n";
    }

    bool fp = is_false_positive(ir);

    // ── Build & emit report ───────────────────────────────
    Report report = build_report(
        opts.input_binary, ir, gadgets,
        tainted_registers, tainted_stack_offsets, fp
    );

    // Open output stream
    ofstream outfile;
    ostream* out = &cout;
    if (!opts.output_file.empty()){
        outfile.open(opts.output_file);
        if (!outfile){ cerr<<"Error: Cannot open output file.\n"; return 1; }
        out = &outfile;
        cerr<<"[+] Writing report to: "<<opts.output_file<<"\n";
    }

    if (opts.format=="json")
        emit_json_report(report, *out);
    else
        emit_text_report(report, *out);

    file.close();
    return 0;
}