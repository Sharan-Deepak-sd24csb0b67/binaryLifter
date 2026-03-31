// ─────────────────────────────────────────────────────────
//  reporter.cpp  —  Phase 4, Week 13
//  CLI parsing + JSON/Text report emission
// ─────────────────────────────────────────────────────────
#include "reporter.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <map>

// Pull in the types defined in the main translation unit
// (IRInst and RopGadget are defined in parser.cpp / its header context)
// We redeclare the minimum we need here via the shared header.

using namespace std;

// ── CLI ───────────────────────────────────────────────────

void print_usage(const char* prog) {
    cout << "\nBinary Code Lifter — Vulnerability Analysis Tool\n"
         << "ARM64 / Mach-O Static Analyser\n\n"
         << "Usage:\n"
         << "  " << prog << " <binary> [options]\n\n"
         << "Options:\n"
         << "  -o <file>       Write report to <file>  (default: stdout)\n"
         << "  -f <format>     Output format: text | json  (default: text)\n"
         << "  --show-ir       Print the lifted IR listing\n"
         << "  --no-asm        Suppress the disassembly table\n"
         << "  -h, --help      Show this help message\n\n"
         << "Examples:\n"
         << "  " << prog << " ./target                         # text report to stdout\n"
         << "  " << prog << " ./target -f json -o report.json  # JSON report to file\n"
         << "  " << prog << " ./target --show-ir               # include IR dump\n\n";
}

CliOptions parse_args(int argc, char* argv[]) {
    CliOptions opts;
    opts.format   = "text";
    opts.show_asm = true;

    if (argc < 2) { opts.help = true; return opts; }

    for (int i = 1; i < argc; ++i) {
        string a(argv[i]);
        if (a == "-h" || a == "--help") {
            opts.help = true;
        } else if (a == "-o" && i + 1 < argc) {
            opts.output_file = argv[++i];
        } else if (a == "-f" && i + 1 < argc) {
            opts.format = argv[++i];
            if (opts.format != "text" && opts.format != "json") {
                cerr << "[!] Unknown format '" << opts.format
                     << "'. Using 'text'.\n";
                opts.format = "text";
            }
        } else if (a == "--show-ir") {
            opts.show_ir = true;
        } else if (a == "--no-asm") {
            opts.show_asm = false;
        } else if (a[0] != '-') {
            opts.input_binary = a;
        } else {
            cerr << "[!] Unknown option: " << a << "\n";
        }
    }

    if (opts.input_binary.empty() && !opts.help)
        opts.help = true;

    return opts;
}

// ── Timestamp helper ──────────────────────────────────────
static string now_iso8601() {
    time_t t = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return buf;
}

// ── JSON escaping ─────────────────────────────────────────
static string json_escape(const string& s) {
    string out;
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    return out;
}

static string hex64(uint64_t v) {
    ostringstream oss;
    oss << "0x" << hex << v;
    return oss.str();
}

// ── Report builder ────────────────────────────────────────
Report build_report(const string& binary_path,
                    const vector<IRInst>& ir,
                    const vector<RopGadget>& gadgets,
                    const set<int>& tainted_regs,
                    const set<int64_t>& tainted_stack,
                    bool is_fp)
{
    Report r;
    r.binary_path        = binary_path;
    r.timestamp          = now_iso8601();
    r.total_instructions = ir.size();

    // ── Taint findings ─────────────────────────────────────
    bool has_critical = false;
    if (!tainted_regs.empty() || !tainted_stack.empty()) {
        TaintFinding f;
        f.address = 0;

        // Determine severity
        if (is_fp) {
            f.severity    = "LOW/FP";
            f.description = "Taint flow detected but assessed as likely false positive. "
                            "Only bounded-length sources (fgets/strncpy) were found with "
                            "no unbounded sink reached.";
        } else if (tainted_regs.count(0)) {
            // X0 is the return value / first arg — highest risk
            f.severity    = "CRITICAL";
            f.description = "Tainted data in X0 reaches a function return or is passed "
                            "to a downstream call — potential control-flow hijack or "
                            "information leak.";
            has_critical  = true;
        } else {
            f.severity    = "HIGH";
            f.description = "Tainted data flows into stack memory slots. "
                            "A buffer overflow may be reachable depending on allocation size.";
            has_critical  = true;
        }

        // Detail which registers / slots are tainted
        if (!tainted_regs.empty()) {
            f.description += " Tainted registers: ";
            for (int reg : tainted_regs)
                f.description += "X" + to_string(reg) + " ";
        }
        if (!tainted_stack.empty()) {
            f.description += " Tainted stack offsets: ";
            for (int64_t off : tainted_stack)
                f.description += "[sp+" + to_string(off) + "] ";
        }

        r.taint_findings.push_back(f);
    }

    // ── ROP findings ───────────────────────────────────────
    for (const auto& g : gadgets) {
        RopFinding rf;
        rf.start_address = g.start_addr;
        rf.category      = g.category;
        rf.insn_addresses = g.insn_addrs;
        r.rop_findings.push_back(rf);
    }

    // ── Overall verdict ────────────────────────────────────
    if (has_critical && !gadgets.empty())
        r.verdict = "CRITICAL — Exploitable taint flow AND usable ROP gadgets detected.";
    else if (has_critical)
        r.verdict = "HIGH — Dangerous taint flow detected.";
    else if (!gadgets.empty())
        r.verdict = "MEDIUM — ROP gadgets present; no active taint flow confirmed.";
    else if (!r.taint_findings.empty() && is_fp)
        r.verdict = "LOW — Minor taint concern (likely false positive).";
    else
        r.verdict = "CLEAN — No vulnerabilities detected.";

    return r;
}

// ── Text emitter ──────────────────────────────────────────
void emit_text_report(const Report& r, ostream& out) {
    out << "\n";
    out << "╔══════════════════════════════════════════════════════════╗\n";
    out << "║        VULNERABILITY ANALYSIS REPORT                    ║\n";
    out << "╚══════════════════════════════════════════════════════════╝\n";
    out << "  Binary   : " << r.binary_path        << "\n";
    out << "  Generated: " << r.timestamp           << "\n";
    out << "  IR size  : " << r.total_instructions  << " instructions\n";
    out << "\n";

    // Taint section
    out << "──────────────────────────────────────────────────────────\n";
    out << "  TAINT ANALYSIS\n";
    out << "──────────────────────────────────────────────────────────\n";
    if (r.taint_findings.empty()) {
        out << "  [OK] No dangerous taint flows detected.\n";
    } else {
        for (const auto& f : r.taint_findings) {
            out << "  [" << f.severity << "] " << f.description << "\n";
        }
    }
    out << "\n";

    // ROP section
    out << "──────────────────────────────────────────────────────────\n";
    out << "  ROP GADGET SCAN\n";
    out << "──────────────────────────────────────────────────────────\n";
    if (r.rop_findings.empty()) {
        out << "  [OK] No ROP gadgets found.\n";
    } else {
        // Group by category
        map<string, vector<const RopFinding*>> by_cat;
        for (const auto& rf : r.rop_findings)
            by_cat[rf.category].push_back(&rf);

        for (const auto& [cat, list] : by_cat) {
            out << "  Category: " << cat << " (" << list.size() << " gadget(s))\n";
            for (const auto* g : list) {
                out << "    Start " << hex64(g->start_address) << "  [";
                for (size_t k = 0; k < g->insn_addresses.size(); ++k) {
                    if (k) out << ", ";
                    out << hex64(g->insn_addresses[k]);
                }
                out << "]\n";
            }
        }
        out << "\n  Dangerous categories:\n";
        static const set<string> dangerous = {
            "STACK_PIVOT", "LOAD_ARG_X0", "LOAD_ARGS_X0_X1", "LOAD_ARGS_X0_X1_X2"
        };
        bool any_dangerous = false;
        for (const auto& [cat, list] : by_cat) {
            if (dangerous.count(cat)) {
                out << "    *** " << cat << " x" << list.size()
                    << " — usable in ROP chain ***\n";
                any_dangerous = true;
            }
        }
        if (!any_dangerous)
            out << "    None flagged as immediately exploitable.\n";
    }
    out << "\n";

    // Verdict
    out << "╔══════════════════════════════════════════════════════════╗\n";
    out << "║  VERDICT: " << left << setw(49) << r.verdict << "║\n";
    out << "╚══════════════════════════════════════════════════════════╝\n";
    out << "\n";
}

// ── JSON emitter ──────────────────────────────────────────
void emit_json_report(const Report& r, ostream& out) {
    out << "{\n";
    out << "  \"binary\": \""    << json_escape(r.binary_path) << "\",\n";
    out << "  \"generated\": \"" << r.timestamp << "\",\n";
    out << "  \"total_instructions\": " << r.total_instructions << ",\n";
    out << "  \"verdict\": \""   << json_escape(r.verdict) << "\",\n";

    // Taint findings
    out << "  \"taint_findings\": [\n";
    for (size_t i = 0; i < r.taint_findings.size(); ++i) {
        const auto& f = r.taint_findings[i];
        out << "    {\n";
        out << "      \"severity\": \""    << json_escape(f.severity)    << "\",\n";
        out << "      \"description\": \"" << json_escape(f.description) << "\"\n";
        out << "    }";
        if (i + 1 < r.taint_findings.size()) out << ",";
        out << "\n";
    }
    out << "  ],\n";

    // ROP findings
    out << "  \"rop_findings\": [\n";
    for (size_t i = 0; i < r.rop_findings.size(); ++i) {
        const auto& g = r.rop_findings[i];
        out << "    {\n";
        out << "      \"category\": \""     << json_escape(g.category) << "\",\n";
        out << "      \"start_address\": \"" << hex64(g.start_address) << "\",\n";
        out << "      \"instructions\": [";
        for (size_t k = 0; k < g.insn_addresses.size(); ++k) {
            if (k) out << ", ";
            out << "\"" << hex64(g.insn_addresses[k]) << "\"";
        }
        out << "]\n";
        out << "    }";
        if (i + 1 < r.rop_findings.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}