# Mach-O Binary Analyzer — Setup & Reference

A fully CLI static analysis tool for ARM64 Mach-O binaries (macOS/iOS). Performs disassembly, taint analysis, ROP gadget scanning, and vulnerability verdict reporting.

---

## Dependencies

| Dependency | Purpose |
|---|---|
| **Capstone** | ARM64 disassembly engine |
| **clang++ / g++** | C++17 compiler |

### Install Capstone

```bash
# macOS
brew install capstone

# Ubuntu / Debian
sudo apt install libcapstone-dev
```

---

## Compile

```bash
# macOS (Homebrew paths)
clang++ -std=c++17 -o analyzer analyzer.cpp \
  -I/opt/homebrew/include \
  -L/opt/homebrew/lib -lcapstone

# Linux
g++ -std=c++17 -o analyzer analyzer.cpp -lcapstone
```

---

## Usage

```bash
./analyzer <path_to_macho_binary>
```

Example:

```bash
./analyzer ./my_arm64_binary
```

---

## Output Pipeline

The tool runs each phase in order and prints results to stdout.

### 1. Mach-O Header
Parses the file header and reports the number of load commands.

### 2. Symbol Table (`LC_SYMTAB`)
Loads all defined symbols and their addresses. Flags any dangerous function names immediately.

```
[+] Loaded 42 symbols from symbol table.
[!] Taint symbol present: gets
```

### 3. Stub Resolution (`LC_DYSYMTAB`)
Maps every `__stubs` slot to its imported symbol name using the indirect symbol table. This is how dynamically-linked calls to `strcpy`, `gets`, etc. get their addresses registered for taint tracking.

```
[+] Resolving 6 stub(s)...
    [!] Taint stub: gets → 0x100003f60
    [ ] printf → 0x100003f6c
```

### 4. Disassembly (`__text` section)
Disassembles the entire `__text` section using Capstone and prints a formatted table.

```
Address         | Mnemonic      | Operands
0x100003f80     | sub           | sp, sp, #0x50
0x100003f84     | stp           | x29, x30, [sp, #0x40]
```

### 5. IR Listing
Lifts each instruction into a simple intermediate representation for analysis.

```
Addr        | Op  | dst src1 src2 imm
0x100003f80 | 2   | 31  31  -1   50
```

### 6. Taint Analysis
Tracks data flow from dangerous source functions through registers and stack slots, looking for critical sinks.

**Taint sources** (any call to these marks X0 tainted):

`strcpy` `gets` `memcpy` `sprintf` `strcat` `scanf` `strncpy` `strncat` `vsprintf` `read` `fgets` `sscanf`

**Propagation rules:**

| Instruction | Behaviour |
|---|---|
| `BL` to taint source | X0 → tainted |
| `MOV`, `ADD`, `SUB` | Taint spreads from src1 or src2 → dst |
| `STR` | Tainted register → stack slot tainted |
| `LDR` | Tainted stack slot → destination register tainted |
| `RET` | Tainted X0 at return = **critical sink** |

Sample output:

```
[T] 0x100003f9c | SOURCE: call to [gets] — X0 marked TAINTED
[T] 0x100003fa0 | SPREAD: X0 → X8
[T] 0x100003fa8 | STORE: X8 → stack[-32] (tainted)
[T] 0x100003fb4 | LOAD: stack[-32] → X0 (now tainted)
[T] 0x100003fbc | !!! CRITICAL SINK: Tainted value in X0 reaches RET !!!
```

### 7. ROP Gadget Scan
Scans the IR for all `RET` instructions and inspects the preceding window of up to 5 instructions. Each gadget is classified by category.

**Gadget categories:**

| Category | Meaning |
|---|---|
| `STACK_PIVOT` | Loads X29/X30 from stack — pivots control flow |
| `LOAD_ARGS_X0_X1_X2` | Loads all three argument registers |
| `LOAD_ARGS_X0_X1` | Loads first two argument registers |
| `LOAD_ARG_X0` | Loads X0 — useful for controlling function arguments |
| `STORE_WITH_ARITH` | Memory write combined with arithmetic |
| `STORE_GADGET` | Memory write |
| `ARITHMETIC` | Pure computation |
| `GENERIC` | No special classification |

Categories marked dangerous: `STACK_PIVOT`, `LOAD_ARG_X0`, `LOAD_ARGS_X0_X1`, `LOAD_ARGS_X0_X1_X2`

### 8. Final Verdict
Consolidates all findings with false-positive filtering.

```
=========================================================
  VULNERABILITY ANALYSIS VERDICT
=========================================================
  [HIGH] Taint analysis found potentially exploitable data flow.
         Tainted registers  : X0 X8
         Tainted stack slots: [sp+-32]
  [WARN] 4 ROP gadget(s) found — binary may be exploitable via ROP chain.
=========================================================
```

**Verdict levels:**

| Level | Condition |
|---|---|
| `[HIGH]` | Tainted data reaches a critical sink, not a false positive |
| `[LOW/FP]` | Taint detected but only bounded-length sources used (e.g. `fgets`, `strncpy`) and no RET sink reached |
| `[OK]` | No dangerous taint flow detected |
| `[WARN]` | ROP gadgets found regardless of taint verdict |

---

## False-Positive Reduction

The analyzer applies a heuristic: if the **only** taint sources are bounded functions (`fgets`, `strncpy`, `strncat`) and no tainted value reaches a `RET`, the finding is downgraded to `LOW/FP`. Unbounded sources (`gets`, `strcpy`, `sprintf`, etc.) always produce a `HIGH` finding when a sink is reached.

---

## Limitations

- **Mach-O 64-bit only** — will reject ELF (Linux) and PE (Windows) binaries
- **ARM64 only** — no x86/x86-64 support
- **No Capstone = no disassembly** — the tool warns and exits the analysis phases gracefully
- **Intraprocedural taint** — taint does not cross function boundaries
- **Single-pass analysis** — no loop iteration or path sensitivity
- **Stub resolution requires both `LC_SYMTAB` and `LC_DYSYMTAB`** — stripped binaries will miss dynamic call targets
