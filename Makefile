# ─────────────────────────────────────────────────────────
#  Makefile — Binary Code Lifter (ARM64 / Mach-O)
#  Supports: macOS (Homebrew Capstone) + Linux (system Capstone)
# ─────────────────────────────────────────────────────────

CXX      := clang++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra

TARGET   := lifter
SRCDIR   := src
INCDIR   := include
OBJDIR   := build

SRCS     := $(SRCDIR)/main.cpp $(SRCDIR)/reporter.cpp
OBJS     := $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))

# ── Capstone detection ────────────────────────────────────
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
  BREW_PREFIX := $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
  CAPSTONE_INC := -I$(BREW_PREFIX)/include
  CAPSTONE_LIB := -L$(BREW_PREFIX)/lib -lcapstone
else
  CAPSTONE_INC :=
  CAPSTONE_LIB := -lcapstone
endif

CXXFLAGS += $(CAPSTONE_INC) -I$(INCDIR)
LDFLAGS  := $(CAPSTONE_LIB)

# ─────────────────────────────────────────────────────────
.PHONY: all clean test check

all: $(OBJDIR) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $@
	@echo "\n[✓] Build successful: ./$(TARGET)"

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ── Quick test using the bundled vuln.c / vuln2.c ─────────
check: all
	@echo "\n=== Compiling test binaries (cross-compile for ARM64 if available) ==="
	@if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then \
	    aarch64-linux-gnu-gcc -O0 -o tests/vuln_arm64 tests/vuln.c && \
	    echo "[+] tests/vuln_arm64 built" && \
	    ./$(TARGET) tests/vuln_arm64; \
	elif command -v clang >/dev/null 2>&1 && clang --target=aarch64-linux-gnu -v 2>&1 | grep -q aarch64; then \
	    clang --target=aarch64-linux-gnu -O0 -o tests/vuln_arm64 tests/vuln.c && \
	    echo "[+] tests/vuln_arm64 built" && \
	    ./$(TARGET) tests/vuln_arm64; \
	else \
	    echo "[!] No ARM64 cross-compiler found. Provide a Mach-O/ARM64 binary manually:"; \
	    echo "    ./$(TARGET) <your_arm64_binary>"; \
	fi

# ── Run with JSON output ──────────────────────────────────
test-json: all
	@echo "\n=== JSON report ==="
	./$(TARGET) $(BINARY) -f json -o report.json 2>/dev/null
	cat report.json

clean:
	rm -rf $(OBJDIR) $(TARGET) tests/vuln_arm64 report.json
