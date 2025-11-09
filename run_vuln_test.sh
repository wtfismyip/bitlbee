#!/bin/bash
# Script to compile and run UTF-8 vulnerability test

echo "==================================================================="
echo "BitlBee UTF-8 Nickname Vulnerability Test Runner"
echo "==================================================================="
echo ""

# Check if glib is available
if ! pkg-config --exists glib-2.0; then
    echo "[ERROR] GLib development files not found!"
    echo "Install with: sudo apt-get install libglib2.0-dev"
    exit 1
fi

echo "[*] Compiling test program with AddressSanitizer..."
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer \
    -o test_utf8_vuln test_utf8_vuln.c \
    $(pkg-config --cflags --libs glib-2.0) 2>&1

if [ $? -ne 0 ]; then
    echo "[ERROR] Compilation failed!"
    exit 1
fi

echo "[*] Compilation successful!"
echo ""
echo "[*] Running tests..."
echo "    (If vulnerable, AddressSanitizer will detect buffer overflows)"
echo ""

# Set AddressSanitizer options for detailed output
export ASAN_OPTIONS=detect_leaks=1:halt_on_error=0:verbosity=1

# Run the test
./test_utf8_vuln

TEST_RESULT=$?

echo ""
echo "==================================================================="
if [ $TEST_RESULT -ne 0 ]; then
    echo "[!] Test program exited with code $TEST_RESULT"
    echo "[!] This may indicate a crash or memory error was detected!"
else
    echo "[*] Test program completed"
    echo "[*] Check output above for AddressSanitizer warnings"
fi
echo "==================================================================="

# Also compile without ASAN for comparison
echo ""
echo "[*] Compiling without AddressSanitizer for comparison..."
gcc -g -O0 -o test_utf8_vuln_noasan test_utf8_vuln.c \
    $(pkg-config --cflags --libs glib-2.0) 2>&1

if [ $? -eq 0 ]; then
    echo "[*] To run without ASAN: ./test_utf8_vuln_noasan"
fi

echo ""
echo "Additional debugging options:"
echo "  - Run with GDB: gdb ./test_utf8_vuln"
echo "  - Run with Valgrind: valgrind --leak-check=full ./test_utf8_vuln_noasan"
echo "  - Check for core dumps: ls -lh core*"
