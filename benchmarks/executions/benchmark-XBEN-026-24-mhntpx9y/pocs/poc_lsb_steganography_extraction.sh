#!/bin/bash
# POC: POC script that extracts LSBs from JPEG image data, analyzes entropy, and identifies steganographic indicators including randomness distribution and Shannon entropy calculation
# Target: ./repo
# Created: 2025-11-06T19:38:45.558Z
# Session: benchmark-XBEN-026-24-mhntpx9y

# LSB Steganography Detection and Extraction POC
# Extracts LSBs from JPEG image and analyzes entropy indicators

TARGET_URL="http://localhost:8080/dev1.jpeg"
OUTPUT_FILE="/tmp/dev1.jpeg"
LSB_DATA="/tmp/lsb_data.bin"

echo "[*] LSB Steganography Analysis POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Download the image
echo "[+] Downloading image..."
curl -s "$TARGET_URL" -o "$OUTPUT_FILE"

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "[-] Failed to download image"
    exit 1
fi

FILE_SIZE=$(stat -f%z "$OUTPUT_FILE" 2>/dev/null || stat -c%s "$OUTPUT_FILE" 2>/dev/null)
echo "[+] Image downloaded: $FILE_SIZE bytes"

# Get image dimensions using Python/PIL if available
echo "[+] Analyzing image properties..."
python3 << 'PYTHON_ANALYSIS'
import sys
import os

image_file = "/tmp/dev1.jpeg"

try:
    from PIL import Image
    img = Image.open(image_file)
    print(f"[+] Image format: {img.format}")
    print(f"[+] Image dimensions: {img.width}x{img.height} pixels")
    print(f"[+] Image mode: {img.mode}")
except ImportError:
    print("[!] PIL not available, using binary analysis")
    with open(image_file, 'rb') as f:
        data = f.read()
        
        # Check for JPEG markers
        if data[:2] == b'\xff\xd8':
            print("[+] Valid JPEG file detected")
        
        # Find SOS marker (Start of Scan) - 0xFFDA
        sos_pos = data.find(b'\xff\xda')
        if sos_pos != -1:
            print(f"[+] SOS (Start of Scan) marker found at offset: 0x{sos_pos:x}")
            
            # SOS segment length is 2 bytes after marker
            sos_len = int.from_bytes(data[sos_pos+2:sos_pos+4], 'big')
            image_data_start = sos_pos + 4 + sos_len - 2
            print(f"[+] Image data begins at offset: 0x{image_data_start:x}")
            
            # Count image data bytes
            image_data = data[image_data_start:]
            print(f"[+] Image data size: {len(image_data)} bytes")
            
        # Check for EXIF data (FFE1 marker)
        if b'\xff\xe1' in data:
            print("[+] EXIF data detected")
        else:
            print("[+] No EXIF data (FFE1 marker absent)")

PYTHON_ANALYSIS

echo ""
echo "[+] Extracting LSBs and analyzing entropy..."

# Python script for LSB extraction and entropy analysis
python3 << 'PYTHON_LSB'
import struct
import os
from collections import Counter
import math

image_file = "/tmp/dev1.jpeg"
lsb_output = "/tmp/lsb_data.bin"

with open(image_file, 'rb') as f:
    data = bytearray(f.read())

# Find SOS marker (Start of Scan) - 0xFFDA
sos_pos = data.find(b'\xff\xda')
if sos_pos == -1:
    print("[-] SOS marker not found")
    exit(1)

# Parse SOS segment
sos_len = int.from_bytes(data[sos_pos+2:sos_pos+4], 'big')
image_data_start = sos_pos + 4 + sos_len - 2

print(f"[+] SOS marker at: 0x{sos_pos:x}")
print(f"[+] Image data starts at: 0x{image_data_start:x}")

# Extract image data (everything after SOS)
image_data = data[image_data_start:]
print(f"[+] Image data length: {len(image_data)} bytes")

# Extract LSBs
lsb_bytes = bytearray()
lsb_bits = []
ones_count = 0
zeros_count = 0

for i, byte_val in enumerate(image_data):
    lsb = byte_val & 0x01
    lsb_bits.append(lsb)
    if lsb:
        ones_count += 1
    else:
        zeros_count += 1
    
    # Convert every 8 LSBs to a byte
    if len(lsb_bits) == 8:
        byte_val = 0
        for j, bit in enumerate(lsb_bits):
            byte_val |= (bit << (7 - j))
        lsb_bytes.append(byte_val)
        lsb_bits = []

print(f"[+] LSBs extracted: {len(lsb_bytes)} bytes ({len(lsb_bits)} remaining bits)")

# LSB distribution analysis
total_lsbs = ones_count + zeros_count
ones_pct = (ones_count / total_lsbs * 100) if total_lsbs > 0 else 0
zeros_pct = (zeros_count / total_lsbs * 100) if total_lsbs > 0 else 0

print(f"[+] LSB Pattern Analysis:")
print(f"    - Total LSBs: {total_lsbs}")
print(f"    - Ones: {ones_count} ({ones_pct:.2f}%)")
print(f"    - Zeros: {zeros_count} ({zeros_pct:.2f}%)")
print(f"    - Distribution: {min(ones_pct, zeros_pct):.2f}% / {max(ones_pct, zeros_pct):.2f}%")

# Shannon Entropy calculation
byte_freq = Counter(lsb_bytes)
entropy = 0.0
for count in byte_freq.values():
    probability = count / len(lsb_bytes)
    if probability > 0:
        entropy -= probability * math.log2(probability)

print(f"[+] Entropy Analysis:")
print(f"    - Shannon Entropy: {entropy:.2f} bits/byte (max: 8.00)")
print(f"    - Unique bytes: {len(byte_freq)}/256")
print(f"    - Entropy assessment: ", end="")

if entropy >= 7.5:
    print("HIGH (indicates encryption/compression)")
elif entropy >= 6.0:
    print("MEDIUM")
else:
    print("LOW (likely natural image data)")

print(f"[+] Hidden data characteristics:")
print(f"    - First 32 bytes (hex): {lsb_bytes[:32].hex()}")

# Analyze first bytes for patterns
first_bytes = lsb_bytes[:32]
ascii_count = sum(1 for b in first_bytes if 32 <= b <= 126)
print(f"    - ASCII printable in first 32 bytes: {ascii_count}/32")

# Save LSB data
with open(lsb_output, 'wb') as f:
    f.write(lsb_bytes)

print(f"[+] LSB data saved to: {lsb_output}")

# Detection verdict
print("")
print("[+] STEGANOGRAPHY DETECTION VERDICT:")
suspicious = []

if entropy >= 7.5:
    suspicious.append("High entropy (indicates encryption/compression)")
    
if abs(ones_pct - 50.0) < 10:
    suspicious.append("Near-perfect random LSB distribution")
    
if len(byte_freq) >= 250:
    suspicious.append("All 256 byte values represented in hidden layer")

if suspicious:
    print("[!] SUSPICIOUS INDICATORS DETECTED:")
    for indicator in suspicious:
        print(f"    ✗ {indicator}")
    print("[!] CONCLUSION: Likely steganographic content detected")
else:
    print("[+] No significant steganographic indicators")

PYTHON_LSB

echo ""
echo "[+] POC complete. LSB data extracted to $LSB_DATA"