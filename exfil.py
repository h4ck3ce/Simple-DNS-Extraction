from scapy.all import rdpcap, DNS, DNSQR
import base64

# Configuration
PCAP_FILE = "dns_capture.pcap"
OUTPUT_FILE = "decoded_output.txt"
TARGET_DOMAIN = "lab.local"

def fix_padding(data):
    """Adds missing Base64 padding."""
    return data + '=' * (-len(data) % 4)

def process_pcap():
    print(f"[*] Reading {PCAP_FILE}...")
    try:
        packets = rdpcap(PCAP_FILE)
    except FileNotFoundError:
        print(f"[!] Error: {PCAP_FILE} not found.")
        return

    chunks = {}

    for pkt in packets:
        # Check for DNS Query (qr=0)
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            query = pkt.getlayer(DNSQR).qname.decode().strip('.')
            
            if TARGET_DOMAIN in query:
                # Expecting format: index-encodeddata.lab.local
                subdomain = query.split('.')[0]
                if '-' in subdomain:
                    try:
                        idx_str, encoded_chunk = subdomain.split('-', 1)
                        chunks[int(idx_str)] = encoded_chunk
                    except ValueError:
                        continue

    if not chunks:
        print("[!] No valid data chunks found in the PCAP.")
        return

    # Sort by index and join
    print(f"[*] Reassembling {len(chunks)} chunks...")
    sorted_indices = sorted(chunks.keys())
    full_b64 = "".join(chunks[i] for i in sorted_indices)

    try:
        # Decode and save
        decoded_bytes = base64.b64decode(fix_padding(full_b64))
        with open(OUTPUT_FILE, "wb") as f:
            f.write(decoded_bytes)
        
        print(f"[SUCCESS] Data decoded and saved to: {OUTPUT_FILE}")
    except Exception as e:
        print(f"[!] Decoding failed: {e}")

if __name__ == "__main__":
    process_pcap()
