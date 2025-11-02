from scapy.all import sniff, IP

def analyze_packet(pkt):
    print("----- Packet -----")
    if IP in pkt:
        ip = pkt[IP]
        print("Src:", ip.src, "-> Dst:", ip.dst, "| Protocol:", ip.proto)
    else:
        print("Non-IP packet:", pkt.summary())

print("Starting capture: capturing 5 packets...")
sniff(count=5, prn=analyze_packet)
print("Capture finished.")
