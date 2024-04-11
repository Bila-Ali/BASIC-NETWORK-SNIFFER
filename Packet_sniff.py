import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"IP Source: {ip_src}, IP Destination: {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Source Port: {src_port}, TCP Destination Port: {dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Source Port: {src_port}, UDP Destination Port: {dst_port}")

sniff_packets("Wi-Fi")






















































































# from scapy.all import * 
# def packet_callback(packet) :
#     if packet.haslayer(IP) :
#         src_ip = packet[IP].src_ip
#         dst_ip = packet[IP].dst_ip
#         print(f"Source IP: {scr_ip} --> Destination IP: {dst_ip}")


# sniff(prn=packet_callback,  store=0)


# from scapy.all import sniff, conf
# def packet_callback(packet) :
#     print(packet.summary())
# conf.L3socket = conf.L3socket

# sniff(prn=packet_callback, co=10)