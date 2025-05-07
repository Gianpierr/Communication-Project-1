
import socket
import struct
import time
import os
import sys

ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
ICMP_ECHO_REPLY = 0

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    res = 0
    for i in range(0, len(data), 2):
        res += (data[i + 1] << 8) + data[i]
    res = (res >> 16) + (res & 0xffff)
    res += (res >> 16)
    return ~res & 0xffff

def create_icmp_packet(identifier, sequence):
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    data = b'TracerouteTest'
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, my_checksum, identifier, sequence)
    return header + data

def parse_icmp_reply(data):
    ip_header = data[:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    icmp_header = data[20:28]
    icmph = struct.unpack('!BBHHh', icmp_header)
    return icmph[0], socket.inet_ntoa(iph[8])  # Return type, source IP

def traceroute(dest_name, max_hops=30, timeout=2):
    try:
        dest_addr = socket.gethostbyname(dest_name)
    except socket.gaierror:
        print("Unable to resolve host.")
        return

    print(f"Traceroute to {dest_name} ({dest_addr}), max hops: {max_hops}")
    identifier = os.getpid() & 0xFFFF
    packet_loss = 0

    for ttl in range(1, max_hops + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            sock.settimeout(timeout)
            packet = create_icmp_packet(identifier, ttl)
            start_time = time.time()
            try:
                sock.sendto(packet, (dest_addr, 0))
                data, addr = sock.recvfrom(1024)
                end_time = time.time()
                rtt = (end_time - start_time) * 1000
                icmp_type, source_ip = parse_icmp_reply(data)
                if icmp_type == ICMP_TIME_EXCEEDED:
                    print(f"{ttl}\t{source_ip}\t{rtt:.2f} ms")
                elif icmp_type == ICMP_ECHO_REPLY:
                    print(f"{ttl}\t{source_ip}\t{rtt:.2f} ms (Reached destination)")
                    break
                else:
                    print(f"{ttl}\t{source_ip}\tUnexpected ICMP type: {icmp_type}")
            except socket.timeout:
                packet_loss += 1
                print(f"{ttl}\t*\tRequest timed out")
            except Exception as e:
                print(f"{ttl}\tError: {e}")
                break

    loss_percent = (packet_loss / ttl) * 100
    print(f"\nPacket Loss: {packet_loss} of {ttl} ({loss_percent:.2f}%)")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    traceroute(target)
