import socket
import time
import dpkt

def sanitize_pcap(input_file, output_file):
    start_time = time.time()
    ip_map = {}
    next_ip_int = 0x0A000001
    packet_count = 0

    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        pcap_in = dpkt.pcap.Reader(f_in)
        pcap_out = dpkt.pcap.Writer(f_out)

        for timestamp, buf in pcap_in:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                eth.src = b'\x00\x00\x00\x00\x00\x00'
                eth.dst = b'\x00\x00\x00\x00\x00\x00'

                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data

                    # Anonymize IP addresses
                    for attr in ['src', 'dst']:
                        val = getattr(ip, attr)
                        if val not in ip_map:
                            ip_map[val] = next_ip_int.to_bytes(4, byteorder='big')
                            next_ip_int += 1
                        setattr(ip, attr, ip_map[val])

                    # Sanitize payload
                    if hasattr(ip.data, 'data') and ip.data.data:
                        ip.data.data = b'[CLEARED]'

                        # Zero out transport layer length and checksum if present
                        if hasattr(ip.data, 'ulen'):
                            ip.data.ulen = 0
                        if hasattr(ip.data, 'sum'):
                            try:
                                ip.data.sum = 0
                            except AttributeError:
                                pass

                    # Zero out IP length and checksum to force recalculation on bytes(eth)
                    ip.len = 0
                    ip.sum = 0

                # Write packet
                pcap_out.writepkt(eth, ts=timestamp)
                packet_count += 1

            except Exception as e:
                print(f"[ERROR] Skipped packet {packet_count + 1} due to: {e}")
                continue

    end_time = time.time()
    print(f"[INFO] Processed {packet_count} packets in {end_time - start_time:.2f} seconds")
