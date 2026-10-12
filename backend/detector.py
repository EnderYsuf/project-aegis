import socket
import dpkt
import sys

# ip address to string
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# duration formating
def format_duration(_sec):
    hour = int(_sec // 3600)
    mins = int((_sec % 3600) // 60)
    sec = int(_sec % 60)
    ms = int((_sec - int(_sec)) * 1000)
    return f"{hour:02d}:{mins:02d}:{sec:02d}.{ms:03d}"

# severity calculation out of score
def get_severity(score):
    if score >= 75:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"
# analyzer function
def analyze(path):
    # setup
    total_packets = 0
    start_time = None
    end_time = None

    dns_txt_count = {}
    syn_requests = {}
    cleartext = []
    large_icmp = []
    suspicious_tcp = []
    tcp_port_scan = {}
    dga_dns = []
    insecure_protos = []
    udp_requests = {}
    icmp_requests = {}

    anomalies = []
    anom_counter = 1

    # analysis
    try:
        with open(path, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                try:
                    pcap = dpkt.pcapng.Reader(f)
                except Exception:
                    raise ValueError("Invalid or corrupted PCAP/PCAPNG file")

            datalink = pcap.datalink()

            for ts, buf in pcap:
                total_packets += 1

                if start_time is None:
                    start_time = ts
                end_time = ts

                try:
                    if datalink == dpkt.pcap.DLT_LINUX_SLL:
                        link_layer = dpkt.sll.SLL(buf)
                    elif datalink == dpkt.pcap.DLT_NULL or datalink == dpkt.pcap.DLT_LOOP:
                        link_layer = dpkt.loopback.Loopback(buf)
                    else:
                        link_layer = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                if not isinstance(link_layer.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue

                ip = link_layer.data
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)

                if isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data

                    udp_key = (dst_ip, udp.dport)
                    if udp_key not in udp_requests:
                        # tracking for src ports for identifying service typees
                        udp_requests[udp_key] = {"count": 0, "sources": set(), "sports": set()}
                    udp_requests[udp_key]["count"] += 1
                    udp_requests[udp_key]["sources"].add(src_ip)
                    udp_requests[udp_key]["sports"].add(udp.sport)

                    if udp.dport == 53 or udp.sport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            for q in dns.qd:
                                if q.type == dpkt.dns.DNS_TXT:
                                    if src_ip not in dns_txt_count:
                                        dns_txt_count[src_ip] = []
                                    dns_txt_count[src_ip].append(total_packets)

                                if len(q.name) > 45:
                                    dga_dns.append((total_packets, q.name))
                        except Exception:
                            pass

                elif isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data

                    if src_ip not in tcp_port_scan:
                        tcp_port_scan[src_ip] = set()
                    tcp_port_scan[src_ip].add(tcp.dport)

                    if tcp.dport in [21, 23]:
                        insecure_protos.append((total_packets, tcp.dport))

                    if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
                        key = (dst_ip, tcp.dport)
                        if key not in syn_requests:
                            syn_requests[key] = {"count": 0, "sources": set()}
                        syn_requests[key]["count"] += 1
                        syn_requests[key]["sources"].add(src_ip)

                    if tcp.flags == 0:
                        suspicious_tcp.append((total_packets, src_ip, "Null Scan"))
                    elif tcp.flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_URG | dpkt.tcp.TH_PUSH) == (dpkt.tcp.TH_FIN | dpkt.tcp.TH_URG | dpkt.tcp.TH_PUSH):
                        suspicious_tcp.append((total_packets, src_ip, "Xmas Scan"))

                    if len(tcp.data) > 0:
                        payload = tcp.data.lower()
                        if b"post " in payload or b"authorization: basic" in payload:
                            if b"password=" in payload or b"passwd=" in payload or b"authorization" in payload:
                                cleartext.append((total_packets, tcp.dport))

                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp = ip.data

                    if dst_ip not in icmp_requests:
                        icmp_requests[dst_ip] = {"count": 0, "sources": set()}
                    icmp_requests[dst_ip]["count"] += 1
                    icmp_requests[dst_ip]["sources"].add(src_ip)

                    if len(icmp.data) > 1000:
                        large_icmp.append((total_packets, src_ip))

    except FileNotFoundError:
        raise ValueError("PCAP file not found")

    duration_str = "00:00:00.000"
    if start_time is not None and end_time is not None:
        duration_str = format_duration(end_time - start_time)

    # scoring and evaluation
    # ANOM-1 dns tunneling detection
    for src, packets in dns_txt_count.items():
        if len(packets) >= 5:
            score = min(60 + (len(packets) * 2), 100)
            anomalies.append({
                "id": f"ANOM-1-{anom_counter:02d}", "type": "DNS Tunneling",
                "score": score, "severity": get_severity(score),
                "description": f"Detected {len(packets)} DNS TXT queries from {src} starting at packet {packets[0]}."
            })
            anom_counter += 1
    # ANOM-2 syn flood detection
    for (dst, dport), data in syn_requests.items():
        if data["count"] >= 50:
            if len(data["sources"]) > 10:
                attack_type = "Distributed SYN Flood (DDoS)"
                score = min(80 + (data["count"] // 100) * 5, 100)
            else:
                attack_type = "SYN Flood (DoS)"
                score = min(60 + (data["count"] // 100) * 5, 90)

            anomalies.append({
                "id": f"ANOM-2-{anom_counter:02d}", "type": attack_type,
                "score": score, "severity": get_severity(score),
                "description": f"Target {dst}:{dport} was hit with {data['count']} SYN packets from {len(data['sources'])} unique IPs."
            })
            anom_counter += 1
    # ANOM-3 cleartext credential detection
    for pkt_num, dport in cleartext:
        score = 75
        anomalies.append({
            "id": f"ANOM-3-{anom_counter:02d}", "type": "Cleartext Transmission",
            "score": score, "severity": get_severity(score),
            "description": f"Detected cleartext credential transmission on port {dport} at packet {pkt_num}."
        })
        anom_counter += 1
    # ANOM-4 large icmp payload detection
    for pkt_num, src in large_icmp:
        score = 45
        anomalies.append({
            "id": f"ANOM-4-{anom_counter:02d}", "type": "Large ICMP Payload",
            "score": score, "severity": get_severity(score),
            "description": f"Unusually large ICMP packet from {src} at packet {pkt_num} (potential exfiltration)."
        })
        anom_counter += 1
    # ANOM-5 suspicious tcp flags detection
    for pkt_num, src, scan_type in suspicious_tcp:
        score = 50
        anomalies.append({
            "id": f"ANOM-5-{anom_counter:02d}", "type": "Suspicious TCP Flags",
            "score": score, "severity": get_severity(score),
            "description": f"Detected {scan_type} from {src} at packet {pkt_num}."
        })
        anom_counter += 1
    # ANOM-6 tcp port scanning detection
    for src, ports in tcp_port_scan.items():
        if len(ports) >= 20:
            score = min(40 + len(ports), 95)
            anomalies.append({
                "id": f"ANOM-6-{anom_counter:02d}", "type": "Port Scanning",
                "score": score, "severity": get_severity(score),
                "description": f"Host {src} targeted {len(ports)} unique ports (potential reconnaissance)."
            })
            anom_counter += 1
    # ANOM-7 suspicious dns request detection
    for pkt_num, domain in dga_dns:
        score = 65
        anomalies.append({
            "id": f"ANOM-7-{anom_counter:02d}", "type": "Suspicious DNS Request",
            "score": score, "severity": get_severity(score),
            "description": f"Query for unusually long domain name ({domain[:30]}...) at packet {pkt_num}."
        })
        anom_counter += 1
    # ANOM-8 insecure protocol detection
    for pkt_num, dport in insecure_protos:
        score = 30
        anomalies.append({
            "id": f"ANOM-8-{anom_counter:02d}", "type": "Insecure Protocol Detected",
            "score": score, "severity": get_severity(score),
            "description": f"Unencrypted legacy protocol traffic detected on port {dport} at packet {pkt_num}."
        })
        anom_counter += 1
    # ANOM-9 udp and icmp flood detection
    for (dst, dport), data in udp_requests.items():
        # exclude high-volume udp if legitimate
        # 443 - normal used for QUIC streaming
        is_quic_stream = (dport == 443 or 443 in data["sports"])
        if is_quic_stream and len(data["sources"]) < 10:
            continue # to ignore

        if data["count"] >= 100:
            if len(data["sources"]) > 10:
                attack_type = "Distributed UDP Flood (DDoS)"
                score = min(80 + (data["count"] // 100) * 5, 100)
            else:
                attack_type = "UDP Flood (DoS)"
                score = min(60 + (data["count"] // 100) * 5, 90)

            anomalies.append({
                "id": f"ANOM-9-{anom_counter:02d}", "type": attack_type,
                "score": score, "severity": get_severity(score),
                "description": f"Target {dst}:{dport} was hit with {data['count']} UDP packets from {len(data['sources'])} unique IPs."
            })
            anom_counter += 1
    # ANOM-10 icmp flood detection
    for dst, data in icmp_requests.items():
        if data["count"] >= 100:
            if len(data["sources"]) > 10:
                attack_type = "Distributed ICMP Flood (DDoS)"
                score = min(80 + (data["count"] // 100) * 5, 100)
            else:
                attack_type = "ICMP Flood (DoS)"
                score = min(60 + (data["count"] // 100) * 5, 90)

            anomalies.append({
                "id": f"ANOM-10-{anom_counter:02d}", "type": attack_type,
                "score": score, "severity": get_severity(score),
                "description": f"Target {dst} was hit with {data['count']} ICMP ping requests from {len(data['sources'])} unique IPs."
            })
            anom_counter += 1

    # overall threat level assessment
    total_score = sum(a["score"] for a in anomalies)

    # if average is high, needed score may be increased
    if total_score >= 150 or any(a["score"] >= 90 for a in anomalies):
        threat_level = "Critical"
    elif total_score >= 75:
        threat_level = "High"
    elif total_score >= 40:
        threat_level = "Medium"
    elif total_score > 0:
        threat_level = "Low"
    else:
        threat_level = "None"

    analysis_res = {
        "filename": path.split("/")[-1].split("\\")[-1],
        "total_packets": total_packets,
        "duration": duration_str,
        "total_anomaly_score": total_score,
        "overall_threat_level": threat_level,
        "anomalies": anomalies
    }

    return analysis_res
# debugging and testing
if __name__ == "__main__":
    test_file = sys.argv[1] if len(sys.argv) > 1 else "test.pcap"
    print(f"[*] Running debug analysis on {test_file}...\n")

    result = analyze(test_file)
    import json
    print(json.dumps(result, indent=4))
