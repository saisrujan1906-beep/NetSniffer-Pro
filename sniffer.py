# ============================================================
#
#   ███╗   ██╗███████╗████████╗███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗
#   ████╗  ██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗
#   ██╔██╗ ██║█████╗     ██║   ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝
#   ██║╚██╗██║██╔══╝     ██║   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
#   ██║ ╚████║███████╗   ██║   ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║
#   ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
#
#   NetSniffer Pro v3.1 — Advanced Network Packet Sniffer & Threat Detector
#
#   Author   : Sai Srujan Muchantula
#   Language : Python 3.x
#
#   Capabilities:
#     - Live packet capture with interface selection
#     - Filter by IP, port (multi), protocol
#     - Threat detection: Port Scan, ARP Spoof, ICMP Flood
#     - Geo-IP lookup, Top Talkers, Packet Rate monitor
#     - CSV export with timestamped session logs
#
#   Usage:
#     sudo python3 sniffer.py
#
#   Disclaimer:
#     This tool is strictly for educational and authorized
#     network analysis only. Unauthorized interception of
#     network traffic is illegal. The author takes no
#     responsibility for misuse of this tool.
#
# ============================================================

from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, DNS, DNSQR, get_if_list, get_if_addr, conf
from colorama import Fore, Back, Style, init
from collections import defaultdict, Counter
import csv, datetime, os, sys, time, urllib.request, json, socket, uuid

init(autoreset=True)

# ─── Global storage ───────────────────────────────────────
captured_packets  = []
port_scan_tracker = defaultdict(set)
arp_table         = {}
icmp_counter      = defaultdict(int)
threat_log        = []
ip_packet_count   = defaultdict(int)
packet_times      = []
geo_cache         = {}
packet_counter    = [0]
session_start     = None

# ─── Service port map ─────────────────────────────────────
SERVICE_MAP = {
    20:"FTP-DATA", 21:"FTP",    22:"SSH",     23:"TELNET",
    25:"SMTP",     53:"DNS",    67:"DHCP",    68:"DHCP",
    80:"HTTP",    110:"POP3",  123:"NTP",    143:"IMAP",
    161:"SNMP",   194:"IRC",   443:"HTTPS",  445:"SMB",
    465:"SMTPS",  514:"SYSLOG",587:"SMTP",   631:"IPP",
    993:"IMAPS",  995:"POP3S",1080:"SOCKS", 1433:"MSSQL",
    1521:"ORACLE",3306:"MySQL",3389:"RDP",  5432:"PgSQL",
    5900:"VNC",   6379:"Redis",8080:"HTTP-ALT",
    8443:"HTTPS-ALT", 27017:"MongoDB"
}

def get_service(port):
    return SERVICE_MAP.get(port, "")

# ─── Helpers ──────────────────────────────────────────────
def now():
    return datetime.datetime.now().strftime("%H:%M:%S")

def separator(char="─", color=Fore.WHITE):
    print(color + char * 52)

def clear_line():
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()

def format_bytes(size):
    if size < 1024:
        return f"{size}B"
    elif size < 1048576:
        return f"{size/1024:.1f}KB"
    return f"{size/1048576:.1f}MB"

# ─── Banner ───────────────────────────────────────────────
def banner():
    os.system("clear")
    print(Fore.CYAN + Style.BRIGHT + """
╔══════════════════════════════════════════════╗
║          NetSniffer Pro  v3.1                ║
║    Advanced Packet Sniffer & Analyzer        ║
║    Professional Edition  |  Parrot OS        ║
╠══════════════════════════════════════════════╣
║  [TCP] [UDP] [ICMP] [DNS] [ARP] Detection    ║
║  Threat Detection | Geo-IP | CSV Export      ║
╚══════════════════════════════════════════════╝
    """)

# ─── Startup Network Info ─────────────────────────────────
def show_network_info(iface):
    separator("═", Fore.CYAN)
    print(Fore.CYAN + Style.BRIGHT + "  SYSTEM NETWORK INFORMATION")
    separator("═", Fore.CYAN)
    try:
        hostname = socket.gethostname()
        local_ip = get_if_addr(iface)
        mac      = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff)
                             for i in range(0,48,8)][::-1])
        print(Fore.WHITE + f"  Hostname       : {hostname}")
        print(Fore.WHITE + f"  Interface      : {iface}")
        print(Fore.WHITE + f"  Local IP       : {local_ip}")
        print(Fore.WHITE + f"  MAC Address    : {mac}")
        print(Fore.WHITE + f"  Capture start  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    except Exception as e:
        print(Fore.YELLOW + f"  Could not fetch network info: {e}")
    separator("═", Fore.CYAN)
    print()

# ─── Interface Selector ───────────────────────────────────
def select_interface():
    interfaces = get_if_list()
    print(Fore.CYAN + Style.BRIGHT + "  Available Network Interfaces:\n")
    for i, iface in enumerate(interfaces, 1):
        try:
            ip = get_if_addr(iface)
        except:
            ip = "N/A"
        print(Fore.WHITE + f"   [{i}] {iface:<15} IP: {ip}")
    print()
    choice = input(Fore.GREEN + "  Select interface number (default=1): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
        selected = interfaces[int(choice) - 1]
    else:
        selected = interfaces[0]
    print(Fore.CYAN + f"\n  Using interface: {selected}\n")
    return selected

# ─── Geo-IP Lookup ────────────────────────────────────────
def get_geo(ip):
    if ip.startswith(("10.", "192.168.", "172.", "127.", "0.")):
        return "Local Network"
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,city,org"
        req = urllib.request.urlopen(url, timeout=2)
        data = json.loads(req.read().decode())
        result = f"{data.get('city','?')}, {data.get('country','?')} | {data.get('org','?')}"
        geo_cache[ip] = result
        return result
    except:
        geo_cache[ip] = "Lookup failed"
        return "Lookup failed"

# ─── Config Menu ──────────────────────────────────────────
def get_config(iface):
    print(Fore.YELLOW + "  Configure your capture session:\n")

    separator()
    print(Fore.WHITE + " [1] IP Address Filter")
    print(Fore.WHITE + "     Leave blank to capture ALL IPs")
    ip_filter = input(Fore.GREEN + "     Enter IP to monitor: ").strip()

    separator()
    print(Fore.WHITE + " [2] Port Filter (multi-port supported)")
    print(Fore.WHITE + "     e.g. 80,443,53  or leave blank for ALL")
    port_input  = input(Fore.GREEN + "     Enter port(s): ").strip()
    port_filter = [int(p.strip()) for p in port_input.split(",")
                   if p.strip().isdigit()]

    separator()
    print(Fore.WHITE + " [3] Protocol Filter")
    print(Fore.WHITE + "     1=TCP  2=UDP  3=ICMP  4=ALL (default)")
    proto_input  = input(Fore.GREEN + "     Choose (1/2/3/4): ").strip()
    proto_map    = {"1":"TCP","2":"UDP","3":"ICMP","4":"ALL"}
    proto_filter = proto_map.get(proto_input, "ALL")

    separator()
    print(Fore.WHITE + " [4] Packet Count")
    count_input  = input(Fore.GREEN + "     How many packets? (default 100): ").strip()
    packet_count = int(count_input) if count_input.isdigit() else 100

    separator()
    print(Fore.WHITE + " [5] Geo-IP Lookup")
    print(Fore.WHITE + "     Requires internet. Slows output slightly.")
    geo_input   = input(Fore.GREEN + "     Enable? (y/n, default n): ").strip().lower()
    geo_enabled = geo_input == "y"

    separator()
    print(Fore.CYAN + "\n  Capture settings confirmed:")
    print(Fore.WHITE + f"   Interface   : {iface}")
    print(Fore.WHITE + f"   IP filter   : {ip_filter if ip_filter else 'ALL'}")
    print(Fore.WHITE + f"   Ports       : {port_filter if port_filter else 'ALL'}")
    print(Fore.WHITE + f"   Protocol    : {proto_filter}")
    print(Fore.WHITE + f"   Packets     : {packet_count}")
    print(Fore.WHITE + f"   Geo-IP      : {'Enabled' if geo_enabled else 'Disabled'}")
    separator()
    input(Fore.YELLOW + "\n  Press ENTER to start capture...")

    return {
        "iface":    iface,
        "ip":       ip_filter,
        "ports":    port_filter,
        "protocol": proto_filter,
        "count":    packet_count,
        "geo":      geo_enabled
    }

# ─── Threat Detection ─────────────────────────────────────
def detect_port_scan(src_ip, dst_port):
    port_scan_tracker[src_ip].add(dst_port)
    if len(port_scan_tracker[src_ip]) == 15:
        alert = f"PORT SCAN from {src_ip} ({len(port_scan_tracker[src_ip])} ports)"
        print(Fore.RED + Back.BLACK + f"\n  [{now()}] ⚠  THREAT: {alert}\n")
        threat_log.append({"time":now(),"type":"Port Scan","detail":alert})

def detect_arp_spoof(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        src_ip  = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        if src_ip in arp_table:
            if arp_table[src_ip] != src_mac:
                alert = f"ARP SPOOF: {src_ip} MAC changed {arp_table[src_ip]}→{src_mac}"
                print(Fore.RED + Back.BLACK + f"\n  [{now()}] ⚠  THREAT: {alert}\n")
                threat_log.append({"time":now(),"type":"ARP Spoof","detail":alert})
        else:
            arp_table[src_ip] = src_mac

def detect_icmp_flood(src_ip):
    icmp_counter[src_ip] += 1
    if icmp_counter[src_ip] == 20:
        alert = f"ICMP FLOOD from {src_ip} ({icmp_counter[src_ip]} pings)"
        print(Fore.RED + Back.BLACK + f"\n  [{now()}] ⚠  THREAT: {alert}\n")
        threat_log.append({"time":now(),"type":"ICMP Flood","detail":alert})

# ─── Filter Check ─────────────────────────────────────────
def matches_filter(packet, config):
    if not packet.haslayer(IP):
        return False

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if config["ip"] and config["ip"] not in (src_ip, dst_ip):
        return False

    proto = config["protocol"]
    if proto == "TCP"  and not packet.haslayer(TCP):  return False
    if proto == "UDP"  and not packet.haslayer(UDP):  return False
    if proto == "ICMP" and not packet.haslayer(ICMP): return False

    if config["ports"]:
        has_port = False
        for port in config["ports"]:
            if packet.haslayer(TCP):
                if port in (packet[TCP].sport, packet[TCP].dport):
                    has_port = True; break
            elif packet.haslayer(UDP):
                if port in (packet[UDP].sport, packet[UDP].dport):
                    has_port = True; break
        if not has_port:
            return False

    return True

# ─── Packet Processor ─────────────────────────────────────
def make_processor(config):
    def process_packet(packet):
        detect_arp_spoof(packet)

        if not matches_filter(packet, config):
            return

        timestamp = now()
        packet_times.append(time.time())
        packet_counter[0] += 1

        proto  = "OTHER"
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size   = len(packet)

        ip_packet_count[src_ip] += 1
        ip_packet_count[dst_ip] += 1

        geo_src = get_geo(src_ip) if config["geo"] else ""
        geo_dst = get_geo(dst_ip) if config["geo"] else ""

        # Live counter
        clear_line()
        sys.stdout.write(
            Fore.YELLOW + f"  [Captured: {packet_counter[0]}/{config['count']}]  " +
            Fore.WHITE   + f"Rate: {get_packet_rate():.1f} pkt/s\r"
        )
        sys.stdout.flush()

        # ── TCP ──────────────────────────────────────────
        if packet.haslayer(TCP):
            proto   = "TCP"
            sp      = packet[TCP].sport
            dp      = packet[TCP].dport
            flags   = packet[TCP].flags
            svc     = get_service(dp) or get_service(sp)
            svc_lbl = f"[{svc}]" if svc else ""
            detect_port_scan(src_ip, dp)
            print(Fore.GREEN +
                f"\n  {timestamp}  TCP  "
                f"{src_ip:<18}:{sp:<6} → "
                f"{dst_ip:<18}:{dp:<6} "
                f"{svc_lbl:<12} {size}B  flags={flags}")

        # ── UDP ──────────────────────────────────────────
        elif packet.haslayer(UDP):
            proto   = "UDP"
            sp      = packet[UDP].sport
            dp      = packet[UDP].dport
            svc     = get_service(dp) or get_service(sp)
            svc_lbl = f"[{svc}]" if svc else ""
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                domain = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
                print(Fore.CYAN +
                    f"\n  {timestamp}  DNS  "
                    f"{src_ip:<18} → lookup '{domain}'  {size}B")
            else:
                print(Fore.YELLOW +
                    f"\n  {timestamp}  UDP  "
                    f"{src_ip:<18}:{sp:<6} → "
                    f"{dst_ip:<18}:{dp:<6} "
                    f"{svc_lbl:<12} {size}B")

        # ── ICMP ─────────────────────────────────────────
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            detect_icmp_flood(src_ip)
            print(Fore.BLUE +
                f"\n  {timestamp}  ICMP "
                f"{src_ip:<18} → {dst_ip:<18} "
                f"{'[PING]':<12} {size}B")

        else:
            print(Fore.WHITE +
                f"\n  {timestamp}  PKT  "
                f"{src_ip:<18} → {dst_ip:<18} {size}B")

        if config["geo"]:
            if geo_src and "Local" not in geo_src and "failed" not in geo_src:
                print(Fore.WHITE + f"               src ▸ {geo_src}")
            if geo_dst and "Local" not in geo_dst and "failed" not in geo_dst:
                print(Fore.WHITE + f"               dst ▸ {geo_dst}")

        captured_packets.append({
            "time":    timestamp,
            "proto":   proto,
            "src_ip":  src_ip,
            "dst_ip":  dst_ip,
            "size":    size,
            "geo_src": geo_src,
            "geo_dst": geo_dst,
            "summary": packet.summary()
        })

    return process_packet

# ─── Packet Rate ──────────────────────────────────────────
def get_packet_rate():
    if len(packet_times) < 2:
        return 0.0
    duration = packet_times[-1] - packet_times[0]
    return len(packet_times) / duration if duration > 0 else 0.0

# ─── Session Duration ─────────────────────────────────────
def get_duration():
    if not session_start:
        return "N/A"
    elapsed = int(time.time() - session_start)
    mins, secs = divmod(elapsed, 60)
    return f"{mins}m {secs}s"

# ─── Save CSV ─────────────────────────────────────────────
def save_csv():
    filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f,
            fieldnames=["time","proto","src_ip","dst_ip","size","geo_src","geo_dst","summary"])
        writer.writeheader()
        writer.writerows(captured_packets)
    print(Fore.GREEN + f"\n  [✓] Packets saved  → {filename}")

    if threat_log:
        tfile = f"threats_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(tfile, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["time","type","detail"])
            writer.writeheader()
            writer.writerows(threat_log)
        print(Fore.RED + f"  [!] Threats saved  → {tfile}")

# ─── Summary Report ───────────────────────────────────────
def print_report(config):
    total_bytes = sum(p.get("size", 0) for p in captured_packets)
    separator("═", Fore.CYAN)
    print(Fore.CYAN + Style.BRIGHT + "         SESSION SUMMARY REPORT")
    separator("═", Fore.CYAN)
    print(Fore.WHITE + f"  Interface      : {config.get('iface','N/A')}")
    print(Fore.WHITE + f"  Session time   : {get_duration()}")
    print(Fore.WHITE + f"  IP filter      : {config['ip'] if config['ip'] else 'ALL'}")
    print(Fore.WHITE + f"  Port filter    : {config['ports'] if config['ports'] else 'ALL'}")
    print(Fore.WHITE + f"  Protocol       : {config['protocol']}")
    separator()
    print(Fore.WHITE + f"  Total packets  : {len(captured_packets)}")
    print(Fore.WHITE + f"  Total data     : {format_bytes(total_bytes)}")
    print(Fore.WHITE + f"  Avg pkt rate   : {get_packet_rate():.2f} packets/sec")
    separator()

    counts = Counter(p["proto"] for p in captured_packets)
    for proto, count in sorted(counts.items()):
        pct = int((count / max(len(captured_packets), 1)) * 30)
        bar = "█" * pct
        print(Fore.WHITE + f"  {proto:<8}       : {count:>4}  {bar}")

    print(Fore.WHITE + f"\n  Unique src IPs : {len(set(p['src_ip'] for p in captured_packets))}")

    separator()
    print(Fore.CYAN + Style.BRIGHT + "  TOP TALKERS")
    separator()
    top5 = sorted(ip_packet_count.items(), key=lambda x: x[1], reverse=True)[:5]
    for rank, (ip, count) in enumerate(top5, 1):
        geo  = geo_cache.get(ip, "")
        bar  = "█" * min(count, 20)
        geo_str = f"  {geo}" if geo and "Local" not in geo and "failed" not in geo else ""
        print(Fore.YELLOW + f"  #{rank}  {ip:<22} {count:>4} pkts  {bar}{geo_str}")

    separator()
    threat_color = Fore.RED if threat_log else Fore.GREEN
    print(threat_color + f"  Threats detected : {len(threat_log)}")
    for t in threat_log:
        print(Fore.RED + f"    [{t['time']}] {t['type']}: {t['detail']}")
    separator("═", Fore.CYAN)

# ─── Clean Exit ───────────────────────────────────────────
def clean_exit(config):
    print(Fore.YELLOW + "\n\n  ┌─────────────────────────────────┐")
    print(Fore.YELLOW +   "  │     Session Ended by User        │")
    print(Fore.YELLOW + f"  │     Duration : {get_duration():<18}│")
    print(Fore.YELLOW + f"  │     Captured : {len(captured_packets):<18}│")
    print(Fore.YELLOW +   "  └─────────────────────────────────┘\n")
    print_report(config)
    save_csv()

# ─── Entry Point ──────────────────────────────────────────
if __name__ == "__main__":
    try:
        banner()
        iface  = select_interface()
        show_network_info(iface)
        config = get_config(iface)
        session_start = time.time()

        print(Fore.YELLOW +
            f"\n  [*] Starting capture on {iface} "
            f"| {config['count']} packets max "
            f"| Press Ctrl+C to stop\n")
        separator()

        sniff(iface=iface, prn=make_processor(config),
              count=config["count"], store=False)

        clear_line()
        print_report(config)
        save_csv()

    except KeyboardInterrupt:
        clean_exit(config)
    except PermissionError:
        print(Fore.RED + "\n  [✗] Permission denied. Run with sudo:\n")
        print(Fore.WHITE + "      sudo python3 sniffer.py\n")
        sys.exit(1)
