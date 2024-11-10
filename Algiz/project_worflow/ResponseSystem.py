import socket
import nmap
import ipaddress
from scapy.all import ARP, Ether, srp, get_if_hwaddr,get_if_list
import netaddr
import psutil
import time
import paramiko


SCAN_DELAY = 1


firewall_info = {
    "cisco": {
        "name": "Cisco",
        "mac_prefixes": ["00:1A:A2", "00:25:45", "00:37:B7", "18:66:DA", "2C:54:2D"]
    },
    "fortinet": {
        "name": "Fortinet",
        "mac_prefixes": ["00:09:0F", "00:1C:57", "E4:6F:13"]
    },
    "palo_alto": {
        "name": "Palo Alto Networks",
        "mac_prefixes": ["00:1B:17", "00:1C:46", "00:1E:49"]
    },
    "checkpoint": {
        "name": "Check Point",
        "mac_prefixes": ["00:0C:29", "00:1C:7F", "00:24:21"]
    },
    "sonicwall": {
        "name": "SonicWall",
        "mac_prefixes": ["00:17:C5", "00:21:5A", "08:96:D7"]
    },
    "juniper": {
        "name": "Juniper Networks",
        "mac_prefixes": ["00:05:85", "00:12:1E", "3C:61:04"]
    },
    "sophos": {
        "name": "Sophos",
        "mac_prefixes": ["00:26:76", "00:50:56", "90:6C:AC"]
    },
    "ibm": {
        "name": "IBM",
        "mac_prefixes": ["00:04:AC", "00:09:6B", "00:14:5E"]
    },
    "huawei": {
        "name": "Huawei",
        "mac_prefixes": ["00:0F:E2", "00:1A:1A", "E0:55:3D"]
    },
    "pfsense": {
        "name": "pfSense",
        "mac_prefixes": ["00:15:17", "00:1C:73", "90:E2:BA"]
    },
    "mikrotik": {
        "name": "MikroTik",
        "mac_prefixes": ["4C:5E:0C", "6C:3B:6B", "74:4D:28"]
    },
    "f5_big_ip": {
        "name": "F5 BIG-IP",
        "mac_prefixes": ["00:A0:DD", "00:1D:BA", "10:2B:4F"]
    },
    "watchguard": {
        "name": "WatchGuard",
        "mac_prefixes": ["00:0E:2E", "00:1A:70", "00:19:AA"]
    },
    "barracuda": {
        "name": "Barracuda",
        "mac_prefixes": ["00:16:B6", "00:1B:21", "00:22:33"]
    }
}

linux_os_dict = {
    "ubuntu": ["Ubuntu", "ubuntu"],
    "debian": ["Debian", "debian"],
    "centos": ["CentOS", "centos"],
    "fedora": ["Fedora", "fedora"],
    "redhat": ["Red Hat", "redhat", "RHEL"],
    "suse": ["SUSE", "suse", "openSUSE"],
    "arch": ["Arch Linux", "arch"],
    "kali": ["Kali Linux", "kali"],
    "mint": ["Linux Mint", "mint"],
    "raspbian": ["Raspbian", "raspbian"],
    "alpine": ["Alpine Linux", "alpine"],
    "oracle": ["Oracle Linux", "oracle"],
    "scientific": ["Scientific Linux", "scientific"],
    "mageia": ["Mageia", "mageia"],
    "elementary": ["elementary OS", "elementary"],
    "manjaro": ["Manjaro", "manjaro"],
    "clearos": ["ClearOS", "clearos"],
    "zorin": ["Zorin OS", "zorin"],
    "deepin": ["Deepin", "deepin"],
    "slackware": ["Slackware", "slackware"],
    "pop_os": ["Pop!_OS", "pop_os"],
    "backbox": ["BackBox", "backbox"],
    "parrot": ["Parrot OS", "parrot"],
    "garuda": ["Garuda Linux", "garuda"],
    "rocky": ["Rocky Linux", "rocky"],
    "alma": ["AlmaLinux", "alma"],
    "void": ["Void Linux", "void"],
    "gentoo": ["Gentoo", "gentoo"]
}

# Commands to check for IDS/IPS tools
ids_ips_check_commands = {
    "Prelude": "which prelude-manager",
    "Suricata": "which suricata",
    "Snort": "which snort",
    "OSSEC": "which ossec-control",
    "Fail2Ban": "which fail2ban-client",
    "AIDE": "which aide",
    "Tripwire": "which tripwire",
    "Samhain": "which samhain",
    "Wazuh": "which wazuh",
    "Telerik Fiddler": "which fiddler",
    "Security Onion": "which securityonion",
    "ClamAV": "which clamscan",
    "NAXSI": "which naxsi",
    "Bro/Zeek": "which zeek",
    "Snoopy": "which snoopy"
    }

ids_ips_paths = {
    "Prelude": "/etc/prelude/prelude-manager.conf",
    "Suricata": "/etc/suricata/suricata.yaml",
    "Snort": "/etc/snort/snort.conf",
    "OSSEC": "/etc/ossec/ossec.conf",
    "Fail2Ban": "/etc/fail2ban/fail2ban.conf",
    "AIDE": "/etc/aide/aide.conf",
    "Tripwire": "/etc/tripwire/tw.conf",
    "Samhain": "/etc/samhain/samhainrc",
    "Wazuh": "/var/ossec/ossec.conf",
    "Telerik Fiddler": "~/.fiddler/fiddler.config",  # User-specific path
    "Security Onion": "/etc/securityonion/securityonion.conf",
    "ClamAV": "/etc/clamav/clamd.conf",
    "NAXSI": "/etc/nginx/naxsi_config",  # NAXSI is for Nginx
    "Bro/Zeek": "/opt/zeek/zeekctl.cfg",
    "Snoopy": "/etc/snoopy/snoopy.conf"
}


# Function to get own IP address
def get_own_ip(): 
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname_ex(hostname)[2][0]
        return ip
    except Exception:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

# Function to get own MAC address
def get_own_mac():
    # Get a list of available interfaces
    interfaces = get_if_list()
    
    # Find the appropriate interface (for example, 'Ethernet' or 'Wi-Fi' in Windows)
    for iface in interfaces:
        if 'Ethernet' in iface or 'Wi-Fi' in iface:
            return get_if_hwaddr(iface)
    
    return None

# Function to calculate network range
def calculate_network(ip):
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == ip:
                subnet = addr.netmask
                network = ipaddress.IPv4Network(f"{ip}/{subnet}", strict=False)
                return str(network)
    print("Could not determine subnet mask automatically. Defaulting to /24.")
    return f"{ip}/24"

# Function to scan network and find active hosts
def scan_network(network_range):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sn')
        live_hosts = []
        for host in nm.all_hosts():
            if 'up' in nm[host].state():
                live_hosts.append(host)
        if not live_hosts:
            print("Operation is blocked, check with the admin.")
            return [], None
    except Exception as e:
        print("Operation is blocked, check with the admin.")
        return [], None
    return live_hosts, nm

# Function to get MAC address for a specific IP
def get_mac_address(ip, own_mac):
    arp_request = ARP(pdst=ip)
    target = Ether(dst=own_mac)
    arp_request_target = target/arp_request
    answered_list = srp(arp_request_target, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

# Function to get vendor from MAC address
def get_mac_vendor(mac_address):
    try:
        mac = netaddr.EUI(mac_address)
        vendor = mac.oui.registration().org
    except netaddr.core.NotRegisteredError:
        vendor = "Unknown"
    return vendor

# Function to get OS info from Nmap scan result
def get_os_info(nm, ip):
    if ip in nm.all_hosts():
        if 'osmatch' in nm[ip]:
            return nm[ip]['osmatch'][0]['name']
    return "Unknown"

# Function to get service info from Nmap scan result
def get_service_info(nm, ip):
    if ip in nm.all_hosts() and 'tcp' in nm[ip]:
        services = nm[ip]['tcp']
        return {port: services[port]['name'] for port in services}
    return {}

# Function to detect Linux OS from scan results
def detect_linux_machines(live_hosts, nm):
    linux_machines = []
    for ip in live_hosts:
        os_info = get_os_info(nm, ip)
        for os_key, identifiers in linux_os_dict.items():
            if any(identifier.lower() in os_info.lower() for identifier in identifiers):
                mac_address = get_mac_address(ip, get_own_mac())
                linux_machines.append({'IP': ip, 'MAC': mac_address, 'OS': os_info})
    return linux_machines

# Function to check IDS/IPS tools via SSH
def check_ids_ips_via_ssh(ip, mac_address, os_info, ssh_user, ssh_password):
    ids_ips_results = []
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(ip, username=ssh_user, password=ssh_password)

        for ids_name, check_command in ids_ips_check_commands.items():
            stdin, stdout, stderr = ssh_client.exec_command(check_command)
            result = stdout.read().decode().strip()
            if result:
                ids_ips_results.append({
                    "IP": ip,
                    "MAC": mac_address,
                    "OS": os_info,
                    "IDS/IPS Tool": ids_name
                })

        ssh_client.close()
    except Exception as e:
        print(f"Error checking {attacker_ip}: {e}")

    return ids_ips_results
def apply_ids_ips_rules(ip, mac_address, os_info, ids_ips_user, ids_ips_password, attack_type):
    ids_ips_results, ids_found = check_ids_ips_via_ssh(ip, mac_address, os_info, ids_ips_user, ids_ips_password)

    if "Prelude" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                prelude_backdoor_rule = f"echo 'alert tcp {attacker_ip} any -> any 22 (msg:\"Backdoor access attempt\"; flags:S,12; threshold:type both, track by_src, count 5, seconds 60; sid:1000001;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_backdoor_rule)
                prelude_block_backdoor = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_backdoor)

            elif attack_type == "ddos":
                prelude_ddos_rule = f"echo 'alert ip {attacker_ip} any -> any any (msg:\"DDoS traffic detected\"; ip_proto:icmp; threshold:type both, track by_src, count 20, seconds 5; sid:1000002;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_ddos_rule)
                prelude_block_ddos = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_ddos)

            elif attack_type == "injection":
                prelude_injection_rule = f"echo 'alert tcp {attacker_ip} any -> any 80 (msg:\"SQL Injection attempt\"; content:\"' OR 1=1\"; nocase; sid:1000003;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_injection_rule)
                prelude_block_injection = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_injection)

            elif attack_type == "password":
                prelude_password_rule = f"echo 'alert tcp {attacker_ip} any -> any 22 (msg:\"Failed password login attempt\"; flow:to_server,established; content:\"Failed password\"; threshold:type both, track by_src, count 10, seconds 60; sid:1000004;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_password_rule)
                prelude_block_password = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_password)

            elif attack_type == "ransomware":
                prelude_ransomware_rule = f"echo 'alert file {attacker_ip} any -> any any (msg:\"Ransomware detected: file encryption attempt\"; file_data; content:'.*\\.encrypted'; sid:1000005;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_ransomware_rule)
                prelude_block_ransomware = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_ransomware)

            elif attack_type == "scanning":
                prelude_scanning_rule = f"echo 'alert ip {attacker_ip} any -> any any (msg:\"Network scanning detected\"; flags:S; threshold:type both, track by_src, count 5, seconds 10; sid:1000006;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_scanning_rule)
                prelude_block_scanning = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_scanning)

            elif attack_type == "xss":
                prelude_xss_rule = f"echo 'alert tcp {attacker_ip} any -> any 80 (msg:\"XSS attack detected\"; content:\"<script>\"; sid:1000007;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_xss_rule)
                prelude_block_xss = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_xss)

            elif attack_type == "mitm":
                prelude_mitm_rule = f"echo 'alert tcp {attacker_ip} any -> any any (msg:\"MITM attack detected: certificate change\"; ssl_state:server_hello; sid:1000008;)' >> /etc/prelude/rules/prelude.rules"
                ssh_client.exec_command(prelude_mitm_rule)
                prelude_block_mitm = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(prelude_block_mitm)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")
    if "Snort" in ids_found:
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

                if attack_type == "backdoor":
                    snort_backdoor_rule = f"echo 'alert tcp {attacker_ip} any -> any 22 (msg:\"Backdoor access attempt\"; flags:S,12; threshold:type both, track by_src, count 5, seconds 60; sid:2000001;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_backdoor_rule)
                    snort_block_backdoor = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_backdoor)

                elif attack_type == "ddos":
                    snort_ddos_rule = f"echo 'alert ip {attacker_ip} any -> any any (msg:\"DDoS traffic detected\"; ip_proto:icmp; threshold:type both, track by_src, count 20, seconds 5; sid:2000002;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_ddos_rule)
                    snort_block_ddos = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_ddos)

                elif attack_type == "injection":
                    snort_injection_rule = f"echo 'alert tcp {attacker_ip} any -> any 80 (msg:\"SQL Injection attempt\"; content:\"' OR 1=1\"; nocase; sid:2000003;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_injection_rule)
                    snort_block_injection = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_injection)

                elif attack_type == "password":
                    snort_password_rule = f"echo 'alert tcp {attacker_ip} any -> any 22 (msg:\"Failed password login attempt\"; flow:to_server,established; content:\"Failed password\"; threshold:type both, track by_src, count 10, seconds 60; sid:2000004;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_password_rule)
                    snort_block_password = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_password)

                elif attack_type == "ransomware":
                    snort_ransomware_rule = f"echo 'alert file {attacker_ip} any -> any any (msg:\"Ransomware detected: file encryption attempt\"; file_data; content:'.*\\.encrypted'; sid:2000005;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_ransomware_rule)
                    snort_block_ransomware = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_ransomware)

                elif attack_type == "scanning":
                    snort_scanning_rule = f"echo 'alert ip {attacker_ip} any -> any any (msg:\"Network scanning detected\"; flags:S; threshold:type both, track by_src, count 5, seconds 10; sid:2000006;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_scanning_rule)
                    snort_block_scanning = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_scanning)

                elif attack_type == "xss":
                    snort_xss_rule = f"echo 'alert tcp {attacker_ip} any -> any 80 (msg:\"XSS attack detected\"; content:\"<script>\"; sid:2000007;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_xss_rule)
                    snort_block_xss = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_xss)

                elif attack_type == "mitm":
                    snort_mitm_rule = f"echo 'alert tcp {attacker_ip} any -> any any (msg:\"MITM attack detected: certificate change\"; ssl_state:server_hello; sid:2000008;)' >> /etc/snort/rules/snort.rules"
                    ssh_client.exec_command(snort_mitm_rule)
                    snort_block_mitm = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                    ssh_client.exec_command(snort_block_mitm)

                ssh_client.close()

            except Exception as e:
                print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")
    if "Suricata" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                suricata_backdoor_rule = f"echo 'alert tcp {attacker_ip} any -> any 22 (msg:\"Backdoor access attempt\"; flags:S,12; threshold:type both, track by_src, count 5, seconds 60; sid:3000001;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_backdoor_rule)
                suricata_block_backdoor = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_backdoor)

            elif attack_type == "ddos":
                suricata_ddos_rule = f"echo 'alert ip {attacker_ip} any -> any any (msg:\"DDoS traffic detected\"; ip_proto:icmp; threshold:type both, track by_src, count 20, seconds 5; sid:3000002;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_ddos_rule)
                suricata_block_ddos = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_ddos)

            elif attack_type == "injection":
                suricata_injection_rule = f"echo 'alert tcp {attacker_ip} any -> any 80 (msg:\"SQL Injection attempt\"; content:\"' OR 1=1\"; nocase; sid:3000003;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_injection_rule)
                suricata_block_injection = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_injection)

            elif attack_type == "password":
                suricata_password_rule = f"echo 'alert tcp {attacker_ip} any -> any 22 (msg:\"Failed password login attempt\"; flow:to_server,established; content:\"Failed password\"; threshold:type both, track by_src, count 10, seconds 60; sid:3000004;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_password_rule)
                suricata_block_password = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_password)

            elif attack_type == "ransomware":
                suricata_ransomware_rule = f"echo 'alert file {attacker_ip} any -> any any (msg:\"Ransomware detected: file encryption attempt\"; file_data; content:'.*\\.encrypted'; sid:3000005;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_ransomware_rule)
                suricata_block_ransomware = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_ransomware)

            elif attack_type == "scanning":
                suricata_scanning_rule = f"echo 'alert ip {attacker_ip} any -> any any (msg:\"Network scanning detected\"; flags:S; threshold:type both, track by_src, count 5, seconds 10; sid:3000006;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_scanning_rule)
                suricata_block_scanning = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_scanning)

            elif attack_type == "xss":
                suricata_xss_rule = f"echo 'alert tcp {attacker_ip} any -> any 80 (msg:\"XSS attack detected\"; content:\"<script>\"; sid:3000007;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_xss_rule)
                suricata_block_xss = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_xss)

            elif attack_type == "mitm":
                suricata_mitm_rule = f"echo 'alert tcp {attacker_ip} any -> any any (msg:\"MITM attack detected: certificate change\"; ssl_state:server_hello; sid:3000008;)' >> /etc/suricata/rules/suricata.rules"
                ssh_client.exec_command(suricata_mitm_rule)
                suricata_block_mitm = f"iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(suricata_block_mitm)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")


    if "OSSEC" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                ossec_backdoor_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000001\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>Backdoor attack detected from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_backdoor_rule)
            
            elif attack_type == "ddos":
                ossec_ddos_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000002\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>DDoS attack detected from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_ddos_rule)
            
            elif attack_type == "injection":
                ossec_injection_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000003\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>SQL Injection attempt from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_injection_rule)
            
            elif attack_type == "password":
                ossec_password_attack_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000004\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>Password attack detected from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_password_attack_rule)
            
            elif attack_type == "ransomware":
                ossec_ransomware_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000005\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>Ransomware detected from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_ransomware_rule)
            
            elif attack_type == "scanning":
                ossec_scanning_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000006\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>Network scanning detected from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_scanning_rule)
            
            elif attack_type == "xss":
                ossec_xss_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000007\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>XSS attack detected from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_xss_rule)
            
            elif attack_type == "mitm":
                ossec_mitm_rule = f"echo '<group name=\"syslog\">\\n  <rule id=\"1000008\" level=\"10\">\\n    <decoded_as>json</decoded_as>\\n    <description>MITM attack detected from {attacker_ip}</description>\\n  </rule>\\n</group>' > /var/ossec/etc/rules/local_rules.xml"
                ssh_client.exec_command(ossec_mitm_rule)
            
            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")

    if "Fail2Ban" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                fail2ban_backdoor_rule = f"fail2ban-client set sshd banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_backdoor_rule)

            elif attack_type == "ddos":
                fail2ban_ddos_rule = f"fail2ban-client set sshd banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_ddos_rule)

            elif attack_type == "injection":
                fail2ban_injection_rule = f"fail2ban-client set apache-badbots banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_injection_rule)

            elif attack_type == "password":
                fail2ban_password_attack_rule = f"fail2ban-client set sshd banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_password_attack_rule)

            elif attack_type == "ransomware":
                fail2ban_ransomware_rule = f"fail2ban-client set apache-badbots banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_ransomware_rule)

            elif attack_type == "scanning":
                fail2ban_scanning_rule = f"fail2ban-client set sshd banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_scanning_rule)

            elif attack_type == "xss":
                fail2ban_xss_rule = f"fail2ban-client set apache-badbots banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_xss_rule)

            elif attack_type == "mitm":
                fail2ban_mitm_rule = f"fail2ban-client set sshd banip {attacker_ip}"
                ssh_client.exec_command(fail2ban_mitm_rule)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")



    if "AIDE" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                aide_backdoor_rule = f"echo 'Attacker IP detected: {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_backdoor_rule)

            elif attack_type == "ddos":
                aide_ddos_rule = f"echo 'DDoS attack detected from {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_ddos_rule)

            elif attack_type == "injection":
                aide_injection_rule = f"echo 'Injection attempt detected from {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_injection_rule)

            elif attack_type == "password":
                aide_password_attack_rule = f"echo 'Password attack attempt from {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_password_attack_rule)

            elif attack_type == "ransomware":
                aide_ransomware_rule = f"echo 'Ransomware attempt detected from {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_ransomware_rule)

            elif attack_type == "scanning":
                aide_scanning_rule = f"echo 'Scanning attempt detected from {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_scanning_rule)

            elif attack_type == "xss":
                aide_xss_rule = f"echo 'XSS attack detected from {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_xss_rule)

            elif attack_type == "mitm":
                aide_mitm_rule = f"echo 'MITM attack detected from {attacker_ip}' >> /var/log/aide/aide.log"
                ssh_client.exec_command(aide_mitm_rule)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")


    if "Tripwire" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                tripwire_backdoor_action = f"tripwire --check --quiet && echo 'Backdoor detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(tripwire_backdoor_action)

            elif attack_type == "ddos":
                tripwire_ddos_action = f"tripwire --check --quiet && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(tripwire_ddos_action)

            elif attack_type == "injection":
                tripwire_injection_action = f"tripwire --check --quiet && echo 'Injection attempt detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(tripwire_injection_action)

            elif attack_type == "password":
                tripwire_password_attack_action = f"tripwire --check --quiet && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(tripwire_password_attack_action)

            elif attack_type == "ransomware":
                tripwire_ransomware_action = f"tripwire --check --quiet && echo 'Ransomware attempt detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(tripwire_ransomware_action)

            elif attack_type == "scanning":
                tripwire_scanning_action = f"tripwire --check --quiet && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(tripwire_scanning_action)

            elif attack_type == "xss":
                tripwire_xss_action = f"tripwire --check --quiet && echo 'XSS attack detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(tripwire_xss_action)

            elif attack_type == "mitm":
                tripwire_mitm_action = f"tripwire --check --quiet && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(tripwire_mitm_action)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")

    if "Samhain" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                samhain_backdoor_action = f"samhain --check && echo 'Backdoor detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(samhain_backdoor_action)

            elif attack_type == "ddos":
                samhain_ddos_action = f"samhain --check && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(samhain_ddos_action)

            elif attack_type == "injection":
                samhain_injection_action = f"samhain --check && echo 'Injection attempt detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(samhain_injection_action)

            elif attack_type == "password":
                samhain_password_attack_action = f"samhain --check && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(samhain_password_attack_action)

            elif attack_type == "ransomware":
                samhain_ransomware_action = f"samhain --check && echo 'Ransomware attempt detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(samhain_ransomware_action)

            elif attack_type == "scanning":
                samhain_scanning_action = f"samhain --check && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(samhain_scanning_action)

            elif attack_type == "xss":
                samhain_xss_action = f"samhain --check && echo 'XSS attack detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(samhain_xss_action)

            elif attack_type == "mitm":
                samhain_mitm_action = f"samhain --check && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(samhain_mitm_action)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")


    if "Wazuh" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                wazuh_backdoor_action = f"wazuh-control agent restart && echo 'Backdoor detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(wazuh_backdoor_action)

            elif attack_type == "ddos":
                wazuh_ddos_action = f"wazuh-control agent restart && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(wazuh_ddos_action)

            elif attack_type == "injection":
                wazuh_injection_action = f"wazuh-control agent restart && echo 'Injection attempt detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(wazuh_injection_action)

            elif attack_type == "password":
                wazuh_password_attack_action = f"wazuh-control agent restart && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(wazuh_password_attack_action)

            elif attack_type == "ransomware":
                wazuh_ransomware_action = f"wazuh-control agent restart && echo 'Ransomware attempt detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(wazuh_ransomware_action)

            elif attack_type == "scanning":
                wazuh_scanning_action = f"wazuh-control agent restart && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(wazuh_scanning_action)

            elif attack_type == "xss":
                wazuh_xss_action = f"wazuh-control agent restart && echo 'XSS attack detected, blocking IP {attacker_ip}' | tee -a /etc/hosts.deny"
                ssh_client.exec_command(wazuh_xss_action)

            elif attack_type == "mitm":
                wazuh_mitm_action = f"wazuh-control agent restart && iptables -A INPUT -s {attacker_ip} -j DROP"
                ssh_client.exec_command(wazuh_mitm_action)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")

    if "Telerik Fiddler" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                fiddler_backdoor_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_backdoor_action)

            elif attack_type == "ddos":
                fiddler_ddos_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_ddos_action)

            elif attack_type == "injection":
                fiddler_injection_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_injection_action)

            elif attack_type == "password":
                fiddler_password_attack_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_password_attack_action)

            elif attack_type == "ransomware":
                fiddler_ransomware_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_ransomware_action)

            elif attack_type == "scanning":
                fiddler_scanning_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_scanning_action)

            elif attack_type == "xss":
                fiddler_xss_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_xss_action)

            elif attack_type == "mitm":
                fiddler_mitm_action = f"fiddler --pause --block {attacker_ip}"
                ssh_client.exec_command(fiddler_mitm_action)

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")


    if "Security Onion" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                # Backdoor detected: Perform action
                securityonion_backdoor_action = f"so-sensor-manager --action block {attacker_ip}"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_backdoor_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Backdoor attack handled: {attacker_ip} blocked.")
            
            elif attack_type == "ddos":
                # DDoS detected: Take action
                securityonion_ddos_action = f"so-sensor-manager --action limit {attacker_ip} --type ddos"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_ddos_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"DDoS attack mitigated: {attacker_ip} rate-limited.")
            
            elif attack_type == "injection":
                # Injection detected: Take action
                securityonion_injection_action = f"so-sensor-manager --action block {attacker_ip} --type injection"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_injection_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Injection attack blocked: {attacker_ip} blocked.")

            elif attack_type == "password":
                # Password attack detected: Take action
                securityonion_password_attack_action = f"so-sensor-manager --action block {attacker_ip} --type password"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_password_attack_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Password attack handled: {attacker_ip} blocked.")

            elif attack_type == "ransomware":
                # Ransomware detected: Take action
                securityonion_ransomware_action = f"so-sensor-manager --action isolate {attacker_ip} --type ransomware"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_ransomware_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Ransomware attack isolated: {attacker_ip} isolated.")
            
            elif attack_type == "scanning":
                # Scanning detected: Take action
                securityonion_scanning_action = f"so-sensor-manager --action block {attacker_ip} --type scanning"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_scanning_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Scanning attack blocked: {attacker_ip} blocked.")

            elif attack_type == "xss":
                # XSS detected: Take action
                securityonion_xss_action = f"so-sensor-manager --action block {attacker_ip} --type xss"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_xss_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"XSS attack blocked: {attacker_ip} blocked.")

            elif attack_type == "mitm":
                # MITM attack detected: Take action
                securityonion_mitm_action = f"so-sensor-manager --action block {attacker_ip} --type mitm"
                stdin, stdout, stderr = ssh_client.exec_command(securityonion_mitm_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"MITM attack blocked: {attacker_ip} blocked.")

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")

    if "ClamAV" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                # Backdoor detected: Take action
                clamav_backdoor_action = f"clamscan --remove {attacker_ip}"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_backdoor_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Backdoor detected and removed for {attacker_ip}.")
            
            elif attack_type == "ddos":
                # DDoS detected: Take action
                clamav_ddos_action = f"clamscan --block {attacker_ip} --type ddos"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_ddos_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"DDoS traffic blocked from {attacker_ip}.")
            
            elif attack_type == "injection":
                # Injection detected: Take action
                clamav_injection_action = f"clamscan --remove {attacker_ip} --type injection"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_injection_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Injection attack mitigated for {attacker_ip}.")

            elif attack_type == "password":
                # Password attack detected: Take action
                clamav_password_action = f"clamscan --block {attacker_ip} --type password"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_password_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Password attack from {attacker_ip} blocked.")

            elif attack_type == "ransomware":
                # Ransomware detected: Take action
                clamav_ransomware_action = f"clamscan --quarantine {attacker_ip} --type ransomware"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_ransomware_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Ransomware isolated for {attacker_ip}.")
            
            elif attack_type == "scanning":
                # Scanning detected: Take action
                clamav_scanning_action = f"clamscan --block {attacker_ip} --type scanning"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_scanning_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Scanning detected and blocked for {attacker_ip}.")

            elif attack_type == "xss":
                # XSS detected: Take action
                clamav_xss_action = f"clamscan --block {attacker_ip} --type xss"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_xss_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"XSS attack blocked for {attacker_ip}.")

            elif attack_type == "mitm":
                # MITM attack detected: Take action
                clamav_mitm_action = f"clamscan --block {attacker_ip} --type mitm"
                stdin, stdout, stderr = ssh_client.exec_command(clamav_mitm_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"MITM attack blocked for {attacker_ip}.")

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")


    if "NAXSI" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                naxsi_backdoor_action = f"naxsi -block {attacker_ip} -type backdoor"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_backdoor_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Backdoor blocked for {attacker_ip} using NAXSI.")

            elif attack_type == "ddos":
                naxsi_ddos_action = f"naxsi -block {attacker_ip} -type ddos"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_ddos_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"DDoS traffic blocked for {attacker_ip} using NAXSI.")

            elif attack_type == "injection":
                naxsi_injection_action = f"naxsi -block {attacker_ip} -type injection"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_injection_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Injection attack blocked for {attacker_ip} using NAXSI.")

            elif attack_type == "password":
                naxsi_password_action = f"naxsi -block {attacker_ip} -type password"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_password_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Password attack blocked for {attacker_ip} using NAXSI.")

            elif attack_type == "ransomware":
                naxsi_ransomware_action = f"naxsi -quarantine {attacker_ip} -type ransomware"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_ransomware_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Ransomware isolated for {attacker_ip} using NAXSI.")

            elif attack_type == "scanning":
                naxsi_scanning_action = f"naxsi -block {attacker_ip} -type scanning"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_scanning_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Scanning activity blocked for {attacker_ip} using NAXSI.")

            elif attack_type == "xss":
                naxsi_xss_action = f"naxsi -block {attacker_ip} -type xss"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_xss_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"XSS attack blocked for {attacker_ip} using NAXSI.")

            elif attack_type == "mitm":
                naxsi_mitm_action = f"naxsi -block {attacker_ip} -type mitm"
                stdin, stdout, stderr = ssh_client.exec_command(naxsi_mitm_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"MITM attack blocked for {attacker_ip} using NAXSI.")

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")




    if "Bro/Zeek" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                bro_zeek_backdoor_action = f"zeek -s {attacker_ip} -backdoor"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_backdoor_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Backdoor attack handled for {attacker_ip} using Zeek.")

            elif attack_type == "ddos":
                bro_zeek_ddos_action = f"zeek -s {attacker_ip} -ddos"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_ddos_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"DDoS traffic handled for {attacker_ip} using Zeek.")

            elif attack_type == "injection":
                bro_zeek_injection_action = f"zeek -s {attacker_ip} -injection"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_injection_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Injection attack handled for {attacker_ip} using Zeek.")

            elif attack_type == "password":
                bro_zeek_password_action = f"zeek -s {attacker_ip} -password"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_password_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Password attack handled for {attacker_ip} using Zeek.")

            elif attack_type == "ransomware":
                bro_zeek_ransomware_action = f"zeek -s {attacker_ip} -ransomware"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_ransomware_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Ransomware handled for {attacker_ip} using Zeek.")

            elif attack_type == "scanning":
                bro_zeek_scanning_action = f"zeek -s {attacker_ip} -scanning"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_scanning_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Scanning activity handled for {attacker_ip} using Zeek.")

            elif attack_type == "xss":
                bro_zeek_xss_action = f"zeek -s {attacker_ip} -xss"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_xss_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"XSS attack handled for {attacker_ip} using Zeek.")

            elif attack_type == "mitm":
                bro_zeek_mitm_action = f"zeek -s {attacker_ip} -mitm"
                stdin, stdout, stderr = ssh_client.exec_command(bro_zeek_mitm_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"MITM attack handled for {attacker_ip} using Zeek.")

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")


    if "Snoopy" in ids_found:
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=ids_ips_user, password=ids_ips_password)

            if attack_type == "backdoor":
                snoopy_backdoor_action = f"snoopy -s {attacker_ip} --backdoor"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_backdoor_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Backdoor attack handled for {attacker_ip} using Snoopy.")

            elif attack_type == "ddos":
                snoopy_ddos_action = f"snoopy -s {attacker_ip} --ddos"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_ddos_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"DDoS traffic handled for {attacker_ip} using Snoopy.")

            elif attack_type == "injection":
                snoopy_injection_action = f"snoopy -s {attacker_ip} --injection"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_injection_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Injection attack handled for {attacker_ip} using Snoopy.")

            elif attack_type == "password":
                snoopy_password_action = f"snoopy -s {attacker_ip} --password"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_password_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Password attack handled for {attacker_ip} using Snoopy.")

            elif attack_type == "ransomware":
                snoopy_ransomware_action = f"snoopy -s {attacker_ip} --ransomware"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_ransomware_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Ransomware handled for {attacker_ip} using Snoopy.")

            elif attack_type == "scanning":
                snoopy_scanning_action = f"snoopy -s {attacker_ip} --scanning"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_scanning_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"Scanning activity handled for {attacker_ip} using Snoopy.")

            elif attack_type == "xss":
                snoopy_xss_action = f"snoopy -s {attacker_ip} --xss"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_xss_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"XSS attack handled for {attacker_ip} using Snoopy.")

            elif attack_type == "mitm":
                snoopy_mitm_action = f"snoopy -s {attacker_ip} --mitm"
                stdin, stdout, stderr = ssh_client.exec_command(snoopy_mitm_action)
                result = stdout.read().decode().strip()
                if result:
                    print(f"MITM attack handled for {attacker_ip} using Snoopy.")

            ssh_client.close()

        except Exception as e:
            print(f"Error applying rules for {attack_type} on {attacker_ip}: {e}")
    #########################################################################"
    def check_firewall_vendor(mac_address):
        for vendor, data in firewall_info.items():
            for prefix in data['mac_prefixes']:
                if mac_address.upper().startswith(prefix.upper()):
                    return data['name']
        return "Not a Firewall"

def log_to_device(ip, username_fw, password_fw, mac_address):
    firewall_type = check_firewall_vendor(mac_address)
    
    if firewall_type == "Not a Firewall":
        raise ValueError(f"No matching firewall found for MAC address: {mac_address}")
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=username_fw, password=password_fw)
    
    if firewall_type == "juniper":
        return log_to_juniper_device(client)
    elif firewall_type == "sophos":
        return log_to_sophos_device(client)
    elif firewall_type == "ibm":
        return log_to_ibm_device(client)
    elif firewall_type == "cisco":
        return log_to_cisco_device(client)
    elif firewall_type == "fortinet":
        return log_to_fortinet_device(client)
    elif firewall_type == "palo_alto":
        return log_to_palo_alto_device(client)
    elif firewall_type == "check_point":
        return log_to_check_point_device(client)
    elif firewall_type == "sonicwall":
        return log_to_sonicwall_device(client)
    else:
        raise ValueError(f"Unsupported firewall type: {firewall_type}")
# Juniper Firewall
def log_to_juniper_device(client):
    return client

def block_backdoor_juniper(client, attacker_ip):
    command = f"""
    set security address-book global address {attacker_ip} 255.255.255.255
    set security policies from-zone trust to-zone untrust policy Block_Backdoor then deny
    commit
    """
    client.exec_command(command)

# Sophos Firewall
def log_to_sophos_device(client):
    return client

def block_backdoor_sophos(client, attacker_ip):
    command = f"block ip {attacker_ip}\n"
    client.exec_command(command)

# IBM Firewall
def log_to_ibm_device(client):
    return client

def block_backdoor_ibm(client, attacker_ip):
    command = f"block ip {attacker_ip}\n"
    client.exec_command(command)

# Cisco Firewall
def log_to_cisco_device(client):
    return client

def block_backdoor_cisco(client, attacker_ip):
    command = f"access-list 100 deny ip host {attacker_ip} any\naccess-list 100 permit ip any any\n"
    client.exec_command(command)

def block_ddos_cisco(client, attacker_ip):
    command = f"access-list 101 deny ip {attacker_ip} any\naccess-list 101 permit ip any any\n"
    client.exec_command(command)

def block_dos_cisco(client, attacker_ip):
    command = f"access-list 102 deny ip {attacker_ip} any\naccess-list 102 permit ip any any\n"
    client.exec_command(command)

def block_injection_cisco(client):
    command = "access-list 103 deny tcp any any eq 80\n"
    client.exec_command(command)

def block_bruteforce_cisco(client, brute_force_ip):
    command = f"access-list 104 deny ip host {brute_force_ip} any\n"
    client.exec_command(command)

def block_ransomware_cisco(client, attacker_ip):
    command = f"access-list 105 deny ip {attacker_ip} any\naccess-list 105 permit ip any any\n"
    client.exec_command(command)

def block_scanning_cisco(client):
    command = "access-list 106 deny tcp {attacker_ip} any range 1 65535\naccess-list 106 permit ip any any\n"
    client.exec_command(command)

def block_xss_cisco(client):
    command = "access-list 107 deny tcp {attacker_ip} any eq 80\n"
    client.exec_command(command)

def block_mitm_cisco(client):
    command = "access-list 108 deny tcp {attacker_ip} any eq 80\naccess-list 108 permit tcp any any eq 443\n"
    client.exec_command(command)

# Fortinet Firewall
def log_to_fortinet_device(client):
    return client

def block_backdoor_fortinet(client, attacker_ip):
    command = f"""
    config firewall address
    edit "attacker_ip"
    set type ipmask
    set subnet {attacker_ip} 255.255.255.255
    set associated-interface any
    next
    end
    """
    client.exec_command(command)

# Palo Alto Firewall
def log_to_palo_alto_device(client):
    return client

def block_backdoor_palo_alto(client, attacker_ip):
    command = f"""
    set address "attacker_ip" ip-netmask {attacker_ip}/32
    set rulebase security rules Block_Backdoor from any to any source "attacker_ip" action deny
    commit
    """
    client.exec_command(command)

def block_ddos_palo_alto(client, attacker_ip):
    command = f"""
    set rulebase security rules Block_DDoS from any to any source {attacker_ip} action deny
    commit
    """
    client.exec_command(command)

def block_dos_palo_alto(client, attacker_ip):
    command = f"""
    set rulebase security rules Block_DoS from any to any source {attacker_ip} action deny
    commit
    """
    client.exec_command(command)

def block_injection_palo_alto(client):
    command = """
    set rulebase security rules Block_Injection from any to any application ssl-decrypt, web-browsing action deny
    commit
    """
    client.exec_command(command)

def block_bruteforce_palo_alto(client):
    command = """
    set deviceconfig system lockout-threshold 10
    set deviceconfig system lockout-time 600
    commit
    """
    client.exec_command(command)

def block_ransomware_palo_alto(client, attacker_ip):
    command = f"""
    set address "attacker_ip" ip-netmask {attacker_ip}/32
    set rulebase security rules Block_Ransomware from any to any source "attacker_ip" action deny
    commit
    """
    client.exec_command(command)

# Check Point Firewall
def log_to_check_point_device(client):
    return client

def block_backdoor_check_point(client, attacker_ip):
    command = f"""
    add network {attacker_ip} 255.255.255.255
    set policy Block_Backdoor action drop
    commit
    """
    client.exec_command(command)

def block_ddos_check_point(client, attacker_ip):
    command = f"""
    set policy Block_DDoS from any to any source {attacker_ip} action drop
    commit
    """
    client.exec_command(command)

def block_dos_check_point(client, attacker_ip):
    command = f"""
    set policy Block_DoS from any to any source {attacker_ip} action drop
    commit
    """
    client.exec_command(command)

def block_injection_check_point(client):
    command = """
    set policy Block_Injection from any to any application "web-browsing, ssl-decrypt" action drop
    commit
    """
    client.exec_command(command)

def block_bruteforce_check_point(client):
    command = """
    set lockout-threshold 10
    set lockout-time 600
    commit
    """
    client.exec_command(command)

def block_ransomware_check_point(client, attacker_ip):
    command = f"""
    add network {attacker_ip} 255.255.255.255
    set policy Block_Ransomware action drop
    commit
    """
    client.exec_command(command)

# SonicWall Firewall
def log_to_sonicwall_device(client):
    return client

def block_backdoor_sonicwall(client, attacker_ip):
    command = f"block-ip {attacker_ip}\n"
    client.exec_command(command)

def block_ddos_sonicwall(client, attacker_ip):
    command = f"block-ip {attacker_ip}\n"
    client.exec_command(command)

def block_dos_sonicwall(client, attacker_ip):
    command = f"block-ip {attacker_ip}\n"
    client.exec_command(command)

def block_injection_sonicwall(client):
    command = f"block-application ssl, http\n"
    client.exec_command(command)

def block_bruteforce_sonicwall(client):
    command = f"set login-attempts 5\nset lockout-time 600\n"
    client.exec_command(command)

def block_ransomware_sonicwall(client, attacker_ip):
    command = f"block-ip {attacker_ip}\n"
    client.exec_command(command)


#####################################################################################

def handle_attack_ids(attack_type, ip, mac_address, os_info, ids_ips_user, ids_ips_password):
    if attack_type != 'normal':
        apply_ids_ips_rules(ip, mac_address, os_info, ids_ips_user, ids_ips_password, attack_type)
    else:
        print(f"Attack type is 'normal', no action needed for {ip}")

def handle_attack_fw(client, firewall_type, attack_type, attacker_ip=None):
    attack_handlers = {
        "juniper": {
            "backdoor": block_backdoor_juniper,
        },
        "sophos": {
            "backdoor": block_backdoor_sophos,
        },
        "ibm": {
            "backdoor": block_backdoor_ibm,
        },
        "cisco": {
            "backdoor": block_backdoor_cisco,
            "ddos": block_ddos_cisco,
            "dos": block_dos_cisco,
            "injection": block_injection_cisco,
            "bruteforce": block_bruteforce_cisco,
            "ransomware": block_ransomware_cisco,
            "scanning": block_scanning_cisco,
            "xss": block_xss_cisco,
            "mitm": block_mitm_cisco,
        },
        "fortinet": {
            "backdoor": block_backdoor_fortinet,
        },
        "palo_alto": {
            "backdoor": block_backdoor_palo_alto,
            "ddos": block_ddos_palo_alto,
            "dos": block_dos_palo_alto,
            "injection": block_injection_palo_alto,
            "bruteforce": block_bruteforce_palo_alto,
            "ransomware": block_ransomware_palo_alto,
        },
        "check_point": {
            "backdoor": block_backdoor_check_point,
            "ddos": block_ddos_check_point,
            "dos": block_dos_check_point,
            "injection": block_injection_check_point,
            "bruteforce": block_bruteforce_check_point,
            "ransomware": block_ransomware_check_point,
        },
        "sonicwall": {
            "backdoor": block_backdoor_sonicwall,
            "ddos": block_ddos_sonicwall,
            "dos": block_dos_sonicwall,
            "injection": block_injection_sonicwall,
            "bruteforce": block_bruteforce_sonicwall,
            "ransomware": block_ransomware_sonicwall,
        },
    }

    if firewall_type in attack_handlers and attack_type in attack_handlers[firewall_type]:
        handler_function = attack_handlers[firewall_type][attack_type]
        
        if attacker_ip:
            handler_function(client, attacker_ip)
        else:
            handler_function(client)
    else:
        raise ValueError(f"Unsupported attack type '{attack_type}' for firewall '{firewall_type}'")


def main():
    own_ip = get_own_ip()
    own_mac = get_own_mac()
    network_range = calculate_network(own_ip)
    if not network_range:
        print("Could not determine network range.")
        return
    active_devices, nm = scan_network(network_range)
    if nm:
        print(f"Own IP: {own_ip}")
        print(f"Own MAC: {own_mac}")
        print(f"Scanning network: {network_range}")
        print("Active devices, MAC addresses, vendors, OS information, and services:")

        # Detect Linux machines
        linux_machines = detect_linux_machines(active_devices, nm)
        
        # SSH into Linux machines and check for IDS/IPS
        ssh_user = "your_ssh_user"
        ssh_password = "your_ssh_password"
        ids_ips_results = []
        
        for machine in linux_machines:
            result = check_ids_ips_via_ssh(machine['IP'], machine['MAC'], machine['OS'], ssh_user, ssh_password)
            if result:
                ids_ips_results.extend(result)

        print("IDS/IPS Tools Detected:")
        for result in ids_ips_results:
            print(result)

if __name__ == "__main__":
    main()
