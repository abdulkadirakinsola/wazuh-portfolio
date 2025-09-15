"""
Wazuh → Huawei Firewall Integration
Active response script to automatically blacklist malicious IPs
detected by Wazuh (rule_id = 300110).
"""

from netmiko import ConnectHandler
import json

# Placeholders (replace with environment variables in production)
FIREWALL_IP = "<HUAWEI_FIREWALL_IP>"
USERNAME = "<API_USER>"
PASSWORD = "<SECRET>"

def block_ip(ip_list):
    """
    Connect to Huawei firewall and add malicious IPs
    to the Wazuh_Huawei_auto address set.
    """
    blacklist_command = ["ip address-set Wazuh_Huawei_auto"] + [
        f"address {ipaddr} mask 32" for ipaddr in ip_list
    ]

    device = {
        'device_type': 'huawei',
        'host': FIREWALL_IP,
        'username': USERNAME,
        'password': PASSWORD,
        'port': 22,
        'fast_cli': False,  # Huawei requires slower CLI interaction
    }

    conn = ConnectHandler(**device)
    response = conn.send_config_set(blacklist_command)
    print(response)

def get_ip_from_alerts(jsonfile):
    """
    Parse Wazuh alerts.json and extract malicious srcip values.
    """
    ips = set()
    with open(jsonfile, "r", encoding="utf-8") as f:
        for line in f:
            try:
                record = json.loads(line)
                if record.get("rule", {}).get("id") == "300110":
                    ips.add(record["data"].get("srcip"))
            except Exception:
                continue
    return list(ips)

# Example execution:
# block_ip(get_ip_from_alerts("/var/ossec/logs/alerts/alerts.json"))
