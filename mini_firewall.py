import random

# Generate random ip for testing
def generate_random_ip():
    return f"192.168.1.{random.randint(0, 20)}"

# Return the corresponding action for the ip


def check_firewall_rules(ip_address, firewall_rules):
    # for rule_ip, action in firewall_rules.items():
    #     if ip_address == rule_ip:
    #         return action
    # hash lookup is faster than looping for all ip
    return firewall_rules[ip_address] if ip_address in firewall_rules else "Block"


def main():
    firewall_rules = {
        "192.168.1.1": "Allow",
        "192.168.1.4": "Allow",
        "192.168.1.9": "Allow",
        "192.168.1.13": "Allow",
        "192.168.1.16": "Allow",
        "192.168.1.19": "Allow"
    }
    # simulate the traffic for a set of ip's
    for _ in range(12):
        ip_address = generate_random_ip()
        action = check_firewall_rules(ip_address, firewall_rules)
        random_number = random.randint(0, 9999)
        print(f"IP: {ip_address}, Action: {action}, Radnom: {random_number}")


if __name__ == "__main__":
    main()
