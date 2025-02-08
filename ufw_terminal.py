import subprocess
import argparse


# Command-line arguments

parser = argparse.ArgumentParser(description="UFW Firewall Manager")
parser.add_argument(
    "--exec", action="store_true", help="Execute commands instead of just printing them"
)
args = parser.parse_args()


def run_command(command: str, raise_error: bool = True, echo_true: bool = True) -> int:
    """Prints or executes the command based on the selected mode."""
    command = f"{'echo "y" | ' if echo_true else ''}{command}"
    if args.exec:
        try:
            result = subprocess.run(
                command, shell=True, check=True, text=True, capture_output=True
            )
            print(result.stdout.strip())
            return result.returncode
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.stderr}")
            if raise_error:
                raise e
    else:
        print(f"[SIMULATION MODE] {command}")
        return 0


def show_status():
    """Displays the UFW status."""
    run_command("sudo ufw status verbose")

def show_status_numbered():
    """Displays the UFW status numbered."""
    run_command("sudo ufw status numbered")

def enable_ufw():
    """Enables UFW."""
    run_command("sudo ufw enable")


def disable_ufw():
    """Disables UFW."""
    run_command("sudo ufw disable")


def choose_option(options: list, prompt: str):
    """Helper function for selecting a numeric option."""
    while True:
        print(prompt)
        for idx, option in enumerate(options, start=1):
            print(f"{idx}. {option}")
        choice = input("Select an option: ")
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        print("Invalid selection, please try again.")


def add_rule():
    """Adds a firewall rule to UFW."""
    port = input("Enter the port number or range (e.g., 7000 or 6000:6010): ")
    protocol = choose_option(["tcp", "udp", "all"], "Select the protocol:")
    ip_version = choose_option(["ipv4", "ipv6", "all"], "Select the IP version:")
    rule_command = (
        f"sudo ufw allow {port}/{protocol}"
        if protocol != "all"
        else f"sudo ufw allow {port}"
    )
    if ip_version == "ipv4":
        rule_command += " proto v4"
    elif ip_version == "ipv6":
        rule_command += " proto v6"
    run_command(rule_command)
    print(f"Rule added for port {port}/{protocol} ({ip_version}).")


def remove_rule():
    """Removes a rule by its rule number."""
    show_status_numbered()
    rule_number = input("\nEnter the rule number to delete: ")
    if not rule_number.isdigit():
        print("Invalid rule number!")
        return
    command = f"sudo ufw delete {rule_number}"
    run_command(command)
    print(f"Rule number {rule_number} has been deleted.")


def block_ip():
    """Blocks a single IP address, range, or subnet."""
    ip_input = input(
        "Enter an IP address, range (e.g., 192.168.1.10-192.168.1.20), or subnet (e.g., 192.168.1.0/24): "
    )
    direction = choose_option(
        ["IN (incoming)", "OUT (outgoing)"], "Select the block direction:"
    )
    direction = "in" if direction.startswith("IN") else "out"
    ip_version = choose_option(["ipv4", "ipv6", "all"], "Select the IP version:")
    block_command = (
        f"sudo ufw deny from {ip_input} to any"
        if direction == "in"
        else f"sudo ufw deny out from any to {ip_input}"
    )
    if ip_version == "ipv4":
        block_command += " proto v4"
    elif ip_version == "ipv6":
        block_command += " proto v6"
    run_command(block_command)
    print(f"Blocked {direction.upper()} traffic from: {ip_input} ({ip_version}).")


def set_default_policy():
    """Allows the user to modify only one default policy (IN, OUT, ROUTED) at a time."""
    policy_types = {
        "incoming": "Incoming traffic (IN)",
        "outgoing": "Outgoing traffic (OUT)",
        "routed": "Routed traffic (ROUTED)",
    }
    direction = choose_option(
        list(policy_types.keys()), "Select the traffic type to modify:"
    )
    policy = choose_option(
        ["allow", "deny"], f"Set policy for {policy_types[direction]}:"
    )
    run_command(f"sudo ufw default {policy} {direction}")
    print(f"Default policy set: {policy.upper()} for {policy_types[direction]}.")


def main():
    while True:
        print("\n=== UFW Firewall Manager ===")
        print("1. Add a rule")
        print("2. Remove a rule by number")
        print("3. Show UFW status")
        print("4. Enable UFW")
        print("5. Disable UFW")
        print("6. Block an IP address / range / subnet")
        print("7. Modify default policy (IN/OUT/ROUTED)")
        print("8. Exit")
        choice = input("Select an option (1-8): ")
        if choice == "1":
            add_rule()
        elif choice == "2":
            remove_rule()
        elif choice == "3":
            show_status()
        elif choice == "4":
            enable_ufw()
        elif choice == "5":
            disable_ufw()
        elif choice == "6":
            block_ip()
        elif choice == "7":
            set_default_policy()
        elif choice == "8":
            print("Exiting program...")

            break
        else:
            print("Invalid selection. Please try again.")


if __name__ == "__main__":
    main()
