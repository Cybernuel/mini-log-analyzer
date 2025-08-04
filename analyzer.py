import json
from colorama import Fore, Style
import os

print(Fore.CYAN + "[*] Mini Log Analyzer - Advanced Mode" + Style.RESET_ALL)

# Ask user for the log file path
log_file = input("Enter the path to the log file (JSON): ").strip()

if not os.path.exists(log_file):
    print(Fore.RED + "[!] File not found. Exiting..." + Style.RESET_ALL)
    exit()

# Load logs
with open(log_file, "r") as file:
    logs = json.load(file)

# --- Stronger Signatures ---

# 1. Suspicious processes and LOLBins
suspicious_processes = [
    "powershell.exe", "cmd.exe", "wmic.exe", "mshta.exe",
    "certutil.exe", "bitsadmin.exe", "rundll32.exe",
    "regsvr32.exe", "cscript.exe", "wscript.exe"
]


powershell_flags = ["-enc", "-nop", "-w hidden", "-command", "iex("]


rare_combos = [
    ("cmd.exe", "powershell.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe")
]


private_networks = ["192.168.", "10.", "172.16."]


print(Fore.GREEN + "[*] Starting advanced analysis..." + Style.RESET_ALL)

alert_count = 0

for log in logs:
    alert_triggered = False
    details = []

    process_name = log.get("ProcessName", "").lower()
    image_path = log.get("Image", "").lower()
    dest_ip = log.get("DestinationIp", "")
    parent_process = log.get("ParentProcess", "").lower()

    # Rule 1: Suspicious LOLBins
    if any(proc in process_name for proc in suspicious_processes):
        alert_triggered = True
        details.append(f"Suspicious process: {process_name}")

    # Rule 2: Obfuscated PowerShell
    if "powershell" in process_name and any(flag in log.get("CommandLine", "").lower() for flag in powershell_flags):
        alert_triggered = True
        details.append(f"PowerShell obfuscation detected: {log.get('CommandLine', '')[:60]}...")

    # Rule 3: Rare parent-child process combo
    if (parent_process, process_name) in rare_combos:
        alert_triggered = True
        details.append(f"Rare parent-child combo: {parent_process} -> {process_name}")

    # Rule 4: External IP Connection
    if dest_ip and not dest_ip.startswith(tuple(private_networks)):
        alert_triggered = True
        details.append(f"External IP detected: {dest_ip}")

    if alert_triggered:
        alert_count += 1
        print(Fore.RED + "[ALERT]" + Style.RESET_ALL, " | ".join(details))

print(Fore.CYAN + f"[*] Analysis complete. Total alerts: {alert_count}" + Style.RESET_ALL)
