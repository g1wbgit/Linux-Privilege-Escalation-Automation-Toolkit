#!/usr/bin/env python3

import subprocess
from datetime import datetime

REPORT_FILE = "privilege_escalation_report.txt"
MAX_LINES = 40


def clean_output(output):
    lines = []

    for line in output.splitlines():
        line = line.strip()

        if line != "":
            lines.append(line)

    if len(lines) == 0:
        return "No output found."

    return "\n".join(lines)


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout

        if result.stderr:
            output += "\n" + result.stderr

        return clean_output(output)

    except subprocess.TimeoutExpired:
        return "Command timed out."

    except Exception as error:
        return "Error: " + str(error)


def save_report(results):
    with open(REPORT_FILE, "w") as file:
        file.write("Linux Privilege Escalation Audit Report\n")
        file.write("===========================================\n")
        file.write("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")

        file.write("Note:\n")
        file.write("This report is for defensive auditing. Review any unusual root services,\n")
        file.write("SUID/SGID files, cron jobs, and weak permissions.\n\n")

        for number, item in enumerate(results, start=1):
            file.write(str(number) + ". " + item["title"] + "\n")
            file.write("-----------------------------------------\n")
            file.write("What this checks:\n")
            file.write(item["meaning"] + "\n\n")
            file.write("Result:\n")
            file.write(item["output"] + "\n\n")

    print("[+] Scan complete.")
    print("[+] Report saved as: " + REPORT_FILE)


def full_scan():
    checks = [
        {
            "title": "OS and Kernel Information",
            "command": "uname -a; cat /etc/os-release 2>/dev/null; cat /etc/issue 2>/dev/null",
            "meaning": "Shows the Linux distribution and kernel version. Old versions may need security updates."
        },
        {
            "title": "Current User Information",
            "command": "id; whoami",
            "meaning": "Shows the current user and groups. Groups like sudo, wheel, docker, lxd, disk, and adm are sensitive."
        },
        {
            "title": "Root-Owned Processes",
            "command": "ps aux | grep root | grep -v grep",
            "meaning": "Shows processes running as root. Unknown root processes should be reviewed."
        },
        {
            "title": "SUID Files",
            "command": "find / -perm -4000 -type f 2>/dev/null",
            "meaning": "Shows files with SUID permission. These run with the file owner's privileges."
        },
        {
            "title": "SGID Files",
            "command": "find / -perm -2000 -type f 2>/dev/null",
            "meaning": "Shows files with SGID permission. These run with the file group's privileges."
        },
        {
            "title": "Cron Jobs",
            "command": "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null",
            "meaning": "Shows scheduled jobs. Cron jobs running as root should not call writable scripts."
        },
        {
            "title": "Running Systemd Services",
            "command": "systemctl list-units --type=service --state=running 2>/dev/null",
            "meaning": "Shows running services. Unknown or unnecessary services should be checked."
        },
        {
            "title": "World-Writable Files",
            "command": "find / -type f -perm -o+w 2>/dev/null | head -50",
            "meaning": "Shows files that any user can modify. Sensitive world-writable files are risky."
        },
        {
            "title": "Writable Directories",
            "command": "find / -writable -type d 2>/dev/null | head -50",
            "meaning": "Shows directories writable by the current user. Review directories used by root scripts or services."
        },
        {
            "title": "PATH Variable",
            "command": "echo $PATH",
            "meaning": "Shows command search paths. Writable directories in PATH can be risky."
        }
    ]

    results = []

    for check in checks:
        output = run_command(check["command"])

        results.append({
            "title": check["title"],
            "meaning": check["meaning"],
            "output": output
        })

    save_report(results)
    
def scan_interface():
    checks = [
        {
            "title": "OS and Kernel Information",
            "command": "uname -a; cat /etc/os-release 2>/dev/null; cat /etc/issue 2>/dev/null",
            "meaning": "Shows the Linux distribution and kernel version. Old versions may need security updates."
        },
        {
            "title": "Current User Information",
            "command": "id; whoami",
            "meaning": "Shows the current user and groups. Groups like sudo, wheel, docker, lxd, disk, and adm are sensitive."
        },
        {
            "title": "Root-Owned Processes",
            "command": "ps aux | grep root | grep -v grep",
            "meaning": "Shows processes running as root. Unknown root processes should be reviewed."
        },
        {
            "title": "SUID Files",
            "command": "find / -perm -4000 -type f 2>/dev/null",
            "meaning": "Shows files with SUID permission. These run with the file owner's privileges."
        },
        {
            "title": "SGID Files",
            "command": "find / -perm -2000 -type f 2>/dev/null",
            "meaning": "Shows files with SGID permission. These run with the file group's privileges."
        },
        {
            "title": "Cron Jobs",
            "command": "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null",
            "meaning": "Shows scheduled jobs. Cron jobs running as root should not call writable scripts."
        },
        {
            "title": "Running Systemd Services",
            "command": "systemctl list-units --type=service --state=running 2>/dev/null",
            "meaning": "Shows running services. Unknown or unnecessary services should be checked."
        },
        {
            "title": "World-Writable Files",
            "command": "find / -type f -perm -o+w 2>/dev/null | head -50",
            "meaning": "Shows files that any user can modify. Sensitive world-writable files are risky."
        },
        {
            "title": "Writable Directories",
            "command": "find / -writable -type d 2>/dev/null | head -50",
            "meaning": "Shows directories writable by the current user. Review directories used by root scripts or services."
        },
        {
            "title": "PATH Variable",
            "command": "echo $PATH",
            "meaning": "Shows command search paths. Writable directories in PATH can be risky."
        }
    ]

    print("""
Linux Privilege Escalation Audit Toolkit

Choose a scan option:

1) OS and Kernel Information
2) Current User Information
3) Root-Owned Processes
4) SUID Files
5) SGID Files
6) Cron Jobs
7) Running Systemd Services
8) World-Writable Files
9) Writable Directories
10) PATH Variable
11) Full Scan
12) Exit
""")

    choice = input("LPC>> ")

    if choice == "12":
        print("Exiting.")
        return

    results = []

    if choice == "11":
        selected_checks = checks
    elif choice.isdigit() and 1 <= int(choice) <= 10:
        selected_checks = [checks[int(choice) - 1]]
    else:
        print("Invalid option.")
        return

    for check in selected_checks:
        output = run_command(check["command"])

        results.append({
            "title": check["title"],
            "meaning": check["meaning"],
            "output": output
        })

    save_report(results)


scan_interface()
        if result.stderr:
            output += "\n" + result.stderr

        return clean_output(output)

    except subprocess.TimeoutExpired:
        return "Command timed out."

    except Exception as error:
        return "Error: " + str(error)


def save_report(results):
    with open(REPORT_FILE, "w") as file:
        file.write("Linux Privilege Escalation Audit Report\n")
        file.write("===========================================\n")
        file.write("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")

        file.write("Note:\n")
        file.write("This report is for defensive auditing. Review any unusual root services,\n")
        file.write("SUID/SGID files, cron jobs, and weak permissions.\n\n")

        for number, item in enumerate(results, start=1):
            file.write(str(number) + ". " + item["title"] + "\n")
            file.write("-----------------------------------------\n")
            file.write("What this checks:\n")
            file.write(item["meaning"] + "\n\n")
            file.write("Result:\n")
            file.write(item["output"] + "\n\n")

    print("[+] Scan complete.")
    print("[+] Report saved as: " + REPORT_FILE)


def full_scan():
    checks = [
        {
            "title": "OS and Kernel Information",
            "command": "uname -a; cat /etc/os-release 2>/dev/null; cat /etc/issue 2>/dev/null",
            "meaning": "Shows the Linux distribution and kernel version. Old versions may need security updates."
        },
        {
            "title": "Current User Information",
            "command": "id; whoami",
            "meaning": "Shows the current user and groups. Groups like sudo, wheel, docker, lxd, disk, and adm are sensitive."
        },
        {
            "title": "Root-Owned Processes",
            "command": "ps aux | grep root | grep -v grep",
            "meaning": "Shows processes running as root. Unknown root processes should be reviewed."
        },
        {
            "title": "SUID Files",
            "command": "find / -perm -4000 -type f 2>/dev/null",
            "meaning": "Shows files with SUID permission. These run with the file owner's privileges."
        },
        {
            "title": "SGID Files",
            "command": "find / -perm -2000 -type f 2>/dev/null",
            "meaning": "Shows files with SGID permission. These run with the file group's privileges."
        },
        {
            "title": "Cron Jobs",
            "command": "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null",
            "meaning": "Shows scheduled jobs. Cron jobs running as root should not call writable scripts."
        },
        {
            "title": "Running Systemd Services",
            "command": "systemctl list-units --type=service --state=running 2>/dev/null",
            "meaning": "Shows running services. Unknown or unnecessary services should be checked."
        },
        {
            "title": "World-Writable Files",
            "command": "find / -type f -perm -o+w 2>/dev/null | head -50",
            "meaning": "Shows files that any user can modify. Sensitive world-writable files are risky."
        },
        {
            "title": "Writable Directories",
            "command": "find / -writable -type d 2>/dev/null | head -50",
            "meaning": "Shows directories writable by the current user. Review directories used by root scripts or services."
        },
        {
            "title": "PATH Variable",
            "command": "echo $PATH",
            "meaning": "Shows command search paths. Writable directories in PATH can be risky."
        }
    ]

    results = []

    for check in checks:
        output = run_command(check["command"])

        results.append({
            "title": check["title"],
            "meaning": check["meaning"],
            "output": output
        })

    save_report(results)


full_scan()
