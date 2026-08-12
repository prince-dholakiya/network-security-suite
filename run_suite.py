import os
import sys
import subprocess
from colorama import Fore, Style, init

init(autoreset=True)

#Use the same Python interpreter that's running this script, so it works
#correctly inside venvs and on any OS (Windows/Mac/Linux) - os.system('scanner.py')
#does NOT run Python, it tries to execute the file as a shell command and fails.
PYTHON = sys.executable

def run_script(args):
    "Run another script in this suite as a subprocess and wait for it to finish"
    try:
        subprocess.run([PYTHON] + args, check=False)
    except FileNotFoundError as e:
        print(f"{Fore.RED}[!] Could not find file: {e}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Stopped.")

def print_menu():
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}   NETWORK SECURITY ASSESSMENT SUITE")
    print(f"{Fore.CYAN}{'='*60}\n")
    print(f"{Fore.YELLOW}1. Run Vulnerability Scanner")
    print(f"{Fore.YELLOW}2. Start Network Monitor (50 packets)")
    print(f"{Fore.YELLOW}3. Start Network Monitor (Continuous)")
    print(f"{Fore.YELLOW}4. Open Dashboard")
    print(f"{Fore.YELLOW}5. Run Full Assessment (Scanner + Monitor)")
    print(f"{Fore.RED}6. Exit")
    print(f"\n{Fore.CYAN}{'='*60}")

def main():
    while True:
        print_menu()
        user_choice = input(f"\n{Fore.GREEN}Enter your choice (1-6): {Style.RESET_ALL}")

        if user_choice == '1':
            print(f"\n{Fore.CYAN}[*] Starting vulnerability scanner..")
            run_script(['scanner.py'])

        elif user_choice == '2':
            print(f"\n{Fore.CYAN}[*] Starting network monitor (50 packets)..")
            run_script(['monitor.py', '50'])

        elif user_choice == '3':
            print(f"\n{Fore.CYAN}[*] Starting continuous monitoring.. (Ctrl+C to stop)")
            run_script(['monitor.py', '0'])

        elif user_choice == '4':
            print(f"\n{Fore.CYAN}[*] Starting dashboard...")
            print(f"{Fore.GREEN}[+] Open browser to: http://localhost:5001")
            print(f"{Fore.YELLOW}[*] Press Ctrl+C in this window to stop the dashboard server.")
            run_script(['dashboard.py'])

        elif user_choice == '5':
            print(f"\n{Fore.CYAN}[*] Running full assessment...")
            print(f"\n{Fore.YELLOW}Step 1: Vulnerability Scan")
            run_script(['scanner.py'])
            print(f"\n{Fore.YELLOW}Step 2: Network Monitoring (50 packets)")
            #NOTE: uses a finite 50-packet capture here on purpose. Passing '0'
            #(continuous) would block forever and the dashboard step below
            #would never run.
            run_script(['monitor.py', '50'])
            print(f"\n{Fore.GREEN}[+] Assessment complete! Starting dashboard...")
            run_script(['dashboard.py'])

        elif user_choice == '6':
            print(f"\n{Fore.GREEN}[+] Thank you for using Network Security Suite!")
            sys.exit(0)

        else:
            print(f"\n{Fore.RED}[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Exiting..")
        sys.exit(0)
