import os 
from random import choice
import sys
from colorama import Fore, Style, init

init(autoreset=True)

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
         choice = input(f"\n{Fore.GREEN}Enter your choice (1-6): {Style.RESET_ALL}")
         
         if choice == '1':
             print(f"\n{Fore.CYAN}[*] Starting vulnerability scanner..")
             os.system('scanner.py')
             
         elif choice == '2':
             print(f"\n{Fore.CYAN}[*] Starting network monitor (50 packets)..")
             os.system('monitor.py')  
         
         elif choice == '3':
             print(f"\n{Fore.CYAN}[*] Starting continuous monitoring..")      
             
             #modify monitor.py to accept command line argument 
             os.system('monitor.py', '0')
             
         elif choice == '4':
             print(f"\n{Fore.CYAN}[*] Starting dashboard...")
             print(f"{Fore.GREEN}[+] Open browser to: http://localhost:5001")
             os.system(' dashboard.py')
             
         elif choice == '5':
             print(f"\n{Fore.CYAN}[*] Running full assessment...")
             print(f"\n{Fore.YELLOW}Step 1: Vulnerability Scan")
             os.system(' scanner.py')
             print(f"\n{Fore.YELLOW}Step 2: Network Monitoring")
             os.system(' monitor.py')
             print(f"\n{Fore.GREEN}[+] Assessment complete! Starting dashboard...")
             os.system(' dashboard.py')
         
         elif choice == '6':
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

                
             