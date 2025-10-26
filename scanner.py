import nmap
import socket
from datetime import datetime
from colorama import Fore, Style , init

init(autoreset=True)

def get_local_network():
    
    "Get your computer's IP address to scan the local network"
    
    hostname = socket.gethostname()
    
    #Get IP address
    local_IP = socket.gethostbyname(hostname)
    
    
    #Extract range of network
    network_parts = local_IP.split('.')
    network = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.0/24"
    
    return network, local_IP



def discover_devices(network):
    "Scans Device and finds all active devices"
    
    print(f"\n{Fore.CYAN}[*] Starting device discovery on {network}...")
    print("This may take 1-2 minutes... \n")
    
    #Create nmap scanner object
    nm = nmap.PortScanner()
    
    #Scan the network( -sn means only ping scan to find devices)
    nm.scan(hosts=network, arguments='-sn')
    
    devices = []
    
    for host in nm.all_hosts():
        #Get device information
        device_info = {
            'ip':host,
            'hostname' : nm[host].hostname() if nm[host].hostname() else 'UNKNOWN',
            'state' : nm[host].state()
        }
        
        devices.append(device_info)
        
        print(f"{Fore.GREEN}[+] Found device : {host} ({device_info['hostname']})")
    
    return devices


def scan_ports(ip, ports='21,22,23,80,443,3389,8080'):
    
    "scans a specific port on device to find open services"
    print(f"\n{Fore.CYAN}[*] Scanning port on {ip}...")
    
    nm = nmap.PortScanner()
    
    try:
        
        nm.scan(ip, ports)
        
        open_ports = []
        
        #check if host has tcp protocol scanned
        if 'tcp' in nm[ip]:
            for port in nm[ip]['tcp'].keys():
                port_info = nm[ip]['tcp'][port]
                
                #check if port is open
                if port_info['state'] == 'open':
                    service_info = {
                    'port' : port, 
                    'service' : port_info['name'],
                    'version' : port_info.get('version', 'Unknown')
                    }
                    open_ports.append(service_info)
                    print(f"{Fore.RED} [!] Port {port} OPEN - {port_info['name']}")
        
        return open_ports            
    
    except Exception as e:
        print(f"{Fore.RED}  [!] Error scanning {ip}: {str(e)}")
        return []
    

def check_vulnerabilities(device):
    "Check common vulnerability on Device"
    
    vulnerabilities = []
    
    risky_ports = {
        21 : "FTP - Unencrypted file transfer",
        23 : "TELNET - unencryoted remote access",
        3389 : "RDP - often targeted for brute force attack",
        8080 : "HTTP proxy - may expose internal service"
    }    
    
    for port_info in device['open_ports']:
        port = port_info['port']
        
        if port in risky_ports :
            vuln = {
                'severity' : 'HIGH',
                'port' : port,
                'issue' : risky_ports[port],
                'recommendation' : f'consider disable port {port} or use encrypted alternative'
            }
            vulnerabilities.append(vuln)
    
    #check for too many open ports 
    if len(device['open_ports']) > 5:
        vulnerabilities.append({
            'severity' : 'MEDIUM',
            'issue' : f'{len(device["open_ports"])} ports open',
            'recommendation' : 'review and close unnecessary ports'
        })        
    
    return vulnerabilities    


def generate_report(devices):
    "create a text report of scan results"
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = f"scan_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    
    with open(filename, 'w') as f:
        f.write("="*60 + "\n")
        f.write("NETWORK SECURITY REPORT\n")
        f.write("="*60 + "\n")
        f.write(f"Scan Date : {timestamp}\n")
        f.write(f"Total Device Scanned : {len(devices)}\n")
        f.write("="*60 +"\n\n")
        
        for device in devices :
            f.write(f"\n Device:{device['ip']}({device['hostname']})\n")
            f.write("-"*40 + "\n")
            
            #open port
            if device['open_ports']:
                f.write(f"Open Ports : \n")
                for port in device['open_ports']:
                    f.write(f" - Port {port['port']} : {port['service']}\n")    
            else :
                f.write("No Open ports detected \n")
                
            #Vulnerabilities
            vulns = check_vulnerabilities(device)
            
            if vulns:
                f.write("\nVulnerabilities Found :\n")
                for vuln in vulns:
                    f.write(f" [{vuln['severity']}][{vuln['issue']}]")
                    f.write(f" Recommendation {vuln['recommendation']}\n")
            else:
                f.write("\nNo Vulnerability Detected\n")  
            
            f.write("\n" + "="*60 + "\n")              
        
        print(f"{Fore.GREEN} [+] Report Saved to : {filename}")
        return filename


# Test the function


if __name__ == "__main__":
    network, my_ip = get_local_network()
    print(f"{Fore.YELLOW}Your IP : {my_ip}")
    print(f"{Fore.YELLOW}Scanning network : {network}") 
    
    devices = discover_devices(network)
    print(f"\n{Fore.GREEN}[+] Total device Found : {len(devices)}")
    
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"{Fore.CYAN}Starting port scan...")
    print(f"{Fore.CYAN}{'='*50}")

    for device in devices:
        open_ports = scan_ports(device['ip'])
        device['open_ports'] = open_ports
        
    generate_report(devices)
    print(f"\n{Fore.GREEN}[+] Scan complete!")    