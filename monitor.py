from scapy.all import sniff, IP, TCP, UDP, ARP
from datetime import datetime
from collections import defaultdict
import json

#store statistics
class NetworkMonitor:
    def __init__(self):
        "Initialize the monitor"
        
        self.traffic_stats = defaultdict(int) #counts packets per IP
        self.port_stats = defaultdict(int) #counts packets per port
        self.protocol_stats = defaultdict(int) #counts packets per protocol
        self.port_attempts = defaultdict(set)#Track ports tried per IP
        self.alerts = [] #List of security alerts
        self.packet_count = 0
        
    def analyze_packet(self, packet):
        "This function is called for EVERY packet captured"
        self.packet_count += 1
        
        #check if packet has IP layer
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            #Count traffic per IP
            self.traffic_stats[src_ip] += 1
            
            #Print every 10th packet 
            if self.packet_count % 10 == 0:
                print(f"[{self.packet_count}] {src_ip}-> {dst_ip}") 
                
            #Check for TCP packets
            if TCP in packet:
                self.protocol_stats['TCP'] += 1
                dst_port = packet[TCP].dport
                self.port_stats[dst_port] += 1
                
                #Detect potential port scan
                self.detect_port_scan(src_ip, dst_port)
                
            #Check for UDP packets
            elif UDP in packet:
                self.protocol_stats['UDP'] +=1
                dst_port = packet[UDP].dport
                self.port_stats[dst_port] += 1            
        
        #Check for ARP packet
        elif ARP in packet:
            self.protocol_stats['ARP'] += 1
    
    def detect_port_scan(self, src_ip, dst_port):
        "Port scan if one ip tries to many different ports"  
        #Add this port to the set of ports this IP has tried
        self.port_attempts[src_ip].add(dst_port)  
        
        if len(self.port_attempts[src_ip]) > 10:
            alert = {
                'timestamp' : datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                'type' : 'Port Scan Detected',
                'source_ip' : src_ip,
                'ports_scanned' : len(self.port_attempts[src_ip]),
                'severity' : 'high'
            }  
            
            #Only alert once per IP
            if not any(a['source_ip'] == src_ip and a['type'] == 'Port Scan Detected' for a in self.alerts):
                self.alerts.append(alert)
                print(f"\n ALERT: Possible port scan from {src_ip}!") 
                print(f"Attempted {len(self.port_attempts[src_ip])} different ports\n")
    
    def start_monitoring(self, interface=None, packet_count=100):
        """
        Start capturing 
        Interface: Network interface to monitor
        packet_count: How many packets to capture (100 for testing)
        """
        print(f"\n{'='*60}")
        print(" NETWORK MONITOR - Starting capture packet..")
        print(f"{'='*60}\n")
        
        
        try:
            #sniff() capture packets and calls analyze_packet for each one
            #iface : which network card to use
            #prn : function to call for each packet(prn = "print")
            #count : how many packets to capture (0 = infinte)
            
            sniff(iface=interface, prn=self.analyze_packet, count=packet_count)
        
        except KeyboardInterrupt:
            print("\n\n[!] Monitoring stopped by user")
        except Exception as e:
            print(f"\n[!] Error: {e}")  
        
        #show summary after stopping    
        self.show_summary()
    
    def show_summary(self):
        "Display statistics after monitoring"  
        print(f"\n{'='*60}")
        print(" MONITORING SUMMARY")
        print(f"{'='*60}\n")
        
        print(f"Total packets captured: {self.packet_count}\n")    
    
        #Show top 5 most active IPs
        print("Top 5 Most Active IPs:")
        sorted_ips = sorted(self.traffic_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_ips:
            print(f" {ip}: {count} packets") 
            
        #Show protocol distribution
        print("\nProtocol Distribution:")
        for protocol, count in self.protocol_stats.items():
            percentage = (count / self.packet_count) * 100
            print(f" {protocol}: {count} packets ({percentage:.1f}%)")               
        
        #Show top ports
        print("\nTop 5 Destination Ports:")
        sorted_ports = sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:50]
        for port, count in sorted_ports:
            print(f" Port {port}: {count} packets")
            
        #Show alerts
        if self.alerts:
            print(f"\n SECURITY ALERTS ({len(self.alerts)}):")
            for alert in self.alerts:
                print(f" [{alert['severity']}] {alert['type']}")
                print(f"  {alert['source_ip']} at {alert['timestamp']}") 
                
        self.save_results()           
    
    def save_results(self):
        timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
        filename = f"monitor_report_{timestamp}.json"
        
        #data for JSON
        results = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_packets': self.packet_count,
            'traffic_stats': dict(self.traffic_stats),
            'protocol_stats': dict(self.protocol_stats),
            'port_stats': {str(k): v for k, v in self.port_stats.items()},
            'alerts': self.alerts,
            'suspicious': sorted(self.traffic_stats.items(), key=lambda x : x[1], reverse=True)[:10]
        }     
        
        #Write to JSON file
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Results saved to: {filename}")
        
        if self.alerts:
            print(f"\n {len(self.alerts)} SECURITY ALERTS detected!")
            for alert in self.alerts:
                print(f" [{alert['severity']}] {alert['type']}")
                print(f"  From : {alert['source_ip']} at {alert['timestamp']}")      
        
#Test the Monitor
if __name__ == "__main__":
    monitor = NetworkMonitor()      
    
    #Capture 50 packets for testing (change to 0 for continuous monitoring)
    monitor.start_monitoring(packet_count=0)     
        