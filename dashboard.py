from flask import Flask, render_template, jsonify
import json
import os
from datetime import datetime

app = Flask(__name__)

def get_latest_scan_report():
    scan_files = [f for f in os.listdir('.') if f.startswith('scan_report_')]
    
    if scan_files:
        latest = max(scan_files)
        with open(latest, 'r') as f:
            return f.read(), latest 
    return None, None

def get_latest_monitor_report():
    monitor_files = [f for f in os.listdir('.') if f.startswith('monitor_report_') and f.endswith('.json')]
    
    if monitor_files:
        latest = max(monitor_files)
        with open(latest, 'r') as f:
            return json.load(f), latest
        
    return None, None

@app.route('/')
def index():
    "Main dashboard page"
    
    #Get latest reports
    scan_content, scan_file = get_latest_scan_report()
    monitor_data, monitor_file = get_latest_monitor_report()
    
    return render_template('dashboard.html', 
                           scan_report=scan_content,
                           scan_file=scan_file,
                           monitor_data=monitor_data,
                           monitor_file=monitor_file)
    
@app.route('/api/monitor-data')
def get_monitor_data():
    "API endpoint to get monitoring data as JSON"
    monitor_data, _ = get_latest_monitor_report()
    return jsonify(monitor_data if monitor_data else {})

if __name__ == '__main__':
    print("\n" + "="*60)
    print(" NETWORK SECURITY DASHBOARD")
    print("="*60)
    print("\n[+] Starting web server..")
    print("[+] Open your browser and go to : http://localhost:5001")
    
    app.run(debug=True, host='0.0.0.0', port=5001)
        