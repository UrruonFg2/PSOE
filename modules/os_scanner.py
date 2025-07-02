import subprocess
import re

class OSScanner:
    def __init__(self, target):
        self.target = target
    
    def scan(self):
        print(f"[*] Detecting OS on {self.target}")
        
        try:
            # Run nmap OS detection
            command = f"nmap -O {self.target}"
            result = subprocess.run(command, shell=True, check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
            
            # Parse OS detection results
            os_info = {}
            
            # Extract OS details using regex
            os_match = re.search(r'OS details: (.+)', result.stdout)
            if os_match:
                os_info['os_details'] = os_match.group(1)
            
            # Extract device type
            device_match = re.search(r'Device type: (.+)', result.stdout)
            if device_match:
                os_info['device_type'] = device_match.group(1)
            
            # Extract running services
            services = []
            service_matches = re.finditer(r'(\d+)/\w+\s+open\s+(\w+)', result.stdout)
            for match in service_matches:
                services.append({
                    'port': match.group(1),
                    'service': match.group(2)
                })
            
            os_info['services'] = services
            
            return os_info
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Error detecting OS: {e.stderr}")
            return {}
