import subprocess
import requests
import json

class WebScanner:
    def __init__(self, target):
        self.target = target
    
    def scan(self):
        print(f"[*] Scanning web applications on {self.target}")
        
        results = {
            'nikto': self.run_nikto(),
            'dirb': self.run_dirb(),
            'headers': self.check_headers()
        }
        
        return results
    
    def run_nikto(self):
        try:
            command = f"nikto -h {self.target} -Format json -output -"
            result = subprocess.run(command, shell=True, check=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
            if not result.stdout.strip():
                print(f"[-] Nikto no devolvió salida. ¿Está instalado y soporta JSON?")
                return {}
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"[-] Nikto devolvió salida no válida para JSON:\n{result.stdout}")
                return {"raw_output": result.stdout}
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running nikto: {e.stderr}")
            return {}
    
    def run_dirb(self):
        try:
            command = f"dirb http://{self.target} -r -z 10"
            result = subprocess.run(command, shell=True, check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)
            
            # Parse dirb results
            directories = []
            for line in result.stdout.split('\n'):
                if line.startswith('+'):
                    directories.append(line.strip())
            
            return {'directories': directories}
        except subprocess.CalledProcessError as e:
            print(f"[-] Error running dirb: {e.stderr}")
            return {}
    
    def check_headers(self):
        try:
            response = requests.get(f"http://{self.target}", timeout=10)
            return dict(response.headers)
        except requests.RequestException as e:
            print(f"[-] Error checking headers: {str(e)}")
            return {}
