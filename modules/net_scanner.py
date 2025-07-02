import subprocess
import xml.etree.ElementTree as ET
import time

class NetworkScanner:
    def __init__(self, target):
        self.target = target
    
    def scan(self):
        print(f"[*] Scanning network on {self.target}")
        from core.config_loader import ConfigLoader
        import sys
        import itertools
        import threading
        config = ConfigLoader()
        timeout = config.getint('SCANNING', 'timeout', fallback=60)
        command = f"nmap -T5 -F -oX - {self.target}"
        spinner_flag = {'running': True}
        spinner_output = []

        def spinner():
            for c in itertools.cycle(['|', '/', '-', '\\']):
                if not spinner_flag['running']:
                    break
                sys.stdout.write(f'\r[Escaneando Nmap] {c}')
                sys.stdout.flush()
                time.sleep(0.2)
            sys.stdout.write('\r')

        try:
            spin_thread = threading.Thread(target=spinner)
            spin_thread.start()
            with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
                output_lines = []
                start_time = time.time()
                for line in proc.stdout:
                    # Solo mostrar líneas importantes, no todo el XML
                    if line.strip() and (line.startswith('Nmap scan report') or line.startswith('PORT') or 'open' in line or 'filtered' in line):
                        print(f"\r{' '*30}\r{line}", end='')
                    output_lines.append(line)
                    if timeout and (time.time() - start_time) > timeout:
                        proc.kill()
                        print(f"\n[-] Nmap superó el tiempo máximo de espera ({timeout}s) y fue abortado.")
                        spinner_flag['running'] = False
                        spin_thread.join()
                        return {'hosts': [], 'error': f'Nmap timeout tras {timeout}s'}
                proc.wait()
                spinner_flag['running'] = False
                spin_thread.join()
                nmap_output = ''.join(output_lines)
        except FileNotFoundError:
            spinner_flag['running'] = False
            print("[-] Nmap no está instalado o no se encuentra en el PATH.")
            return {'hosts': [], 'error': 'Nmap no está instalado'}

        if not nmap_output.strip():
            print("[-] Nmap no devolvió salida. ¿Está instalado y accesible?")
            return {'hosts': [], 'error': 'Nmap no devolvió salida'}

        try:
            root = ET.fromstring(nmap_output)
        except ET.ParseError as e:
            print(f"[-] Error parseando la salida XML de Nmap: {e}")
            return {'hosts': [], 'error': f'Error parseando XML: {e}', 'raw_output': nmap_output}

        scan_results = {
            'hosts': [],
            'ports': []
        }

        for host in root.findall('host'):
            address = host.find('address')
            status = host.find('status')
            host_data = {
                'ip': address.get('addr') if address is not None else 'unknown',
                'status': status.get('state') if status is not None else 'unknown',
                'ports': []
            }

            for port in host.findall('.//port'):
                port_data = {
                    'port': port.get('portid'),
                    'protocol': port.get('protocol'),
                    'state': port.find('state').get('state') if port.find('state') is not None else 'unknown',
                    'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
                }
                host_data['ports'].append(port_data)

            scan_results['hosts'].append(host_data)

        return scan_results
