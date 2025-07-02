import subprocess
import json
import time
from modules.net_scanner import NetworkScanner
from modules.os_scanner import OSScanner
from modules.web_scanner import WebScanner
from modules.vuln_scanner import VulnerabilityScanner
from modules.exploit_verifier import ExploitVerifier
from core.vuln_integration import VulnerabilityIntegrator
from core.config_loader import ConfigLoader

class PSEScanner:
    def __init__(self, target, scan_mode='fast'):
        self.target = target
        self.scan_mode = scan_mode
        self.config = ConfigLoader()
        self.profile = self.config.load_profile(scan_mode)
        self.vuln_integrator = VulnerabilityIntegrator()
        self.exploit_verifier = ExploitVerifier()
        
        self.results = {
            'target': target,
            'scan_mode': scan_mode,
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'network': {},
            'os': {},
            'web': {},
            'vulnerabilities': [],
            'openvas': {},
            'metasploit': []
        }
    
    def run_scan(self):
        from tqdm import tqdm
        from colorama import Fore, Style
        print(f"\n{Fore.CYAN}[*] Starting {self.scan_mode} scan on {self.target}{Style.RESET_ALL}")
        scan_steps = []
        if self.profile.getboolean('NETWORK', 'enabled', fallback=True):
            scan_steps.append('network')
        if self.profile.getboolean('OS_DETECTION', 'enabled', fallback=True):
            scan_steps.append('os')
        if self.profile.getboolean('WEB', 'enabled') and (self.scan_mode == 'web' or self.scan_mode == 'full'):
            scan_steps.append('web')
        if self.profile.getboolean('VULN_SCAN', 'enabled') and self.scan_mode == 'full':
            scan_steps.append('vuln')
        scan_steps.append('vulndb')

        with tqdm(total=len(scan_steps), desc=f'{Fore.YELLOW}Progreso del escaneo{Style.RESET_ALL}', ncols=80) as pbar:
            # Network scanning
            if 'network' in scan_steps:
                print(f"\n{Fore.BLUE}[+] Running network scan...{Style.RESET_ALL}")
                net_scanner = NetworkScanner(self.target)
                net_scanner.scan_options = self.profile.get('NETWORK', 'options', fallback='-T4 -A')
                self.results['network'] = net_scanner.scan()
                pbar.update(1)

            # OS detection
            if 'os' in scan_steps:
                print(f"\n{Fore.BLUE}[+] Running OS detection...{Style.RESET_ALL}")
                os_scanner = OSScanner(self.target)
                self.results['os'] = os_scanner.scan()
                pbar.update(1)

            # Web scanning
            if 'web' in scan_steps:
                print(f"\n{Fore.BLUE}[+] Running web application scan...{Style.RESET_ALL}")
                web_scanner = WebScanner(self.target)
                web_scanner.scan_options = self.profile.get('WEB', 'options', fallback='')
                self.results['web'] = web_scanner.scan()
                pbar.update(1)

            # Advanced vulnerability scanning
            if 'vuln' in scan_steps:
                print(f"\n{Fore.BLUE}[+] Running advanced vulnerability scan...{Style.RESET_ALL}")
                vuln_scanner = VulnerabilityScanner(self.target)
                self.results['openvas'] = vuln_scanner.run_openvas_scan()
                pbar.update(1)

                # Verify exploits for found vulnerabilities
                if self.profile.getboolean('EXPLOIT_VERIFICATION', 'enabled', fallback=True):
                    print(f"\n{Fore.MAGENTA}[+] Verifying exploits...{Style.RESET_ALL}")
                    for vuln in self.results['openvas'].get('vulnerabilities', []):
                        if vuln['cve'] != 'N/A':
                            result = self.exploit_verifier.verify_exploit(
                                vuln['cve'],
                                self.target,
                                self.results['network']['ports'][0]['port'] if self.results['network']['ports'] else 80
                            )
                            self.results['metasploit'].append(result)

            # Vulnerability database integration
            print(f"\n{Fore.YELLOW}[+] Checking for known vulnerabilities...{Style.RESET_ALL}")
            self.check_vulnerabilities()
            pbar.update(1)

        self.results['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        self.results['duration'] = time.time() - time.mktime(time.strptime(self.results['start_time'], '%Y-%m-%d %H:%M:%S'))
        return self.results
    
    def check_vulnerabilities(self):
        # Check services for vulnerabilities
        for host in self.results['network'].get('hosts', []):
            for port in host.get('ports', []):
                if port['service'] != 'unknown':
                    cpe = self.vuln_integrator.map_cpe(port['service'], port['version'] if 'version' in port else 'unknown')
                    vulns = self.vuln_integrator.get_vulnerabilities(
                        port['service'], 
                        port['version'] if 'version' in port else 'unknown', 
                        cpe
                    )
                    self.results['vulnerabilities'].extend(vulns)
        
        # Add remediation suggestions
        for vuln in self.results['vulnerabilities']:
            vuln['remediation'] = self.get_remediation_suggestion(vuln)
    
    def get_remediation_suggestion(self, vulnerability):
        """Genera sugerencias de remediación basadas en la vulnerabilidad"""
        description = vulnerability.get('description') or ''
        cpe = vulnerability.get('cpe', '')
        if 'http' in cpe or 'web' in description.lower():
            return [
                "Actualizar a la última versión del software",
                "Implementar un WAF (Web Application Firewall)",
                "Deshabilitar características innecesarias"
            ]
        elif 'remote' in description.lower():
            return [
                "Restringir el acceso a la red",
                "Implementar autenticación fuerte",
                "Aplicar parches de seguridad"
            ]
        else:
            return [
                "Aplicar actualizaciones de seguridad",
                "Seguir las mejores prácticas de configuración",
                "Monitorear registros para actividades sospechosas"
            ]
