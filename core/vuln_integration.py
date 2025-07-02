import requests
import csv
import os
import json
from core.config_loader import ConfigLoader

class VulnerabilityIntegrator:
    def __init__(self):
        self.config = ConfigLoader()
        self.nvd_api_key = self.config.get('API_KEYS', 'nvd_api_key')
        self.vulners_api_key = self.config.get('API_KEYS', 'vulners_api_key')
        self.exploit_db_path = self.config.get('TOOLS', 'exploit_db_path')
        
    def check_nvd(self, cpe, max_retries=2):
        """Consulta la NVD para una cadena CPE dada, con manejo robusto de errores y reintentos."""
        import time
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
        if self.nvd_api_key:
            headers = {'apiKey': self.nvd_api_key}
        else:
            headers = {}
        retries = 0
        while retries <= max_retries:
            try:
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 404:
                    msg = f"[NVD] No se encontraron vulnerabilidades para {cpe} (404)"
                    print(f"{msg}")
                    # Devuelve un error especial para mostrar en el reporte
                    return [{
                        'cve': {
                            'id': 'NVD-ERROR-404',
                            'descriptions': [{'value': msg}],
                            'metrics': {}
                        }
                    }]
                elif response.status_code == 429:
                    print(f"[NVD] Límite de peticiones alcanzado (429). Reintentando en 5s...")
                    time.sleep(5)
                    retries += 1
                    continue
                elif response.status_code >= 500:
                    print(f"[NVD] Error del servidor NVD ({response.status_code}). Reintentando en 5s...")
                    time.sleep(5)
                    retries += 1
                    continue
                response.raise_for_status()
                data = response.json()
                return data.get('vulnerabilities', [])
            except requests.RequestException as e:
                print(f"[-] Error al consultar NVD: {e}")
                if retries < max_retries:
                    print("[NVD] Reintentando en 5s...")
                    time.sleep(5)
                    retries += 1
                else:
                    msg = f"[NVD] Error al consultar NVD para {cpe}: {e}"
                    # Devuelve un error especial para mostrar en el reporte
                    return [{
                        'cve': {
                            'id': 'NVD-ERROR',
                            'descriptions': [{'value': msg}],
                            'metrics': {}
                        }
                    }]
        # Si sale del bucle sin éxito
        msg = f"[NVD] Error desconocido al consultar NVD para {cpe}"
        return [{
            'cve': {
                'id': 'NVD-ERROR-UNKNOWN',
                'descriptions': [{'value': msg}],
                'metrics': {}
            }
        }]

    def check_vulners(self, cpe, max_retries=2):
        """Consulta Vulners.com para una cadena CPE dada, con manejo robusto de errores y reintentos."""
        import time
        url = "https://vulners.com/api/v3/search/lucene/"
        query = f"cpe:{cpe}"
        params = {
            'query': query,
            'apiKey': self.vulners_api_key
        }
        retries = 0
        while retries <= max_retries:
            try:
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 404:
                    msg = f"[Vulners] No se encontraron vulnerabilidades para {cpe} (404)"
                    print(f"{msg}")
                    return [{
                        '_id': 'VULNERS-ERROR-404',
                        'description': msg,
                        'cvss': {'score': None},
                        '_source': {'href': None}
                    }]
                elif response.status_code == 429:
                    print(f"[Vulners] Límite de peticiones alcanzado (429). Reintentando en 5s...")
                    time.sleep(5)
                    retries += 1
                    continue
                elif response.status_code >= 500:
                    print(f"[Vulners] Error del servidor Vulners ({response.status_code}). Reintentando en 5s...")
                    time.sleep(5)
                    retries += 1
                    continue
                response.raise_for_status()
                data = response.json()
                return data.get('data', {}).get('search', [])
            except requests.RequestException as e:
                print(f"[-] Error al consultar Vulners: {e}")
                if retries < max_retries:
                    print("[Vulners] Reintentando en 5s...")
                    time.sleep(5)
                    retries += 1
                else:
                    msg = f"[Vulners] Error al consultar Vulners para {cpe}: {e}"
                    return [{
                        '_id': 'VULNERS-ERROR',
                        'description': msg,
                        'cvss': {'score': None},
                        '_source': {'href': None}
                    }]
        msg = f"[Vulners] Error desconocido al consultar Vulners para {cpe}"
        return [{
            '_id': 'VULNERS-ERROR-UNKNOWN',
            'description': msg,
            'cvss': {'score': None},
            '_source': {'href': None}
        }]

    def check_exploit_db(self, software, version):
        """Busca en la base de datos local de Exploit-DB, con manejo robusto de errores."""
        exploits = []
        try:
            exploits_file = os.path.join(self.exploit_db_path, 'files_exploits.csv')
            if not os.path.exists(exploits_file):
                msg = f"[Exploit-DB] Archivo no encontrado: {exploits_file}"
                print(msg)
                return [{
                    'id': 'EXPLOIT-DB-ERROR-NOTFOUND',
                    'description': msg,
                    'url': None
                }]
            with open(exploits_file, 'r', encoding='latin-1') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if software.lower() in row['description'].lower() and version in row['description']:
                        exploits.append({
                            'id': row['id'],
                            'description': row['description'],
                            'url': f"https://www.exploit-db.com/exploits/{row['id']}"
                        })
        except Exception as e:
            msg = f"[Exploit-DB] Error al leer Exploit-DB: {e}"
            print(msg)
            return [{
                'id': 'EXPLOIT-DB-ERROR',
                'description': msg,
                'url': None
            }]
        if not exploits:
            msg = f"[Exploit-DB] No se encontraron exploits para {software} {version}"
            print(msg)
            return [{
                'id': 'EXPLOIT-DB-NO-RESULT',
                'description': msg,
                'url': None
            }]
        return exploits

    def get_vulnerabilities(self, software, version, cpe=None):
        """Obtiene vulnerabilidades de todas las fuentes"""
        vulns = []
        
        # Consultar NVD
        if cpe:
            nvd_results = self.check_nvd(cpe)
            for vuln in nvd_results:
                vuln_data = vuln['cve']
                cvss_metrics = vuln_data.get('metrics', {})
                cvss_v3 = cvss_metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                cvss_v2 = cvss_metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {})
                
                vulns.append({
                    'source': 'NVD',
                    'id': vuln_data['id'],
                    'description': vuln_data['descriptions'][0]['value'],
                    'severity': cvss_v3.get('baseSeverity', cvss_v2.get('baseSeverity', 'N/A')),
                    'cvss': cvss_v3.get('baseScore', cvss_v2.get('baseScore', 'N/A')),
                    'url': f"https://nvd.nist.gov/vuln/detail/{vuln_data['id']}",
                    'cpe': cpe
                })
        
        # Consultar Vulners
        if cpe:
            vulners_results = self.check_vulners(cpe)
            for item in vulners_results:
                vulns.append({
                    'source': 'Vulners',
                    'id': item.get('_id'),
                    'description': item.get('description'),
                    'severity': item.get('cvss', {}).get('score'),
                    'cvss': item.get('cvss', {}).get('score'),
                    'url': item.get('_source', {}).get('href'),
                    'cpe': cpe
                })
        
        # Consultar Exploit-DB local
        exploits = self.check_exploit_db(software, version)
        for exploit in exploits:
            vulns.append({
                'source': 'Exploit-DB',
                'id': exploit['id'],
                'description': exploit['description'],
                'severity': 'N/A',
                'cvss': 'N/A',
                'url': exploit['url'],
                'cpe': cpe
            })
        
        return vulns
    
    def map_cpe(self, service_name, version):
        """Mapea un servicio a una cadena CPE y detecta si es un router."""
        router_keywords = [
            'router', 'routeros', 'openwrt', 'dd-wrt', 'mikrotik', 'tp-link', 'd-link', 'cisco', 'huawei', 'zyxel', 'netgear', 'asus', 'fritz', 'ubiquiti', 'edgeos', 'juniper', 'arris', 'alcatel', 'belkin', 'linksys', 'tenda', 'totolink', 'vodafone', 'movistar', 'livebox', 'zte', 'technicolor', 'sagemcom', 'arcadyan', 'comtrend', 'fiberhome', 'actiontec', 'motorola', 'arris', 'thomson', 'smc', 'trendnet', 'sitecom', 'teltonika', 'keenetic', 'draytek', 'edimax', 'openmesh', 'meraki', 'fortinet', 'watchguard', 'peplink', 'tp-link', 'tplink', 'routerboard'
        ]
        cpe_mappings = {
            'apache': f'cpe:2.3:a:apache:http_server:{version}',
            'nginx': f'cpe:2.3:a:nginx:nginx:{version}',
            'openssh': f'cpe:2.3:a:openbsd:openssh:{version}',
            'mysql': f'cpe:2.3:a:mysql:mysql:{version}',
            'php': f'cpe:2.3:a:php:php:{version}',
            'wordpress': f'cpe:2.3:a:wordpress:wordpress:{version}',
            'tomcat': f'cpe:2.3:a:apache:tomcat:{version}',
            # Ejemplos de routers populares
            'routeros': f'cpe:2.3:o:mikrotik:routeros:{version}',
            'openwrt': f'cpe:2.3:o:openwrt:openwrt:{version}',
            'dd-wrt': f'cpe:2.3:o:dd-wrt:dd-wrt:{version}',
            'cisco': f'cpe:2.3:o:cisco:ios:{version}',
            'tp-link': f'cpe:2.3:o:tp-link:firmware:{version}',
            'd-link': f'cpe:2.3:o:d-link:firmware:{version}',
            'huawei': f'cpe:2.3:o:huawei:firmware:{version}',
            'zyxel': f'cpe:2.3:o:zyxel:firmware:{version}',
            'netgear': f'cpe:2.3:o:netgear:firmware:{version}',
            'asus': f'cpe:2.3:o:asus:firmware:{version}',
            'fritz': f'cpe:2.3:o:avm:fritzbox_firmware:{version}',
            'ubiquiti': f'cpe:2.3:o:ubiquiti:edgeos:{version}',
            'juniper': f'cpe:2.3:o:juniper:junos:{version}',
            'arris': f'cpe:2.3:o:arris:firmware:{version}',
            'alcatel': f'cpe:2.3:o:alcatel:firmware:{version}',
            'belkin': f'cpe:2.3:o:belkin:firmware:{version}',
            'linksys': f'cpe:2.3:o:linksys:firmware:{version}',
            'tenda': f'cpe:2.3:o:tenda:firmware:{version}',
            'totolink': f'cpe:2.3:o:totolink:firmware:{version}',
            'vodafone': f'cpe:2.3:o:vodafone:firmware:{version}',
            'zte': f'cpe:2.3:o:zte:firmware:{version}',
            'technicolor': f'cpe:2.3:o:technicolor:firmware:{version}',
            'sagemcom': f'cpe:2.3:o:sagemcom:firmware:{version}',
            'arcadyan': f'cpe:2.3:o:arcadyan:firmware:{version}',
            'comtrend': f'cpe:2.3:o:comtrend:firmware:{version}',
            'fiberhome': f'cpe:2.3:o:fiberhome:firmware:{version}',
            'actiontec': f'cpe:2.3:o:actiontec:firmware:{version}',
            'motorola': f'cpe:2.3:o:motorola:firmware:{version}',
            'thomson': f'cpe:2.3:o:thomson:firmware:{version}',
            'smc': f'cpe:2.3:o:smc:firmware:{version}',
            'trendnet': f'cpe:2.3:o:trendnet:firmware:{version}',
            'sitecom': f'cpe:2.3:o:sitecom:firmware:{version}',
            'teltonika': f'cpe:2.3:o:teltonika:firmware:{version}',
            'keenetic': f'cpe:2.3:o:keenetic:firmware:{version}',
            'draytek': f'cpe:2.3:o:draytek:firmware:{version}',
            'edimax': f'cpe:2.3:o:edimax:firmware:{version}',
            'openmesh': f'cpe:2.3:o:openmesh:firmware:{version}',
            'meraki': f'cpe:2.3:o:cisco:meraki_firmware:{version}',
            'fortinet': f'cpe:2.3:o:fortinet:fortios:{version}',
            'watchguard': f'cpe:2.3:o:watchguard:fireware:{version}',
            'peplink': f'cpe:2.3:o:peplink:firmware:{version}',
            'tplink': f'cpe:2.3:o:tp-link:firmware:{version}',
            'routerboard': f'cpe:2.3:o:mikrotik:routeros:{version}'
        }
        service_lower = service_name.lower()
        for key, value in cpe_mappings.items():
            if key in service_lower:
                # Si es un router, añade una marca especial
                if key in router_keywords:
                    print(f"[!] Dispositivo identificado como router/módem: {key} (CPE: {value})")
                return value
        # Detección genérica de router si el nombre del servicio lo sugiere
        for router_kw in router_keywords:
            if router_kw in service_lower:
                print(f"[!] Dispositivo identificado como router/módem (palabra clave: {router_kw})")
                break
        # Retornar un CPE genérico si no se encuentra un mapeo específico
        return f'cpe:2.3:a:*:{service_lower}:{version}'
