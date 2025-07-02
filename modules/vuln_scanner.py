import subprocess
import xml.etree.ElementTree as ET
import tempfile
import os
import time
from core.config_loader import ConfigLoader

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
        self.config = ConfigLoader()
        self.openvas_path = self.config.get('TOOLS', 'openvas_path')
        self.timeout = self.config.getint('SCANNING', 'timeout')
        
    def run_openvas_scan(self):
        """Ejecuta un escaneo de OpenVAS"""
        print(f"[*] Iniciando escaneo OpenVAS en {self.target}")
        
        # Crear un archivo temporal para el informe
        with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as temp_file:
            report_file = temp_file.name
        
        try:
            # Comando para ejecutar OpenVAS (gvm-cli)
            command = [
                self.openvas_path,
                '--gmp-username', 'admin',
                '--gmp-password', 'admin',
                'socket',
                '--xml', f'<create_task><name>PSOE Scan</name><target><hosts>{self.target}</hosts></target></create_task>'
            ]
            
            # Crear tarea
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise Exception(f"Error al crear tarea: {result.stderr}")
            
            # Parsear el ID de la tarea
            root = ET.fromstring(result.stdout)
            task_id = root.find('.//task_id').text
            
            # Iniciar la tarea
            command = [
                self.openvas_path,
                '--gmp-username', 'admin',
                '--gmp-password', 'admin',
                'socket',
                '--xml', f'<start_task task_id="{task_id}"/>'
            ]
            subprocess.run(command, check=True, timeout=10)
            
            # Monitorear el progreso
            print("[*] Escaneo en progreso...")
            status = "Running"
            while status == "Running":
                time.sleep(60)
                command = [
                    self.openvas_path,
                    '--gmp-username', 'admin',
                    '--gmp-password', 'admin',
                    'socket',
                    '--xml', f'<get_tasks task_id="{task_id}"/>'
                ]
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                root = ET.fromstring(result.stdout)
                status = root.find('.//status').text
                print(f"Estado actual: {status}")
            
            # Obtener el informe
            command = [
                self.openvas_path,
                '--gmp-username', 'admin',
                '--gmp-password', 'admin',
                'socket',
                '--xml', f'<get_reports task_id="{task_id}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5"/>'
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            # Guardar informe
            with open(report_file, 'w') as f:
                f.write(result.stdout)
            
            # Parsear informe
            return self.parse_openvas_report(report_file)
            
        except Exception as e:
            print(f"[-] Error en escaneo OpenVAS: {str(e)}")
            return {}
        finally:
            if os.path.exists(report_file):
                os.remove(report_file)
    
    def parse_openvas_report(self, report_file):
        """Parsea el informe XML de OpenVAS"""
        tree = ET.parse(report_file)
        root = tree.getroot()
        
        report = {
            'host': self.target,
            'vulnerabilities': []
        }
        
        for result in root.findall('.//result'):
            nvt = result.find('nvt')
            vulnerability = {
                'name': nvt.find('name').text if nvt.find('name') is not None else 'Desconocido',
                'description': result.find('description').text if result.find('description') is not None else '',
                'severity': result.find('severity').text if result.find('severity') is not None else 'N/A',
                'cve': nvt.find('cve').text if nvt.find('cve') is not None else 'N/A',
                'solution': result.find('solution').text if result.find('solution') is not None else ''
            }
            report['vulnerabilities'].append(vulnerability)
        
        return report
