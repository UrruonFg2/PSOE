from jinja2 import Environment, FileSystemLoader
import json
import os
from datetime import datetime
from core.config_loader import ConfigLoader

def generate_report(scan_results, output_path, format="html"):
    """Genera un informe en formato HTML o JSON"""
    config = ConfigLoader()
    
    if format not in ["html", "json"]:
        print(f"[-] Formato {format} no soportado. Usando HTML por defecto.")
        format = "html"
    
    from core.scan_db import save_scan
    report_path = None
    if format == "html":
        report_path = output_path + ".html"
        _generate_html_report(scan_results, report_path)
    elif format == "json":
        report_path = output_path + ".json"
        with open(report_path, 'w') as f:
            json.dump(scan_results, f, indent=4)
    # Guardar el escaneo en la base de datos
    save_scan(scan_results, report_path)

def _generate_html_report(scan_results, output_file):
    """Genera un informe HTML"""
    config = ConfigLoader()
    template_path = config.get('REPORTING', 'html_template', fallback='./templates/report_template.html')
    template_dir = os.path.dirname(template_path)
    template_file = os.path.basename(template_path)
    
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template(template_file)
    
    # Filtrar vulnerabilidades: solo mostrar las que tengan descripción válida (no None ni vacío)
    filtered_vulns = [
        v for v in scan_results.get('vulnerabilities', [])
        if v.get('description') not in [None, '', 'None']
    ]
    report_data = {
        'results': dict(scan_results, vulnerabilities=filtered_vulns),
        'report_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'vuln_count': len(filtered_vulns),
        'critical_count': sum(1 for v in filtered_vulns if str(v.get('severity', '')).lower() == 'critical')
    }
    
    html_report = template.render(**report_data)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_report)
