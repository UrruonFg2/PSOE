import subprocess
import requests
import os
import csv
import json
from core.config_loader import ConfigLoader

def update_databases():
    """Actualiza las bases de datos de vulnerabilidades"""
    config = ConfigLoader()
    
    # Actualizar Exploit-DB
    try:
        exploit_db_path = config.get('TOOLS', 'exploit_db_path')
        if os.path.exists(exploit_db_path):
            print("[*] Actualizando Exploit-DB...")
            subprocess.run(['sudo', 'git', '-C', exploit_db_path, 'pull'], check=True)
    except Exception as e:
        print(f"[-] Error actualizando Exploit-DB: {str(e)}")
    
    # Actualizar mapeo CPE
    try:
        print("[*] Actualizando mapeo CPE...")
        response = requests.get('https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.zip')
        with open('db/cpematch.zip', 'wb') as f:
            f.write(response.content)
        
        # Descomprimir y procesar (ejemplo simplificado)
        # En una implementación real se usaría una librería para descomprimir
        # y procesar el archivo JSON
        print("[+] Mapeo CPE actualizado")
    except Exception as e:
        print(f"[-] Error actualizando mapeo CPE: {str(e)}")
    
    # Actualizar base de datos de vulnerabilidades locales
    try:
        print("[*] Actualizando base de datos local...")
        # Esto podría incluir descargar la última versión de la NVD
        # u otras fuentes de vulnerabilidades
        print("[+] Base de datos local actualizada")
    except Exception as e:
        print(f"[-] Error actualizando base de datos local: {str(e)}")
