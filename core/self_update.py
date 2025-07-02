import subprocess
import os

def self_update():
    print("[+] Actualizando el código fuente desde el repositorio remoto...")
    try:
        # Solo actualiza el código fuente, no la carpeta db/
        subprocess.check_call(['git', 'pull', '--rebase'])
        print("[OK] Actualización completada. Reinicia la herramienta para aplicar los cambios.")
    except Exception as e:
        print(f"[ERROR] No se pudo actualizar automáticamente: {e}")
