#!/usr/bin/env python3

import argparse
import time
import os
from core.scan_db import list_scans, get_scan
from core.scanner import PSEScanner
from core.reporter import generate_report
from core.config_loader import ConfigLoader
from core.db_manager import update_databases
from colorama import init, Fore, Style

# Nuevo banner con colores ANSI directos para mejor visualización en terminal
banner = """
\033[36m
   ____   ____   ____   ____   
  / __ \ / __ \ / __ \ / __ \  
 / /_/ // /_/ // /_/ // /_/ /  
/ ____// ____// ____// ____/   
/_/    /_/    /_/    /_/       
\033[0m

\033[32m   (\_/)
   ( •_•)   Pentesting Security & Offensive Engine
  / >🍪   by URRUON\033[0m

\033[35m██████╗ ███████╗ ██████╗ ███████╗\033[0m
\033[35m██╔══██╗██╔════╝██╔════╝ ██╔════╝\033[0m
\033[35m██████╔╝█████╗  ██║  ███╗█████╗  \033[0m
\033[35m██╔═══╝ ██╔══╝  ██║   ██║██╔══╝  \033[0m
\033[35m██║     ███████╗╚██████╔╝███████╗\033[0m
\033[35m╚═╝     ╚══════╝ ╚═════╝ ╚══════╝\033[0m
"""

def main():
    init(autoreset=True)
    print(banner)

    config = ConfigLoader()

    parser = argparse.ArgumentParser(
        description='PSOE - Pentesting Security & Offensive Engine',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--target', required=False, help='Target IP or domain')
    parser.add_argument(
        '-m', '--mode',
        choices=['fast', 'full', 'web', 'router'],
        default='fast',
        help='Scanning mode:\n'
             '  fast: Escaneo básico de red y servicios\n'
             '  full: Escaneo completo con análisis de vulnerabilidades\n'
             '  web : Escaneo enfocado en aplicaciones web\n'
             '  router: Escaneo especial para routers'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file for report (without extension)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['html', 'pdf', 'json'],
        default='html',
        help='Report format:\n'
             '  html: Informe HTML interactivo (predeterminado)\n'
             '  pdf : Informe en formato PDF\n'
             '  json: Datos en bruto en formato JSON'
    )
    parser.add_argument(
        '--update-db',
        action='store_true',
        help='Actualizar bases de datos de vulnerabilidades antes de escanear'
    )
    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='Listar perfiles de escaneo disponibles'
    )
    parser.add_argument(
        '--list-scans',
        action='store_true',
        help='Listar todos los escaneos guardados en la base de datos'
    )
    parser.add_argument(
        '--show-scan',
        type=int,
        help='Mostrar detalles de un escaneo por ID'
    )
    parser.add_argument(
        '--filter-ip',
        type=str,
        help='Filtrar escaneos por dirección IP o dominio objetivo'
    )
    parser.add_argument(
        '--self-update',
        action='store_true',
        help='Actualizar automáticamente la herramienta desde el repositorio (sin tocar la base de datos)'
    )

    args = parser.parse_args()

    # Autoactualización del código fuente (sin tocar la base de datos)
    if args.self_update:
        from core.self_update import self_update
        self_update()
        exit(0)
    
    # Actualizar bases de datos si se solicita y salir
    if args.update_db:
        print(f"\n{Fore.YELLOW}[+] Actualizando bases de datos de vulnerabilidades...{Style.RESET_ALL}")
        update_databases()
        config.record_update()
        print(f"{Fore.GREEN}[+] Bases de datos actualizadas correctamente.{Style.RESET_ALL}")
        return
    # Si no se solicita explícitamente, pero el sistema recomienda actualizar
    if config.should_update_databases():
        print(f"\n{Fore.YELLOW}[+] Actualizando bases de datos de vulnerabilidades...{Style.RESET_ALL}")
        update_databases()
        config.record_update()
    
    # Listar escaneos guardados
    if args.list_scans:
        scans = list_scans()
        if args.filter_ip:
            scans = [s for s in scans if args.filter_ip in (s[1] or '')]
        print("\nID | Target        | Mode | Start Time           | End Time             | Vulns | Critical | Report")
        print("-"*90)
        for s in scans:
            # Evitar error de formato con None
            s_fmt = [(str(x) if x is not None else '') for x in s[:8]]
            print(f"{s_fmt[0]:<3}| {s_fmt[1]:<13}| {s_fmt[2]:<5}| {s_fmt[3]:<20}| {s_fmt[4]:<20}| {s_fmt[5]:<5}| {s_fmt[6]:<8}| {s_fmt[7]}")
        return

    # Mostrar detalles de un escaneo por ID
    if args.show_scan:
        row = get_scan(args.show_scan)
        if not row:
            print(f"No se encontró el escaneo con ID {args.show_scan}")
            exit(1)
        print(f"\nID: {row[0]}\nTarget: {row[1]}\nMode: {row[2]}\nStart: {row[3]}\nEnd: {row[4]}\nDuration: {row[5]}\nVulns: {row[6]}\nCritical: {row[7]}\nReport: {row[8]}\nRaw JSON:\n{row[9]}")
        exit(0)

    # Listar perfiles si se solicita
    if args.list_profiles:
        print(f"\n{Fore.CYAN}Perfiles de escaneo disponibles:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}fast{Style.RESET_ALL}: Escaneo rápido (red y servicios básicos)")
        print(f"  {Fore.GREEN}full{Style.RESET_ALL}: Escaneo completo (todas las funcionalidades)")
        print(f"  {Fore.GREEN}web{Style.RESET_ALL} : Escaneo de aplicaciones web")
        return
    
    # Ejecutar escaneo
    scanner = PSEScanner(target=args.target, scan_mode=args.mode)
    results = scanner.run_scan()
    
    # Generar informe
    output_dir = config.get('REPORTING', 'output_dir', fallback='./outputs')
    os.makedirs(output_dir, exist_ok=True)
    
    if args.output:
        output_path = os.path.join(output_dir, args.output)
    else:
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        output_path = os.path.join(output_dir, f"psoe_scan_{args.target}_{timestamp}")
    
    generate_report(results, output_path, args.format)
    
    print(f"\n{Fore.GREEN}[+] Escaneo completado en {results['duration']:.2f} segundos{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] Reporte generado: {output_path}.{args.format}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
