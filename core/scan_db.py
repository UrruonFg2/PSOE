import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'db', 'scans.db')

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            scan_mode TEXT,
            start_time TEXT,
            end_time TEXT,
            duration REAL,
            vuln_count INTEGER,
            critical_count INTEGER,
            report_path TEXT,
            raw_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(scan_results, report_path=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Filtrar vulnerabilidades reales (con descripción válida)
    filtered_vulns = [
        v for v in scan_results.get('vulnerabilities', [])
        if v.get('description') not in [None, '', 'None']
    ]
    vuln_count = len(filtered_vulns)
    critical_count = sum(1 for v in filtered_vulns if str(v.get('severity', '')).lower() == 'critical')
    c.execute('''
        INSERT INTO scans (target, scan_mode, start_time, end_time, duration, vuln_count, critical_count, report_path, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_results.get('target'),
        scan_results.get('scan_mode'),
        scan_results.get('start_time'),
        scan_results.get('end_time'),
        scan_results.get('duration'),
        vuln_count,
        critical_count,
        report_path,
        str(scan_results)
    ))
    conn.commit()
    conn.close()

def list_scans():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, target, scan_mode, start_time, end_time, vuln_count, critical_count, report_path FROM scans ORDER BY id DESC')
    rows = c.fetchall()
    conn.close()
    return rows

def get_scan(scan_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM scans WHERE id=?', (scan_id,))
    row = c.fetchone()
    conn.close()
    return row

# Inicializar la base de datos al importar
init_db()
