import sys
import os
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit, QLabel, QHBoxLayout, QMessageBox, QTextEdit
)
from core.scan_db import list_scans, get_scan

class ScanDBViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Historial de Escaneos - PSOE')
        self.resize(1000, 600)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Filtro por IP
        filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText('Filtrar por IP o dominio...')
        self.filter_btn = QPushButton('Filtrar')
        self.filter_btn.clicked.connect(self.apply_filter)
        filter_layout.addWidget(QLabel('Filtro:'))
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.filter_btn)
        self.layout.addLayout(filter_layout)

        # Tabla de escaneos
        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            'ID', 'Target', 'Modo', 'Inicio', 'Fin', 'Vulns', 'Críticas', 'Reporte'
        ])
        self.table.cellDoubleClicked.connect(self.show_details)
        self.layout.addWidget(self.table)

        # Detalles
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.layout.addWidget(self.details)

        self.load_scans()

    def load_scans(self, filter_ip=None):
        self.table.setRowCount(0)
        scans = list_scans()
        if filter_ip:
            scans = [s for s in scans if filter_ip in (s[1] or '')]
        for row_idx, s in enumerate(scans):
            self.table.insertRow(row_idx)
            for col, val in enumerate(s):
                self.table.setItem(row_idx, col, QTableWidgetItem(str(val) if val is not None else ''))

    def apply_filter(self):
        ip = self.filter_input.text().strip()
        self.load_scans(ip if ip else None)

    def show_details(self, row, col):
        scan_id = int(self.table.item(row, 0).text())
        scan = get_scan(scan_id)
        if scan:
            details = f"ID: {scan[0]}\nTarget: {scan[1]}\nModo: {scan[2]}\nInicio: {scan[3]}\nFin: {scan[4]}\nDuración: {scan[5]}\nVulns: {scan[6]}\nCríticas: {scan[7]}\nReporte: {scan[8]}\n\nJSON:\n{scan[9]}"
            self.details.setPlainText(details)
        else:
            QMessageBox.warning(self, 'No encontrado', 'No se encontró el escaneo seleccionado.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    viewer = ScanDBViewer()
    viewer.show()
    sys.exit(app.exec_())
