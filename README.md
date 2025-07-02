# 🔥 PSOE - Pentesting Security & Offensive Engine

**PSOE** es una potente herramienta de escaneo de vulnerabilidades para Kali Linux que automatiza pruebas de penetración y análisis de seguridad. Diseñada para pentesters profesionales y entusiastas de la ciberseguridad.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPLv3-red)](LICENSE)
[![Kali](https://img.shields.io/badge/Kali-Linux-Compatible-brightgreen)](https://www.kali.org/)

## 🌟 Características Principales

- 🕵️ Escaneo avanzado de red y servicios
- 🔍 Detección automática de vulnerabilidades
- 🌐 Análisis completo de aplicaciones web
- 📊 Generación de informes profesionales
- 🔄 Integración con herramientas populares:
  - Nmap, OpenVAS, Nikto, Metasploit
  - Bases de datos NVD, Exploit-DB, Vulners

## 🚀 Instalación Rápida

```bash
# Clonar repositorio
git clone https://github.com/tuusuario/PSOE.git
cd PSOE

# Instalar dependencias
sudo apt update && sudo apt install nmap nikto dirb
pip install -r requirements.txt

# Configurar (opcional)
cp config/config.ini.example config/config.ini
```

## 🛠️ Uso Básico

```bash
# Escaneo rápido
python main.py -t 192.168.1.1

# Escaneo completo
python main.py -t ejemplo.com -m full -o informe

# Escaneo web
python main.py -t ejemplo.com -m web -f html
```

## 📌 Opciones Principales

| Opción       | Descripción                                  |
|--------------|--------------------------------------------|
| `-t TARGET`  | IP/Dominio objetivo (requerido)            |
| `-m MODE`    | Modo: fast, full o web                     |
| `-o OUTPUT`  | Nombre del archivo de salida               |
| `-f FORMAT`  | Formato: html o json                       |
| `--update-db`| Actualizar bases de datos antes de escanear|


## 🧩 Módulos Principales

| Módulo            | Función                                  |
|-------------------|----------------------------------------|
| Network Scanner   | Escaneo de puertos y servicios         |
| OS Detector       | Detección de sistemas operativos       |
| Web Analyzer      | Análisis de aplicaciones web           |
| Vuln Scanner      | Escaneo de vulnerabilidades            |
| Report Generator  | Generación de informes profesionales   |

## 📚 Documentación Completa

Consulta nuestra [wiki](https://github.com/tuusuario/PSOE/wiki) para:
- Guías detalladas de instalación
- Ejemplos avanzados de uso
- Configuración personalizada
- Solución de problemas

## 🤝 Contribuir

¡Contribuciones son bienvenidas! Por favor lee nuestro:
- [Código de Conducta](CODE_OF_CONDUCT.md)
- [Guía de Contribución](CONTRIBUTING.md)

## 📜 Licencia

Este proyecto está bajo licencia [GPL-3.0](LICENSE).

---

💻 **Hecho con ❤️ para la comunidad de seguridad** | 🌐 [Visita nuestro sitio web](https://tusitio.com)

