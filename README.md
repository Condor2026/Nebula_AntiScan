![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![OSINT](https://img.shields.io/badge/OSINT-Sí-brightgreen)
![Termux](https://img.shields.io/badge/Termux-Compatible-brightgreen)
![Linux](https://img.shields.io/badge/Linux-Compatible-brightgreen)

# 🛡️ NEBULA ANTISCAN – Detector de escaneos agresivos en tiempo real

**NEBULA ANTISCAN** es una herramienta de ciberdefensa diseñada para detectar, geolocalizar y clasificar **escaneos agresivos e ilegales** dirigidos a infraestructuras críticas.  
Nace con una filosofía clara: *“Conocer al enemigo es el primer paso para defenderte”*. Por eso su diseño prioriza la transparencia, la ética y la inteligencia de amenazas.

---

## 📌 Índice

- [¿Qué hace NEBULA ANTISCAN?](#qué-hace-nebula-antiscan)
- [Características clave](#características-clave)
- [Tecnología y arquitectura](#tecnología-y-arquitectura)
- [Instalación y uso](#instalación-y-uso)
- [Modo terminal](#modo-terminal)
- [Modo web interactivo](#modo-web-interactivo)
- [Fuentes monitorizadas](#fuentes-monitorizadas)
- [Tipo de OSINT y metodología](#tipo-de-osint-y-metodología)
- [Ética, legalidad y protección de datos](#ética-legalidad-y-protección-de-datos)
- [Contribuciones y futuro](#contribuciones-y-futuro)
- [Licencia](#licencia)

---

## 🔍 ¿Qué hace NEBULA ANTISCAN?

NEBULA ANTISCAN automatiza la detección de **escaneos maliciosos** a nivel global. En lugar de revisar manualmente listas negras o logs de servidores, la herramienta:

- Descarga **más de 13 fuentes OSINT** en tiempo real.
- **Geolocaliza** cada IP con país, ASN y organización.
- **Clasifica** IPs por botnet (🔥) y grupo de ataque (🚩).
- **Muestra** los resultados en terminal con formato numerado.
- **Expone** un dashboard web cyberpunk con estadísticas y paginación.

---

## ⚙️ Características clave

- 🔁 **Rotación de User‑Agent** – evita bloqueos simulando diferentes navegadores.
- 🧠 **Paginación inteligente** – adapta la extracción a los formatos de cada fuente.
- 🔎 **Detector automático de URLs** – si una fuente cambia, busca alternativas (no aplica a listas fijas, pero está pensado para futuras extensiones).
- 📊 **Clasificación avanzada** – marca IPs con 🔥 (botnet) y 🚩 (grupo) usando feeds actualizados.
- 🔗 **Conexiones entre incidentes** – agrupa IPs por misma botnet/grupo y muestra frecuencias.
- 🌐 **Interfaz web interactiva** – gráficos de barras, filtros por período, lista de últimas IPs.
- 🖥️ **Menú terminal completo** – 6 comandos para ejecutar todas las funciones sin navegador.

---

## 🛠️ Tecnología y arquitectura

El siguiente diagrama muestra el flujo de datos desde las fuentes hasta las salidas:

![Arquitectura de NEBULA ANTISCAN](images/arquitectura.png)

*(El diagrama se encuentra en la carpeta `/images`)*

### Componentes principales

| Módulo | Descripción |
|--------|-------------|
| **Recolector** | Itera sobre las fuentes cada 30 segundos, extrae IPs y maneja formatos especiales (DShield tabulado, Spamhaus con `;`, Maltrail con comentarios). |
| **Motor de detección** | Normaliza, filtra privadas/whitelist, geolocaliza (con caché) y aplica inteligencia de grupos. |
| **Intel en segundo plano** | Actualiza feeds de botnets y grupos cada 6 horas sin interrumpir el monitor. |
| **Almacenamiento** | JSON diario, últimas IPs y caché geográfica. |
| **Salidas** | Terminal con colores y comandos (`vt`, `q`), dashboard web con Flask y auto‑refresh. |

---

## 📥 Instalación y uso

### Requisitos
- Python 3.8 o superior
- Conexión a Internet

### En Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install -r requirements.txt
git clone https://github.com/tuusuario/nebula-antiscan.git
cd nebula-antiscan
python nebula_antiscan.py
