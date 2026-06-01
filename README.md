```markdown
![Version](https://img.shields.io/badge/version-1.0-blue)
![Release](https://img.shields.io/badge/release-stable-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Code style](https://img.shields.io/badge/code%20style-PEP8-brightgreen)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Termux-lightgrey)
![Termux](https://img.shields.io/badge/Termux-Compatible-brightgreen)
![Linux](https://img.shields.io/badge/Linux-Compatible-brightgreen)
![macOS](https://img.shields.io/badge/macOS-Compatible-brightgreen)
![OSINT](https://img.shields.io/badge/OSINT-Sí-brightgreen)
![Passive](https://img.shields.io/badge/Passive-Yes-blue)
![Analytical](https://img.shields.io/badge/Analytical-Yes-blue)
![Threat Intel](https://img.shields.io/badge/Threat%20Intel-Enabled-blue)
![Botnet Detection](https://img.shields.io/badge/Botnet%20Detection-🔥-orange)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20Ready-orange)
![Dashboard](https://img.shields.io/badge/Web%20Dashboard-Cyberpunk-ff69b4)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

# 🛡️ NEBULA ANTISCAN – Detector de escaneos agresivos en tiempo real

**NEBULA ANTISCAN** es una herramienta de ciberdefensa diseñada para detectar, geolocalizar y clasificar **escaneos agresivos e ilegales** dirigidos a infraestructuras críticas.  
Nace con una filosofía clara: *“Conocer al enemigo es el primer paso para defenderte”*. Por eso su diseño prioriza la transparencia, la ética y la inteligencia de amenazas.

> **Nota importante:** NEBULA ANTISCAN detecta IPs que realizan **escaneos de puertos, bruteforce y actividades de reconocimiento**. No está diseñada para detectar ataques de denegación de servicio (DDoS), porque sus fuentes se centran en comportamientos de intrusión, no de saturación de ancho de banda.

---

## 📌 Índice

- [✨ ¿Qué hace NEBULA ANTISCAN?](#-qué-hace-nebula-antiscan)
- [⚙️ Características clave](#️-características-clave)
- [🛠️ Tecnología y arquitectura](#️-tecnología-y-arquitectura)
- [📊 Fuentes OSINT integradas](#-fuentes-osint-integradas)
- [🧠 Inteligencia de amenazas](#-inteligencia-de-amenazas)
- [🖥️ Modo terminal](#️-modo-terminal)
- [🌐 Modo web interactivo](#-modo-web-interactivo)
- [🔗 Integración con VirusTotal](#-integración-con-virustotal)
- [📥 Instalación y uso](#-instalación-y-uso)
- [📁 Estructura del proyecto](#-estructura-del-proyecto)
- [⚖️ Ética, legalidad y protección de datos](#️-ética-legalidad-y-protección-de-datos)
- [🤝 Contribuciones y futuro](#-contribuciones-y-futuro)
- [📄 Licencia](#-licencia)

---

## ✨ ¿Qué hace NEBULA ANTISCAN?

NEBULA ANTISCAN automatiza la detección de **escaneos maliciosos** a nivel global. En lugar de revisar manualmente listas negras o logs de servidores, la herramienta:

- 🔍 Descarga **más de 13 fuentes OSINT** en tiempo real (Blocklist.de, DShield, Spamhaus, Emerging Threats, FireHOL, GreenSnow, AlienVault, CIRCL, Maltrail, etc.).
- 🌍 **Geolocaliza** cada IP con país, código de país, ASN y organización.
- 🔥 **Clasifica** IPs por botnet (ThreatFox, CI Army, Feodo, etc.) y por grupo de ataque (Killnet, NoName057(16), etc.).
- 📊 **Muestra** los resultados en terminal con formato numerado, colores ANSI y comandos interactivos (`vt`, `q`).
- 🖥️ **Expone** un dashboard web cyberpunk con estadísticas, paginación, gráficos y descarga JSON.

---

## ⚙️ Características clave

| Característica | Descripción |
|----------------|-------------|
| 🔁 **Rotación de User‑Agent** | Simula diferentes navegadores y sistemas operativos para evitar bloqueos. |
| 🧠 **Paginación inteligente** | Adapta la extracción a los formatos de cada fuente (listas planas, CSV, JSON, etc.). |
| 🔎 **Detector automático de URLs** | Si una fuente cambia de URL, busca alternativas (pensado para futuras extensiones). |
| 📊 **Clasificación avanzada** | Marca IPs con 🔥 (botnet) y 🚩 (grupo) usando feeds actualizados cada 6 horas. |
| 🔗 **Conexiones entre incidentes** | Agrupa IPs por misma botnet o grupo y muestra frecuencias. |
| 🌐 **Interfaz web interactiva** | Gráficos de barras, filtros por período, lista de últimas IPs y descarga JSON. |
| 🖥️ **Menú terminal completo** | 7 comandos para ejecutar todas las funciones sin necesidad de abrir el navegador. |
| 🔌 **API de VirusTotal (opcional)** | Si tienes clave, enriquece los resultados con reputación y detecciones. |
| 💾 **Almacenamiento local** | Todo se guarda en JSON, sin necesidad de bases de datos externas. |

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

## 📊 Fuentes OSINT integradas

NEBULA ANTISCAN se alimenta de **13 fuentes activas** que reportan IPs maliciosas en tiempo real:

| Fuente | Tipo de actividad |
|--------|-------------------|
| Blocklist.de (SSH) | Bruteforce a SSH |
| Blocklist.de (FTP) | Bruteforce a FTP |
| Blocklist.de (Bots) | Escáneres y bots |
| Blocklist.de (Mail) | Spam y ataques a mail |
| Blocklist.de (Apache) | Ataques a servidores web |
| DShield | Escáneres detectados por honeypots |
| Spamhaus EDROP | Redes maliciosas (IPs individuales) |
| Emerging Threats | IPs comprometidas |
| FireHOL Level1 | IPs maliciosas consolidadas |
| GreenSnow | Atacantes activos |
| AlienVault OTX | IPs con mala reputación |
| CIRCL OSINT | IPs de escáneres y bruteforce |
| Maltrail | IPs maliciosas de tráfico |

---

## 🧠 Inteligencia de amenazas

Además de las fuentes de escaneo, NEBULA ANTISCAN incorpora **feeds de inteligencia** para clasificar IPs por botnet y grupo de ataque:

| Feed | Etiqueta | Tipo |
|------|----------|------|
| ThreatFox | 🔥 ThreatFox | Botnet |
| CI Army | 🔥 CI Army | Botnet |
| Feodo Tracker | 🔥 Feodo | Botnet |
| GreenSnow | 🔥 GreenSnow | Botnet |
| Killnet proxies | 🚩 Killnet | Grupo |
| NoName057(16) | 🚩 NoName057(16) | Grupo |

Estos feeds se actualizan automáticamente cada 6 horas en segundo plano, sin interrumpir el monitor principal.

---

## 🖥️ Modo terminal

Al ejecutar NEBULA ANTISCAN, aparece un menú con **7 opciones**:

```
1. 🚀 Iniciar monitor en tiempo real (ciclos de 30s)
2. ⚡ Ejecutar un solo ciclo de escaneo (prueba rápida)
3. 📊 Ver estadísticas globales (top países y ASN)
4. 📰 Ver últimas 50 IPs detectadas
5. 🌐 Iniciar servidor web (dashboard cyberpunk)
6. 🔗 Generar enlaces VirusTotal (con API si hay clave)
7. 🚪 Salir
```

### Monitor en tiempo real (opción 1)

- Muestra IPs cada 30 segundos con formato numerado, colores y columnas:
  ```
  [15:18:28] IPs obtenidas: 3267 únicas
       1. 185.130.5.123     Russia          ASN:AS201814   Some Provider          🔥ThreatFox   🚩Killnet
       2. 45.155.205.5      Netherlands     ASN:AS20495    Some VPS               🔥GreenSnow   🚩-
  ```
- **Comandos interactivos**:
  - `vt` – genera archivo con enlaces a VirusTotal (y si hay API clave, incluye resúmenes de reputación).
  - `q` – sale del monitor.

---

## 🌐 Modo web interactivo

Al seleccionar la opción **5**, se levanta un servidor Flask en `http://localhost:5091`.  
El dashboard ofrece:

- 📊 **Estadísticas en vivo**: total IPs, países distintos, ASN distintos.
- 📋 **Tabla paginada**: 30 IPs por página con columnas: #, IP, País, ASN, Organización, 🔥, 🚩, Última vez.
- ⬇️ **Botón de descarga JSON** para exportar todos los datos.
- 🔄 **Actualización automática** cada 30 segundos.
- 🖥️ **Diseño cyberpunk**: fondo negro, neón verde, naranja, fuentes modernas.

---

## 🔗 Integración con VirusTotal

NEBULA ANTISCAN puede integrarse con la **API de VirusTotal** (opcional). Solo necesitas:

1. Obtener una clave gratuita en [VirusTotal](https://www.virustotal.com/gui/join-us) (500 consultas/día).
2. Editar el archivo `nebula_antiscan.py` y pegar tu clave en la variable `VT_API_KEY`.

Una vez configurada, tanto el comando `vt` durante el monitor como la opción 6 del menú generarán un archivo de enlaces **con resúmenes de reputación** (ej. `5/87 detecciones`).

Si no tienes clave, la herramienta genera solo los enlaces sin consultar la API.

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
```

### En Linux / macOS

```bash
git clone https://github.com/tuusuario/nebula-antiscan.git
cd nebula-antiscan
pip install -r requirements.txt
python nebula_antiscan.py
```

### Instalación rápida con script (Linux/macOS/Termux)

```bash
chmod +x install.sh
./install.sh
python nebula_antiscan.py
```

---

## 📁 Estructura del proyecto

```
nebula-antiscan/
├── README.md
├── LICENSE
├── SECURITY.md
├── DISCLAIMER.md
├── requirements.txt
├── install.sh
├── nebula_antiscan.py          # Código principal (monolítico, fácil de usar)
└── images/
    └── arquitectura.png         # Diagrama de arquitectura
```

*(El código es monolítico a propósito: facilita la portabilidad, la ejecución en Termux y las contribuciones puntuales.)*

---

## ⚖️ Ética, legalidad y protección de datos

- **No se escanean redes ajenas** – NEBULA ANTISCAN solo consulta listas públicas que ya han realizado el escaneo (OSINT pasivo).
- **No se almacenan datos personales** – solo direcciones IP y metadatos técnicos (país, ASN, organización).
- **Uso legítimo** – la herramienta está diseñada para ciberseguridad defensiva, inteligencia de amenazas y educación.
- **Transparencia** – todo el código es abierto y verificable.

Consulta el archivo [DISCLAIMER.md](DISCLAIMER.md) para más detalles.

---

## 🤝 Contribuciones y futuro

¿Tienes ideas para mejorar NEBULA ANTISCAN? ¡Las contribuciones son bienvenidas!

- **Reporta bugs** en Issues.
- **Envía pull requests** con mejoras.
- **Sugiere nuevas fuentes** o funcionalidades.

**Próximos pasos planeados:**
- Soporte para IPv6.
- Integración con CrowdSec CTI.
- Alertas por Telegram / Correo.
- Exportación a formato STIX/TAXII.
- Base de datos local GeoLite2 para geolocalización offline.

---

## 📄 Licencia

Este proyecto está bajo la licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

*Creado por **Condor2026 – SpectrumSecurity** para la comunidad de ciberseguridad.*

¡Que los escaneos no te pillen desprevenido! 🚀
```
