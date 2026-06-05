![Version](https://img.shields.io/badge/version-1.3-blue)
![Release](https://img.shields.io/badge/release-stable-brightgreen)
![License](https://badgen.net/badge/license/GPLv3/blue)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Termux-lightgrey)
![OSINT](https://img.shields.io/badge/OSINT-Sí-brightgreen)
![Passive](https://img.shields.io/badge/Passive-Yes-blue)
![Analytical](https://img.shields.io/badge/Analytical-Yes-blue)
![Threat Intel](https://img.shields.io/badge/Threat%20Intel-Enabled-blue)
![Botnet Detection](https://img.shields.io/badge/Botnet%20Detection-🔥-orange)
![CIDR Support](https://img.shields.io/badge/CIDR%20Support-Yes-green)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20Ready-orange)
![Dashboard](https://img.shields.io/badge/Web%20Dashboard-Cyberpunk-ff69b4)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&duration=3000&pause=500&color=00FF00&center=true&vCenter=true&width=600&lines=Condor2026+%7C+Threat+Hunter;OSINT+%7C+Purple+Team;Andr%C3%B3meda+%5BPrivado%5D;Nebula+%5BP%C3%BAblico%5D;Actividad+maliciosa+en+red" alt="Typing animation" />
</p>


**NEBULA ANTISCAN** es la demo de Andromeda.

# 🛡️ NEBULA ANTISCAN v2.0 – Detector de escaneos agresivos en tiempo real

**NEBULA ANTISCAN** es una herramienta de ciberdefensa diseñada para detectar, geolocalizar y clasificar **escaneos agresivos e ilegales** dirigidos a infraestructuras críticas.  
Nace con una filosofía clara: *“Conocer al enemigo es el primer paso para defenderte”*. Por eso su diseño prioriza la transparencia, la ética y la inteligencia de amenazas.

> **Nota importante:** NEBULA ANTISCAN detecta IPs que realizan **escaneos de puertos, bruteforce y actividades de reconocimiento**. No está diseñada para detectar ataques de denegación de servicio (DDoS), porque sus fuentes se centran en comportamientos de intrusión, no de saturación de ancho de banda.


Nebula – Demo de Detección de Amenazas (Malware, Killnet IPs, Escaneos Agresivos)
⚠️ Nebula es una demostración pública limitada de un sistema de contra-inteligencia más amplio (no publicado).
Muestra solo una fracción de las capacidades reales. No incluye el motor completo de correlación, el panel de análisis avanzado ni la inteligencia en tiempo real del sistema privado.

---

## 📌 Índice

- [✨ ¿Qué hace NEBULA ANTISCAN?](#-qué-hace-Nebula-AntiScan)
- [⚙️ Características clave](#️-características-clave)2
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

- 🔍 Descarga **73 fuentes OSINT** en tiempo real (Blocklist.de, DShield, Spamhaus, Emerging Threats, FireHOL, GreenSnow, AlienVault, CIRCL, Maltrail, etc.) y **más de 80 feeds de inteligencia**.
- 🌍 **Geolocaliza** cada IP con país, código de país, ASN y organización.
- 🔥 **Clasifica** IPs por botnet (ThreatFox, CI Army, Feodo, Spydi, MaxMind, BinaryDefense, etc.) y por grupo de ataque (Killnet, NoName057(16), DarkStorm, RootSec, Coup, Electus, BotnetKingdom...).
- 📊 **Muestra** los resultados en terminal con formato numerado, colores ANSI y comandos interactivos (`vt`, `top`, `q`).
- 🖥️ **Expone** un dashboard web cyberpunk con estadísticas, paginación, gráficos de evolución temporal, panel de contexto y descarga JSON.

---

## ⚙️ Características clave

| Característica | Descripción |
|----------------|-------------|
| 🔁 **Rotación de User‑Agent** | Simula diferentes navegadores y sistemas operativos (130 UAs únicos). |
| 🧠 **Soporte de rangos CIDR** | Detecta redes enteras (ej. `192.168.1.0/24`) además de IPs individuales. |
| 🔎 **Normalización robusta** | Adapta la extracción a cada fuente (listas planas, CSV, formato DShield, Spamhaus, etc.). |
| 📊 **Clasificación avanzada** | Marca IPs con 🔥 (botnet) y 🚩 (grupo) usando feeds actualizados cada 6 horas. |
| 🔗 **Conexiones entre incidentes** | Agrupa IPs por misma botnet o grupo y muestra frecuencias. |
| 🌐 **Interfaz web interactiva** | Gráficos de barras, panel de contexto (grupo activo, país predominante, botnet principal), filtros por fuente y descarga JSON. |
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
| **Recolector** | Itera sobre las 73 fuentes cada 30 segundos, extrae IPs y rangos CIDR, maneja formatos especiales. |
| **Motor de detección** | Normaliza, geolocaliza (con caché) y aplica inteligencia de grupos/botnets. |
| **Intel en segundo plano** | Actualiza más de 80 feeds de inteligencia cada 6 horas sin interrumpir el monitor. |
| **Almacenamiento** | JSON diario, últimas IPs y caché geográfica. |
| **Salidas** | Terminal con colores y comandos (`vt`, `top`, `q`), dashboard web con Flask y auto‑refresh. |

---

## 📊 Fuentes OSINT integradas

NEBULA ANTISCAN se alimenta de **73 fuentes activas** que reportan IPs maliciosas en tiempo real (lista completa en el código). Algunas de las más importantes:

| Categoría | Fuentes |
|-----------|---------|
| **Escáneres activos** | Blocklist.de (5 sublistas), DShield, SANS ISC, AlienVault OTX |
| **Malware y C2** | Feodo Tracker, ThreatFox, Spydi ThreatIntel (3 niveles), Malware Patrol |
| **Botnets** | FireHOL (4 niveles), GreenSnow, CI Army, CIRCL, Maltrail |
| **Spamhaus** | EDROP, DROPv6 |
| **Proxies residenciales** | MaxMind High‑Risk, IPIDEA (futuro), SocksEscort (futuro) |
| **Agregadores** | CINS Army, Ultimate IP Blacklist, IPsum, Blackbook |
| **Grupos específicos** | Killnet, NoName057(16), DarkStorm, RootSec, Coup, Electus, BotnetKingdom |

---

## 🧠 Inteligencia de amenazas

Además de las fuentes de escaneo, NEBULA ANTISCAN incorpora **más de 80 feeds de inteligencia** para clasificar IPs por botnet y grupo de ataque. Ejemplos:

| Feed | Etiqueta | Tipo |
|------|----------|------|
| ThreatFox | 🔥 ThreatFox | Botnet |
| CI Army | 🔥 CI Army | Botnet |
| Emerging Threats | 🔥 EmergingThreats | Botnet |
| FireHOL | 🔥 FireHOL | Botnet |
| GreenSnow | 🔥 GreenSnow | Botnet |
| Feodo Tracker | 🔥 Feodo/Mirai | Botnet |
| AlienVault OTX | 🔥 AlienVault | Botnet |
| DShield | 🔥 DShield | Botnet |
| Spamhaus | 🔥 Spamhaus | Botnet |
| URLhaus | 🔥 URLhaus | Botnet |
| MaxMind | 🔥 MaxMind Proxy | Botnet |
| BinaryDefense | 🔥 BinaryDefense | Botnet |
| BruteforceBlocker | 🔥 Bruteforce Blocker | Botnet |
| Spydi (Alta/Media/Baja) | 🔥 Spydi (Nivel) | Botnet |
| Killnet | 🚩 Killnet | Grupo |
| NoName057(16) | 🚩 NoName057(16) | Grupo |
| DarkStorm | 🚩 DarkStorm Team | Grupo |
| RootSec | 🚩 RootSec | Grupo |
| Coup | 🚩 Coup | Grupo |
| Electus | 🚩 Electus | Grupo |
| BotnetKingdom | 🚩 BotnetKingdom | Grupo |

Estos feeds se actualizan automáticamente cada 6 horas en segundo plano, sin interrumpir el monitor principal.

---

## 🖥️ Modo terminal

Al ejecutar NEBULA ANTISCAN, aparece un menú con **7 opciones**:

```text
1. 🚀 Iniciar monitor en tiempo real (ciclos de 30s)
2. ⚡ Ejecutar un solo ciclo de escaneo (prueba rápida)
3. 📊 Ver estadísticas globales (top países, ASN, botnets, grupos)
4. 📰 Ver últimas 50 IPs detectadas
5. 🌐 Iniciar servidor web (dashboard cyberpunk)
6. 🔗 Generar enlaces VirusTotal (con API si hay clave)
7. 🚪 Salir
```

### Monitor en tiempo real (opción 1)

- Muestra IPs cada 30 segundos con formato numerado, colores y columnas:

```text
[15:18:28] IPs obtenidas: 3267 únicas
   1. 185.130.5.123   Russia          ASN:AS201814   Some Provider   🔥ThreatFox   🚩Killnet
   2. 45.155.205.5    Netherlands     ASN:AS20495    Some VPS        🔥Spydi (Alta) 🚩-
```

- **Comandos interactivos**:
  - `vt` – genera archivo con enlaces a VirusTotal (y si hay API clave, incluye resúmenes de reputación).
  - `top` – muestra las IPs más activas históricamente.
  - `q` – sale del monitor.

---

## 🌐 Modo web interactivo

Al seleccionar la opción **5**, se levanta un servidor Flask en `http://localhost:5091`.  
El dashboard ofrece:

- 📊 **Estadísticas en vivo**: total IPs, países distintos, ASN distintos, botnets detectadas.
- 📋 **Tabla paginada**: 30 IPs por página con columnas: #, IP, País, ASN, Organización, 🔥, 🚩, 📡 Fuente, Última vez.
- 📥 **Botón de descarga JSON** para exportar todos los datos.
- 🔄 **Actualización automática** cada 30 segundos.
- 🖥️ **Diseño cyberpunk**: fondo negro, neón verde, naranja, fuentes modernas.
- 📈 **Gráfico de evolución temporal** (últimos 7 días).
- 🧠 **Panel de contexto** (grupo más activo, país predominante, botnet principal, fuente más activa).
- 🔎 **Filtros** (todas, solo con botnet, solo con grupo, por fuente origen).

---

## 🔗 Integración con VirusTotal

NEBULA ANTISCAN puede integrarse con la **API de VirusTotal** (opcional). Solo necesitas:

1. Obtener una clave gratuita en [VirusTotal](https://www.virustotal.com/gui/join-us) (500 consultas/día).
2. Editar el archivo `Nebula_AntiScan.py` y pegar tu clave en la variable `VT_API_KEY`.

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
git clone https://github.com/Condor2026/Nebula_AntiScan2
cd Nebula_AntiScan2
python Nebula_AntiScan2.py
```

### En Linux / macOS

```bash
git clone https://github.com/Condor2026/Nebula_AntiScan2
cd Nebula_AntiScan2
pip install -r requirements.txt
python Nebula_AntiScan2.py
```

### Instalación rápida con script (Linux/macOS/Termux)

```bash
chmod +x install.sh
./install.sh
python Nebula_AntiScan2.py
```

### En Linux / macOS

```bash
git clone https://github.com/Condor2026/Nebula_AntiScan
cd Nebula_AntiScan2
pip install -r requirements.txt
python Nebula_AntiScan2.py
```

> **Nota:** Si no quieres usar `git`, puedes descargar el ZIP directamente desde la página de GitHub y descomprimirlo.

---

## 📁 Estructura del proyecto

```
nebula-antiscan/
├── README.md
├── LICENSE
├── DISCLAIMER.md
├── requirements.txt
├── install.sh
├── Nebula_AntiScan2.py             # Código principal (monolítico)
└── images/
    └── arquitectura.png           # Diagrama de arquitectura
```

(El código es monolítico a propósito: facilita la portabilidad, la ejecución en Termux y las contribuciones puntuales.)

---

## ⚖️ Ética, legalidad y protección de datos

- **No se escanean redes ajenas** – NEBULA ANTISCAN solo consulta listas públicas que ya han realizado el escaneo (OSINT pasivo).
- **No se almacenan datos personales** – solo direcciones IP y metadatos técnicos (país, ASN, organización).
- **Uso legítimo** – la herramienta está diseñada para ciberseguridad defensiva, inteligencia de amenazas y educación.
- **Transparencia** – todo el código es abierto y verificable.
- Consulta el archivo `DISCLAIMER.md` para más detalles.

---

## 🤝 Contribuciones y futuro

¿Tienes ideas para mejorar NEBULA ANTISCAN? ¡Las contribuciones son bienvenidas!

- Reporta bugs en **Issues**.
- Envía pull requests con mejoras.
- Sugiere nuevas fuentes o funcionalidades.

**Próximos pasos planeados**:
- Soporte para IPv6.
- Integración con CrowdSec CTI.
- Alertas por Telegram / Correo.
- Exportación a formato STIX/TAXII.
- Base de datos local GeoLite2 para geolocalización offline.
- Más fuentes de inteligencia (IPIDEA, SocksEscort, etc.).

---

## 📄 Licencia

Este proyecto está bajo la licencia **GPL v3**. Consulta el archivo `LICENSE` para más detalles.

---

**Creado por Condor2026 – SpectrumSecurity para la comunidad de ciberseguridad.**

*¡Que los escaneos no te pillen desprevenido! 🚀*

## 💰 Apoya el proyecto

NEBULA ANTISCAN es **100% código abierto** bajo licencia **GPL v3**.
Si te es útil, considera donar para ayudar a mantenerlo y mejorarlo:

- [GitHub Sponsors](https://github.com/sponsors/Condor2026)
> ⚠️ **No uso PayPal.** No respeta la privacidad.



