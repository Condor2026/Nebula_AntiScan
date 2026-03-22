# 🛡️ NEBULA ANTISCAN – Detector de escaneos agresivos en tiempo real

| Version | License | Python | OSINT | Pasivo | Analítico | Termux | Linux | macOS |
|---------|---------|--------|-------|--------|-----------|--------|-------|-------|
| 1.0     | MIT     | 3.8+   | Sí    | Sí     | Sí        | Sí     | Sí    | Sí    |

**NEBULA ANTISCAN** es una herramienta de ciberdefensa diseñada para detectar, geolocalizar y clasificar **escaneos agresivos e ilegales** dirigidos a infraestructuras críticas.  
Nace con una filosofía clara: *“Conocer al enemigo es el primer paso para defenderte”*. Por eso su diseño prioriza la transparencia, la ética y la inteligencia de amenazas.

---

## 📋 Índice

- [¿Qué hace NEBULA ANTISCAN?](#qué-hace-nebula-antiscan)
- [Características clave](#características-clave)
- [Tecnología y arquitectura](#tecnología-y-arquitectura)
- [Instalación y uso](#instalación-y-uso)
- [Modo terminal (comandos)](#modo-terminal)
- [Modo web interactivo](#modo-web-interactivo)
- [Fuentes monitorizadas](#fuentes-monitorizadas)
- [Tipo de OSINT y metodología](#tipo-de-osint-y-metodología)
- [Ética, legalidad y protección de datos](#ética-legalidad-y-protección-de-datos)
- [Contribuciones y futuro](#contribuciones-y-futuro)
- [Licencia](#licencia)

---

## ¿Qué hace NEBULA ANTISCAN?

NEBULA ANTISCAN automatiza la detección de **escaneos maliciosos** a nivel global. En lugar de revisar manualmente listas negras o logs de servidores, la herramienta:

- Descarga **más de 13 fuentes OSINT** en tiempo real.
- **Geolocaliza** cada IP con país, ASN y organización.
- **Clasifica** IPs por botnet (🔥) y grupo de ataque (🚩).
- **Muestra** los resultados en terminal con formato numerado.
- **Expone** un dashboard web cyberpunk con estadísticas y paginación.

---

## Características clave

- 🔍 **Detección en tiempo real** – ciclos cada 30 segundos.
- 🌍 **Geolocalización + ASN + organización** con caché inteligente.
- 🔥 **Inteligencia de grupos** – ThreatFox, CI Army, Feodo, Killnet, NoName, etc.
- 📊 **Dashboard web** – estadísticas, paginación (30 IPs/página), descarga JSON.
- 🤖 **Actualización silenciosa** – feeds de inteligencia cada 6 horas sin molestar.
- 📱 **Multiplataforma** – Linux, macOS, Termux (Android).
- 📦 **Código abierto** – 100% Python, fácil de modificar.

---

## Tecnología y arquitectura

El siguiente diagrama muestra el flujo de datos desde las fuentes hasta las salidas:

![Arquitectura de NEBULA ANTISCAN](images/arquitectura.png)

*(El diagrama se encuentra en la carpeta `/images`)*

---

## Instalación y uso

### Requisitos
- Python 3.8 o superior
- Conexión a Internet

### Instalación rápida

```bash
# Clonar el repositorio
git clone https://github.com/tuusuario/nebula-antiscan.git
cd nebula-antiscan

# Dar permisos al instalador
chmod +x install.sh

# Ejecutar instalador (instala dependencias)
./install.sh
