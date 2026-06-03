# Roadmap

🚀 NEBULA ANTISCAN 

## 📌 Visión General
NEBULA ANTISCAN es un detector de escaneos agresivos en tiempo real que consume decenas de fuentes OSINT, aplica inteligencia de amenazas (APT, ransomware, hacktivistas, botnets) y expone un dashboard cyberpunk con estadísticas expandibles y paginación funcional.

---

## 🧩 Fases de Desarrollo

### ✅ Fase 1 – Base funcional (COMPLETADA)
- [x] Arquitectura CLI con menú interactivo.
- [x] 130 User-Agents rotativos.
- [x] 73 fuentes de listas negras (Blocklist.de, DShield, Spamhaus, etc.).
- [x] Normalización y validación de IPv4.
- [x] Geolocalización con caché (ip-api.com).
- [x] Persistencia de IPs detectadas en JSON y archivos diarios `.txt`.
- [x] Ciclo único de escaneo (opción 2).
- [x] Estadísticas básicas de países y ASN (opción 3).

### ✅ Fase 2 – Inteligencia de amenazas (COMPLETADA)
- [x] Carga en memoria de feeds de inteligencia (`INTEL_FEEDS`).
- [x] Estructuras para grupos APT, ransomware y hacktivistas (dinámicas).
- [x] Diccionario de familias de botnets.
- [x] Función `obtener_intel()` que prioriza: APT > ransomware > hacktivistas > fuentes OSINT.
- [x] Actualización silenciosa de los feeds cada 6 horas.
- [x] Resumen detallado en la salida de la terminal.

### ✅ Fase 3 – Monitor en tiempo real (COMPLETADA)
- [x] Ciclo continuo de descarga de fuentes cada 30 segundos.
- [x] Comandos interactivos: `vt` (generar enlaces VirusTotal), `q` (salir).
- [x] Muestra IPs con país, ASN, organización, botnet y grupo.
- [x] Guardado automático de cada ciclo en ficheros diarios.

### ✅ Fase 4 – Dashboard web cyberpunk (COMPLETADA)
- [x] Servidor Flask en puerto 5091.
- [x] Panel de contexto con datos dinámicos (grupo activo, origen principal, botnet predominante, fuente más activa).
- [x] Tarjetas clicables que muestran modales con TOP 20 (países, ASN, botnets, grupos, fuentes).
- [x] Paginación funcional (25-30 IPs por página, botones Anterior/Siguiente y números).
- [x] Gráfico de evolución temporal (últimos 7 días) con Chart.js.
- [x] Filtros: todas, con botnet, con grupo, por fuente origen.
- [x] Descarga del JSON completo de detecciones.
- [x] Estilo cyberpunk (gradientes, fondos oscuros, acentos neón).

### 🔄 Fase 5 – Optimización y fiabilidad (EN PROGRESO)
- [x] Corrección de `SyntaxWarning` por escapes `\/` en el HTML.
- [ ] **Reemplazo de INTEL_FEEDS caídos** por fuentes estables (ej. lista Andrómeda).
- [ ] Mejora del manejo de errores en `descargar_fuente()` y `descargar_feed()`.
- [ ] Reducción de falsos positivos mediante filtrado de IPs repetitivas.
- [ ] Añadir opción de `itemsPerPage` configurable (actualmente 30).
- [ ] Soporte para IPv6 en geolocalización y búsquedas.

### 🧪 Fase 6 – Nuevas funcionalidades (PLANIFICADO)
- [ ] Integración de API de AbuseIPDB o VirusTotal directamente en el monitor.
- [ ] Dashboard en tiempo real con WebSockets (actualización automática sin recarga).
- [ ] Exportación de informes en PDF/CSV.
- [ ] Sistema de reglas personalizadas por el usuario (whitelist, blacklist).
- [ ] Notificaciones por Telegram/Discord cuando se detecte un grupo prioritario.
- [ ] Soporte para múltiples idiomas (i18n).
- [ ] Modo oscuro/claro alternativo en el frontend.

---

## 📁 Estructura de Archivos Esperada
nebula_antiscan/
├── nebula_antiscan.py # Script principal (unificado)
├── datos_escaneos_nebula/
│ ├── ultimas_ips_escaneos.json
│ └── ultimas_ips_escaneos.json.bak (opcional)
├── intel_escaneos_nebula/ # Almacén de feeds descargados (se crea automáticamente)
├── escaneos_AAAA-MM-DD.txt # Archivos diarios de ciclos
└── enlaces_vt_*.txt # Enlaces VirusTotal generados

text

---

## 🧰 Instalación y Ejecución

```bash
   git clone https://github.com/Condor2026/Nebula_AntiScan
   cd Nebula_AntiScan
   pip install -r requirements.txt   (Flask, requests)
   python Nebula_AntiScan.py
   📊 Métricas Actuales
   Componente	Cantidad
   User-Agents únicos	130
   Fuentes de escaneo	73
   Feeds de inteligencia	80+ (por actualizar)
   Grupos APT	16
   Grupos Ransomware	9
   Grupos Hacktivistas	9
   Familias de botnets	23
   Líneas de código	~1900-2000
   🗓️ Próximos Hitos (Estimados)
   Hito	Fecha estimada
   Sustituir INTEL_FEEDS muertos por Andrómeda	1 semana
   Añadir WebSockets al dashboard	2 semanas
   Sistema de whitelist/blacklist	3 semanas
   Notificaciones Telegram	4 semanas
   Versión 2.0 (interfaz web completa)	6 semanas
   🤝 Contribuciones
   ¿Quieres ayudar? Revisa las tareas abiertas en Fase 5 y Fase 6. Crea un issue o un PR.

   📜 Licencia
   GPL v3 – By Condor2026 / SpectrumSecurity
   Uso educativo y de defensa de redes. No me hago responsable del mal uso.

   text


