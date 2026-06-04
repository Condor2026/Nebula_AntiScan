#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""

NEBULA ANTISCAN v1.3 – Detector de escaneos agresivos en tiempo real
Monitoriza y clasifica IPs maliciosas con geolocalización e inteligencia de amenazas.
- Formato: IP | País | ASN | Organización | 🔥 botnet | 🚩 grupo | 📡 fuente
- Dashboard web cyberpunk con estadísticas, paginación, gráficos interactivos y panel de contexto
- Comandos durante monitor: vt (enlaces VirusTotal), q (salir)
- SIN LÍMITES de IPs (muestra todas las detectadas)
- Manejo de rangos CIDR y mejora de feeds

Ejecutar: python Nebula_AntiScan.py

"""

import os
import json
import time
import threading
import requests
import sys
import re
import socket
import ipaddress
import random
from datetime import datetime
from collections import Counter
from flask import Flask, render_template_string, jsonify, send_file

# ================= CONFIGURACIÓN =================
PUERTO_WEB = 5091
VT_API_KEY = "TU_API_KEY_AQUI"  # Opcional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATOS_DIR = os.path.join(BASE_DIR, "datos_escaneos_nebula")
INTEL_DIR = os.path.join(BASE_DIR, "intel_escaneos_nebula")
os.makedirs(DATOS_DIR, exist_ok=True)
os.makedirs(INTEL_DIR, exist_ok=True)

ULTIMAS_IPS_JSON = os.path.join(DATOS_DIR, "ultimas_ips_escaneos.json")

# ================= COLORES ANSI =================
VERDE = "\033[92m"
ROJO = "\033[91m"
AMARILLO = "\033[93m"
AZUL = "\033[94m"
MAGENTA = "\033[95m"
CIAN = "\033[96m"
RESET = "\033[0m"
NEGRITA = "\033[1m"

app = Flask(__name__)

# ================= USER AGENTS (130 ÚNICOS) =================
USER_AGENTS = [
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Debian; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 5.1; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/119.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-X910) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-T970) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; SM-T860) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; OnePlus 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; OnePlus 10 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Xiaomi 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; Xiaomi 13 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Xiaomi 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Samsung Galaxy Tab S9 Ultra) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.8 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.7 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPod touch; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPod touch; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.6045.163 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/119.0.6045.163 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
    'Mozilla/5.0 (compatible; DuckDuckBot/1.1; +https://duckduckgo.com/duckduckbot)',
    'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
    'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
    'Mozilla/5.0 (compatible; FacebookBot/1.0; +https://developers.facebook.com/docs/sharing/bot/)',
    'Mozilla/5.0 (compatible; Twitterbot/1.0; +https://developer.twitter.com/en/docs/twitter-for-websites/cards/overview)',
    'Mozilla/5.0 (compatible; LinkedInBot/1.0; +https://www.linkedin.com/help/linkedin/answer/904)',
    'Mozilla/5.0 (compatible; WhatsApp/2.18.203; +https://www.whatsapp.com/legal/)',
    'Mozilla/5.0 (compatible; TelegramBot/1.0; +https://telegram.org/bot)',
    'Wget/1.21.3 (linux-gnu)',
    'Wget/1.20.3 (linux-gnu)',
    'curl/8.2.1',
    'curl/7.88.1',
    'Python-urllib/3.11',
    'Python-urllib/3.10',
    'Go-http-client/1.1',
    'Apache-HttpClient/4.5.13 (Java/1.8.0_421)',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Thunderbird/115.0',
]

def obtener_user_agent():
    return random.choice(USER_AGENTS)

# ================= GEOLOCALIZACIÓN =================
geo_cache = {}

def geo_ip(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,org"
        r = requests.get(url, timeout=2)
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                res = {
                    'pais': data.get('country', 'Desconocido'),
                    'codigo_pais': data.get('countryCode', ''),
                    'asn': data.get('as', '').split()[0] if data.get('as') else '',
                    'org': data.get('org', '')[:30]
                }
                geo_cache[ip] = res
                return res
    except:
        pass
    return None

# ================= FUNCIONES DE ARCHIVO =================
def cargar_ultimas_ips():
    if os.path.exists(ULTIMAS_IPS_JSON):
        try:
            with open(ULTIMAS_IPS_JSON, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    return []

def guardar_ultimas_ips(datos):
    with open(ULTIMAS_IPS_JSON, 'w', encoding='utf-8') as f:
        json.dump(datos, f, indent=2, ensure_ascii=False)
    print(f"{VERDE}📁 JSON guardado en {ULTIMAS_IPS_JSON} ({len(datos)} IPs){RESET}")

# ================= FUENTES DE ESCANEOS (73 FUENTES) =================
FUENTES = [
    {"nombre": "Blocklist.de (ssh)", "url": "https://lists.blocklist.de/lists/ssh.txt"},
    {"nombre": "Blocklist.de (ftp)", "url": "https://lists.blocklist.de/lists/ftp.txt"},
    {"nombre": "Blocklist.de (bots)", "url": "https://lists.blocklist.de/lists/bots.txt"},
    {"nombre": "Blocklist.de (mail)", "url": "https://lists.blocklist.de/lists/mail.txt"},
    {"nombre": "Blocklist.de (apache)", "url": "https://lists.blocklist.de/lists/apache.txt"},
    {"nombre": "DShield", "url": "https://feeds.dshield.org/block.txt"},
    {"nombre": "Spamhaus EDROP", "url": "https://www.spamhaus.org/drop/edrop.txt"},
    {"nombre": "Emerging Threats", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
    {"nombre": "FireHOL Level1", "url": "https://iplists.firehol.org/files/firehol_level1.netset"},
    {"nombre": "GreenSnow", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/greensnow.ipset"},
    {"nombre": "AlienVault OTX", "url": "https://reputation.alienvault.com/reputation.data"},
    {"nombre": "CIRCL", "url": "https://raw.githubusercontent.com/CIRCL/osint-feed/master/iprep/iprep.txt"},
    {"nombre": "Maltrail", "url": "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malicious/malicious.txt"},
    {"nombre": "IPsum", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"},
    {"nombre": "BinaryDefense", "url": "https://www.binarydefense.com/banlist.txt"},
    {"nombre": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"},
    {"nombre": "CI Army", "url": "https://cinsscore.com/list/ci-badguys.txt"},
    {"nombre": "Bitwire Inbound", "url": "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt"},
    {"nombre": "Bitwire Outbound", "url": "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt"},
    {"nombre": "SSLBL", "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"},
    {"nombre": "HaGeZi TIF", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt"},
    {"nombre": "ThreatFox", "url": "https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/main/ips.txt"},
    {"nombre": "Phishing DB", "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-IPs-ACTIVE.txt"},
    {"nombre": "FireHOL Level2", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"},
    {"nombre": "FireHOL Level3", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset"},
    {"nombre": "ThreatFox Abuse", "url": "https://threatfox.abuse.ch/downloads/ipblocklist.txt"},
    {"nombre": "URLhaus", "url": "https://urlhaus.abuse.ch/downloads/ipblocklist.txt"},
    {"nombre": "IPsum Level3", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
    {"nombre": "Ellio Tech", "url": "https://feed.ellio.tech"},
    {"nombre": "SBLAM", "url": "https://sblam.com/blacklist.txt"},
    {"nombre": "DarkList", "url": "http://www.darklist.de/raw.php"},
    {"nombre": "StopForumSpam", "url": "https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt"},
    {"nombre": "DigitalSide", "url": "https://osint.digitalside.it/Threat-Intel/"},
    {"nombre": "RomainMarcoux Full AA", "url": "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-aa.txt"},
    {"nombre": "HaGeZi TIF CDN", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/tif.txt"},
    {"nombre": "Rescure", "url": "https://rescure.me/rescure_blacklist.txt"},
    {"nombre": "Botvrij", "url": "https://www.botvrij.eu/data/ioc/ioc.json"},
    {"nombre": "Dataplane SSH", "url": "https://dataplane.org/sshp.txt"},
    {"nombre": "Dataplane SIP", "url": "https://dataplane.org/sipinvites.txt"},
    {"nombre": "HoneyDB", "url": "https://honeydb.io/feeds/ips.txt"},
    {"nombre": "CriticalPath Security", "url": "https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/main/Combined-Intel.txt"},
    {"nombre": "Spydi ThreatIntel", "url": "https://raw.githubusercontent.com/spydisec/spydithreatintel/main/ips.txt"},
    {"nombre": "James Brine SSH", "url": "https://jamesbrine.com.au/feeds/ssh.txt"},
    {"nombre": "Nothink SSH", "url": "http://www.nothink.org/blacklist/ssh_all.txt"},
    {"nombre": "DuggyTuxy", "url": "https://raw.githubusercontent.com/duggytuxy/malicious-ip/main/malicious-ip.txt"},
    {"nombre": "WIFX Blocklist", "url": "https://blocklist.wifx.net/"},
    {"nombre": "CleanTalk", "url": "https://www.clean-talk.org/blacklists/ip"},
    {"nombre": "Maravento Blackweb", "url": "https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.txt"},
    {"nombre": "Bambenek C2", "url": "https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt"},
    {"nombre": "StrictBlock", "url": "https://raw.githubusercontent.com/pallebone/StrictBlockPAllebone/main/blocklist.txt"},
    {"nombre": "Intercept Threatlists", "url": "https://intercept.sh/threatlists/"},
    {"nombre": "WaLLy3K", "url": "https://raw.githubusercontent.com/WaLLy3K/wally3k.github.io/master/blacklist.txt"},
    {"nombre": "BBcan177", "url": "https://raw.githubusercontent.com/BBcan177/ipv4_blocklist/main/ipv4_blocklist.txt"},
    {"nombre": "AlphaSOC Ryuk", "url": "https://feeds.alphasoc.net/ryuk.txt"},
    {"nombre": "Ellio Feed", "url": "https://raw.githubusercontent.com/ellio/tech/main/feed.txt"},
    {"nombre": "CyberCure", "url": "https://www.cybercure.ai/feed"},
    {"nombre": "FireHOL Botscout", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset"},
    {"nombre": "FireHOL Coinbl", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/coinbl.txt"},
    {"nombre": "HaGeZi Pro", "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/pro.txt"},
    {"nombre": "IPsum Level5", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt"},
    {"nombre": "IPsum Level7", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt"},
    {"nombre": "Dataplane DNS RD", "url": "https://dataplane.org/dnsrd.txt"},
    {"nombre": "Dataplane DNS RD Any", "url": "https://dataplane.org/dnsrdany.txt"},
    {"nombre": "Dataplane SMTP", "url": "https://dataplane.org/smtp.txt"},
    {"nombre": "RomainMarcoux Full AB", "url": "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-ab.txt"},
    {"nombre": "RomainMarcoux Full AC", "url": "https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-ac.txt"},
    {"nombre": "MoImran Blacklist", "url": "https://github.com/moimran/blacklist-IP/raw/main/blacklist.txt"},
    {"nombre": "Kraloveckey Intel", "url": "https://raw.githubusercontent.com/kraloveckey/threat-intelligence-feeds/main/ips.txt"},
    {"nombre": "CriticalPath IPs", "url": "https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/main/IPs.txt"},
]

def normalizar_ip(ip_str):
    ip_str = ip_str.strip()
    if '/' in ip_str:
        try:
            red = ipaddress.ip_network(ip_str, strict=False)
            return str(red)
        except:
            return None
    patron = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(patron, ip_str):
        return None
    partes = ip_str.split('.')
    for p in partes:
        if int(p) > 255:
            return None
    return ip_str

def descargar_fuente(fuente):
    print(f"{AZUL}[*] {fuente['nombre']}...{RESET}")
    ips = []
    try:
        headers = {'User-Agent': obtener_user_agent()}
        r = requests.get(fuente['url'], headers=headers, timeout=15)
        if r.status_code == 200:
            for linea in r.text.splitlines():
                if not linea or linea.startswith('#') or linea.startswith(';'):
                    continue
                ip = normalizar_ip(linea)
                if ip:
                    ips.append(ip)
            print(f"{VERDE}  [+] {len(ips)} IPs/rangos{RESET}")
        else:
            print(f"{AMARILLO}  [!] HTTP {r.status_code}{RESET}")
    except Exception as e:
        print(f"{ROJO}  [!] Error: {e}{RESET}")
    return ips

# ================= INTELIGENCIA DE AMENAZAS (FEEDS ADICIONALES) =================
INTEL_FEEDS = [
    ("https://raw.githubusercontent.com/securityscorecard/SSC-Threat-Intel-IoCs/master/KillNet-DDoS-Blocklist/proxylist.txt", "killnet_proxies.txt"),
    ("https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/main/ips.txt", "threatfox_ips.txt"),
    ("https://raw.githubusercontent.com/govcert-ch/CTI/main/20240615_NoName057-attacking-ips.csv", "noname_attacking_ips.csv"),
    ("http://cinsscore.com/list/ci-badguys.txt", "ciarmy.txt"),
    ("http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt", "emerging.txt"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "firehol.txt"),
    ("http://blocklist.greensnow.co/greensnow.txt", "greensnow.txt"),
    ("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json", "feodo_ips.txt"),
    ("https://reputation.alienvault.com/reputation.data", "alienvault_ips.txt"),
    ("https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malicious/malicious.txt", "maltrail_ips.txt"),
    ("https://raw.githubusercontent.com/CIRCL/osint-feed/master/iprep/iprep.txt", "circl_ips.txt"),
    ("https://www.maxmind.com/en/high-risk-ip-sample-list", "maxmind_proxies.txt"),
    ("https://feeds.dshield.org/block.txt", "dshield_block.txt"),
    ("https://lists.blocklist.de/lists/all.txt", "blocklist_all.txt"),
    ("https://www.spamhaus.org/drop/edrop.txt", "spamhaus_edrop.txt"),
    ("https://urlhaus.abuse.ch/downloads/csv/", "urlhaus.csv"),
    ("https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt", "stopforumspam_toxic.txt"),
    ("https://www.binarydefense.com/banlist.txt", "binarydefense_banlist.txt"),
    ("https://danger.rulez.sk/projects/bruteforceblocker/blist.php", "bruteforceblocker.txt"),
    ("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt", "ipsum.txt"),
    ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "feodo_ipblocklist.txt"),
    ("https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt", "bitwire_inbound.txt"),
    ("https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt", "bitwire_outbound.txt"),
    ("https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "sslbl.txt"),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt", "hagezi_tif.txt"),
    ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-IPs-ACTIVE.txt", "phishing_db.txt"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset", "firehol_level2.txt"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset", "firehol_level3.txt"),
    ("https://threatfox.abuse.ch/downloads/ipblocklist.txt", "threatfox_ipblocklist.txt"),
    ("https://urlhaus.abuse.ch/downloads/ipblocklist.txt", "urlhaus_ipblocklist.txt"),
    ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "ipsum_level3.txt"),
    ("https://feed.ellio.tech", "ellio_feed.txt"),
    ("https://sblam.com/blacklist.txt", "sblam.txt"),
    ("http://www.darklist.de/raw.php", "darklist.txt"),
    ("https://osint.digitalside.it/Threat-Intel/", "digitalside.txt"),
    ("https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-aa.txt", "romainmarcoux_aa.txt"),
    ("https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/ips/tif.txt", "hagezi_tif_cdn.txt"),
    ("https://rescure.me/rescure_blacklist.txt", "rescure.txt"),
    ("https://www.botvrij.eu/data/ioc/ioc.json", "botvrij.json"),
    ("https://dataplane.org/sshp.txt", "dataplane_ssh.txt"),
    ("https://dataplane.org/sipinvites.txt", "dataplane_sip.txt"),
    ("https://honeydb.io/feeds/ips.txt", "honeydb.txt"),
    ("https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/main/Combined-Intel.txt", "criticalpath.txt"),
    ("https://raw.githubusercontent.com/spydisec/spydithreatintel/main/ips.txt", "spydi.txt"),
    ("https://jamesbrine.com.au/feeds/ssh.txt", "jamesbrine_ssh.txt"),
    ("http://www.nothink.org/blacklist/ssh_all.txt", "nothink_ssh.txt"),
    ("https://raw.githubusercontent.com/duggytuxy/malicious-ip/main/malicious-ip.txt", "duggytuxy.txt"),
    ("https://blocklist.wifx.net/", "wifx.txt"),
    ("https://www.clean-talk.org/blacklists/ip", "cleantalk.txt"),
    ("https://raw.githubusercontent.com/maravento/blackweb/master/blackweb.txt", "maravento.txt"),
    ("https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt", "bambenek.txt"),
    ("https://raw.githubusercontent.com/pallebone/StrictBlockPAllebone/main/blocklist.txt", "strictblock.txt"),
    ("https://intercept.sh/threatlists/", "intercept.txt"),
    ("https://raw.githubusercontent.com/WaLLy3K/wally3k.github.io/master/blacklist.txt", "wally3k.txt"),
    ("https://raw.githubusercontent.com/BBcan177/ipv4_blocklist/main/ipv4_blocklist.txt", "bbcan177.txt"),
    ("https://feeds.alphasoc.net/ryuk.txt", "alphasoc_ryuk.txt"),
    ("https://raw.githubusercontent.com/ellio/tech/main/feed.txt", "ellio_tech.txt"),
    ("https://www.cybercure.ai/feed", "cybercure.txt"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/botscout_1d.ipset", "botscout.txt"),
    ("https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/coinbl.txt", "coinbl.txt"),
    ("https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/pro.txt", "hagezi_pro.txt"),
    ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt", "ipsum_level5.txt"),
    ("https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt", "ipsum_level7.txt"),
    ("https://dataplane.org/dnsrd.txt", "dataplane_dnsrd.txt"),
    ("https://dataplane.org/dnsrdany.txt", "dataplane_dnsrdany.txt"),
    ("https://dataplane.org/smtp.txt", "dataplane_smtp.txt"),
    ("https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-ab.txt", "romainmarcoux_ab.txt"),
    ("https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-ac.txt", "romainmarcoux_ac.txt"),
    ("https://github.com/moimran/blacklist-IP/raw/main/blacklist.txt", "moimran.txt"),
    ("https://raw.githubusercontent.com/kraloveckey/threat-intelligence-feeds/main/ips.txt", "kraloveckey.txt"),
    ("https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/main/IPs.txt", "criticalpath_ips.txt"),
]

# Variables globales de inteligencia
KILLNET_IPS = set()
NONAME_IPS = set()
NONAME_CIDRS = []
THREATFOX_DB = {}
CIARMY_IPS = set()
EMERGING_IPS = set()
FIREHOL_IPS = set()
GREENSNOW_IPS = set()
MAXMIND_PROXY_IPS = set()
MIRAI_IPS = set()
FEODO_IPS = set()
ALIENVAULT_IPS = set()
DSHIELD_IPS = set()
BLOCKLIST_DE_IPS = set()
SPAMHAUS_IPS = set()
URLHAUS_IPS = set()
STOPFORUMSPAM_IPS = set()
BINARYDEFENSE_IPS = set()
BRUTEFORCE_IPS = set()
KILLNET_EXTRA_IPS = set()
DARKSTORM_IPS_SET = set()
ROOTSEC_IPS_SET = set()
COUP_IPS_SET = set()
ELECTUS_IPS_SET = set()
BOTNETKINGDOM_IPS_SET = set()
BOTNET_FAMILIES = {}
GRUPOS_APT = {}
GRUPOS_RANSOMWARE = {}
GRUPOS_HACKTIVISTAS = {}

def descargar_feed(url, nombre, mostrar=True):
    try:
        headers = {'User-Agent': obtener_user_agent()}
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            with open(os.path.join(INTEL_DIR, nombre), 'w', encoding='utf-8') as f:
                f.write(r.text)
            if mostrar:
                print(f"{VERDE}  ✅ {nombre} actualizado ({len(r.text.splitlines())} líneas){RESET}")
        else:
            if mostrar:
                print(f"{AMARILLO}  ⚠ {nombre} error HTTP {r.status_code}{RESET}")
    except Exception as e:
        if mostrar:
            print(f"{AMARILLO}  ⚠ {nombre} error: {e}{RESET}")

def cargar_intel_en_memoria():
    global KILLNET_IPS, NONAME_IPS, NONAME_CIDRS, THREATFOX_DB, CIARMY_IPS, EMERGING_IPS
    global FIREHOL_IPS, GREENSNOW_IPS, MAXMIND_PROXY_IPS, MIRAI_IPS, FEODO_IPS, ALIENVAULT_IPS
    global DSHIELD_IPS, BLOCKLIST_DE_IPS, SPAMHAUS_IPS, URLHAUS_IPS, STOPFORUMSPAM_IPS
    global BINARYDEFENSE_IPS, BRUTEFORCE_IPS, BOTNET_FAMILIES, KILLNET_EXTRA_IPS
    global DARKSTORM_IPS_SET, ROOTSEC_IPS_SET, COUP_IPS_SET, ELECTUS_IPS_SET, BOTNETKINGDOM_IPS_SET
    global GRUPOS_APT, GRUPOS_RANSOMWARE, GRUPOS_HACKTIVISTAS

    # Limpiar
    KILLNET_IPS.clear()
    NONAME_IPS.clear()
    NONAME_CIDRS.clear()
    THREATFOX_DB.clear()
    CIARMY_IPS.clear()
    EMERGING_IPS.clear()
    FIREHOL_IPS.clear()
    GREENSNOW_IPS.clear()
    MAXMIND_PROXY_IPS.clear()
    MIRAI_IPS.clear()
    FEODO_IPS.clear()
    ALIENVAULT_IPS.clear()
    DSHIELD_IPS.clear()
    BLOCKLIST_DE_IPS.clear()
    SPAMHAUS_IPS.clear()
    URLHAUS_IPS.clear()
    STOPFORUMSPAM_IPS.clear()
    BINARYDEFENSE_IPS.clear()
    BRUTEFORCE_IPS.clear()
    KILLNET_EXTRA_IPS.clear()
    DARKSTORM_IPS_SET.clear()
    ROOTSEC_IPS_SET.clear()
    COUP_IPS_SET.clear()
    ELECTUS_IPS_SET.clear()
    BOTNETKINGDOM_IPS_SET.clear()
    BOTNET_FAMILIES.clear()
    GRUPOS_APT.clear()
    GRUPOS_RANSOMWARE.clear()
    GRUPOS_HACKTIVISTAS.clear()

    if not os.path.exists(INTEL_DIR):
        return

    for archivo in os.listdir(INTEL_DIR):
        ruta = os.path.join(INTEL_DIR, archivo)
        if not os.path.isfile(ruta):
            continue
        nombre_lower = archivo.lower()

        # Clasificación
        if 'killnet' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.split(':')[0].strip() if ':' in line else line.strip())
                    if ip:
                        KILLNET_IPS.add(ip)
                        GRUPOS_HACKTIVISTAS.setdefault("🚩Killnet", set()).add(ip)
        elif 'noname' in nombre_lower and 'attacking' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    parts = line.strip().split(',')
                    ip = normalizar_ip(parts[0].strip() if parts else '')
                    if ip:
                        NONAME_IPS.add(ip)
                        GRUPOS_HACKTIVISTAS.setdefault("🚩NoName057(16)", set()).add(ip)
        elif 'noname_cidr' in nombre_lower or 'cidr' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    cidr = line.strip()
                    if '/' in cidr:
                        try:
                            red = ipaddress.ip_network(cidr, strict=False)
                            NONAME_CIDRS.append(red)
                        except:
                            pass
        elif 'threatfox' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip and not line.startswith('#'):
                        THREATFOX_DB[ip] = "malware"
        elif 'ciarmy' in nombre_lower or 'ci-badguys' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip and not line.startswith('#'):
                        CIARMY_IPS.add(ip)
        elif 'emerging' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip and not line.startswith('#'):
                        EMERGING_IPS.add(ip)
        elif 'firehol' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip and not line.startswith('#'):
                        FIREHOL_IPS.add(ip)
        elif 'greensnow' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip and not line.startswith('#'):
                        GREENSNOW_IPS.add(ip)
        elif 'feodo' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        FEODO_IPS.add(ip)
                        BOTNET_FAMILIES.setdefault("🔥Feodo", set()).add(ip)
        elif 'alienvault' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip and not line.startswith('#'):
                        ALIENVAULT_IPS.add(ip)
        elif 'maxmind' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        MAXMIND_PROXY_IPS.add(ip)
        elif 'binarydefense' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BINARYDEFENSE_IPS.add(ip)
        elif 'bruteforceblocker' in nombre_lower or 'bruteforce' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BRUTEFORCE_IPS.add(ip)
        elif 'dshield' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line and not line.startswith('#'):
                        parts = line.split()
                        ip = normalizar_ip(parts[0]) if parts else None
                        if ip:
                            DSHIELD_IPS.add(ip)
        elif 'blocklist' in nombre_lower and 'de' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BLOCKLIST_DE_IPS.add(ip)
        elif 'spamhaus' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not line.startswith(';'):
                        ip = normalizar_ip(line.split(';')[0].strip())
                        if ip:
                            SPAMHAUS_IPS.add(ip)
        elif 'urlhaus' in nombre_lower and 'csv' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) >= 2:
                            ip = normalizar_ip(parts[1].strip('"'))
                            if ip:
                                URLHAUS_IPS.add(ip)
        elif 'stopforumspam' in nombre_lower or 'toxic' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        STOPFORUMSPAM_IPS.add(ip)
        elif 'darkstorm' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        DARKSTORM_IPS_SET.add(ip)
                        GRUPOS_HACKTIVISTAS.setdefault("🚩DarkStorm Team", set()).add(ip)
        elif 'rootsec' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        ROOTSEC_IPS_SET.add(ip)
                        GRUPOS_HACKTIVISTAS.setdefault("🚩RootSec", set()).add(ip)
        elif 'coup' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        COUP_IPS_SET.add(ip)
                        GRUPOS_HACKTIVISTAS.setdefault("🚩Coup", set()).add(ip)
        elif 'electus' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        ELECTUS_IPS_SET.add(ip)
                        GRUPOS_APT.setdefault("🚩Electus", set()).add(ip)
        elif 'botnetkingdom' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BOTNETKINGDOM_IPS_SET.add(ip)
                        GRUPOS_HACKTIVISTAS.setdefault("🚩BotnetKingdom", set()).add(ip)
        elif 'gafgyt' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BOTNET_FAMILIES.setdefault("🔥Gafgyt", set()).add(ip)
        elif 'kaiji' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BOTNET_FAMILIES.setdefault("🔥Kaiji", set()).add(ip)
        elif 'miori' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BOTNET_FAMILIES.setdefault("🔥Miori", set()).add(ip)
        elif 'hailbot' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BOTNET_FAMILIES.setdefault("🔥Hailbot", set()).add(ip)
        elif 'xorbot' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BOTNET_FAMILIES.setdefault("🔥Xorbot", set()).add(ip)
        elif 'mirai' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        MIRAI_IPS.add(ip)
                        BOTNET_FAMILIES.setdefault("🔥Mirai", set()).add(ip)
        elif 'spydi' in nombre_lower:
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        BOTNET_FAMILIES.setdefault("🔥Spydi", set()).add(ip)
        elif 'apt' in nombre_lower:
            nombre_grupo = "🚩" + archivo.replace('.txt', '').replace('_ips', '').replace('_', ' ').title()
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        GRUPOS_APT.setdefault(nombre_grupo, set()).add(ip)
        elif 'ransomware' in nombre_lower or 'lockbit' in nombre_lower or 'conti' in nombre_lower or 'revil' in nombre_lower:
            nombre_grupo = "🚩" + archivo.replace('.txt', '').replace('_ips', '').replace('_', ' ').title()
            with open(ruta, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip = normalizar_ip(line.strip())
                    if ip:
                        GRUPOS_RANSOMWARE.setdefault(nombre_grupo, set()).add(ip)

    total_apt = sum(len(s) for s in GRUPOS_APT.values())
    total_ransomware = sum(len(s) for s in GRUPOS_RANSOMWARE.values())
    total_hacktivistas = sum(len(s) for s in GRUPOS_HACKTIVISTAS.values())

    print(f"{CIAN}📚 Intel cargada: Killnet={len(KILLNET_IPS)} | NoName={len(NONAME_IPS)} IPs+{len(NONAME_CIDRS)} CIDRs | ThreatFox={len(THREATFOX_DB)} | CI Army={len(CIARMY_IPS)} | Emerging={len(EMERGING_IPS)} | Firehol={len(FIREHOL_IPS)} | GreenSnow={len(GREENSNOW_IPS)} | MaxMind={len(MAXMIND_PROXY_IPS)} | Mirai={len(MIRAI_IPS)} | Feodo={len(FEODO_IPS)} | AlienVault={len(ALIENVAULT_IPS)}{RESET}")
    print(f"{CIAN}     DShield={len(DSHIELD_IPS)} | Blocklist.de={len(BLOCKLIST_DE_IPS)} | Spamhaus={len(SPAMHAUS_IPS)} | URLhaus={len(URLHAUS_IPS)} | StopForumSpam={len(STOPFORUMSPAM_IPS)} | BinaryDefense={len(BINARYDEFENSE_IPS)} | Bruteforce={len(BRUTEFORCE_IPS)}{RESET}")
    print(f"{CIAN}     Spydi: {len(BOTNET_FAMILIES.get('🔥Spydi', set()))} | KillnetExtra={len(KILLNET_EXTRA_IPS)} | DarkStorm={len(DARKSTORM_IPS_SET)} | RootSec={len(ROOTSEC_IPS_SET)} | Coup={len(COUP_IPS_SET)} | Electus={len(ELECTUS_IPS_SET)} | BotnetKingdom={len(BOTNETKINGDOM_IPS_SET)}{RESET}")
    print(f"{CIAN}     Gafgyt={len(BOTNET_FAMILIES.get('🔥Gafgyt', set()))} | Kaiji={len(BOTNET_FAMILIES.get('🔥Kaiji', set()))} | Miori={len(BOTNET_FAMILIES.get('🔥Miori', set()))} | Hailbot={len(BOTNET_FAMILIES.get('🔥Hailbot', set()))} | Xorbot={len(BOTNET_FAMILIES.get('🔥Xorbot', set()))} | MiraiExtra={len(BOTNET_FAMILIES.get('🔥Mirai', set()))}{RESET}")
    print(f"{CIAN}     Grupos APT: {len(GRUPOS_APT)} grupos, {total_apt} IPs | Ransomware: {len(GRUPOS_RANSOMWARE)} grupos, {total_ransomware} IPs | Hacktivistas: {len(GRUPOS_HACKTIVISTAS)} grupos, {total_hacktivistas} IPs{RESET}")

def obtener_intel(ip, fuente_origen=None):
    grupo = None
    botnet = None
    fuente_detectada = fuente_origen

    for nombre_grupo, ips_set in GRUPOS_APT.items():
        if ip in ips_set:
            grupo = nombre_grupo
            break
    if not grupo:
        for nombre_grupo, ips_set in GRUPOS_RANSOMWARE.items():
            if ip in ips_set:
                grupo = nombre_grupo
                break
    if not grupo:
        for nombre_grupo, ips_set in GRUPOS_HACKTIVISTAS.items():
            if ip in ips_set:
                grupo = nombre_grupo
                break
    if not grupo:
        if ip in KILLNET_IPS or ip in KILLNET_EXTRA_IPS:
            grupo = "🚩Killnet"
        elif ip in NONAME_IPS or any(ipaddress.ip_address(ip) in cidr for cidr in NONAME_CIDRS):
            grupo = "🚩NoName057(16)"
        elif ip in DARKSTORM_IPS_SET:
            grupo = "🚩DarkStorm Team"
        elif ip in ROOTSEC_IPS_SET:
            grupo = "🚩RootSec"
        elif ip in COUP_IPS_SET:
            grupo = "🚩Coup"
        elif ip in ELECTUS_IPS_SET:
            grupo = "🚩Electus"
        elif ip in BOTNETKINGDOM_IPS_SET:
            grupo = "🚩BotnetKingdom"

    if ip in THREATFOX_DB:
        botnet = "🔥ThreatFox"
    elif ip in CIARMY_IPS:
        botnet = "🔥CI Army"
    elif ip in EMERGING_IPS:
        botnet = "🔥EmergingThreats"
    elif ip in FIREHOL_IPS:
        botnet = "🔥FireHOL"
    elif ip in GREENSNOW_IPS:
        botnet = "🔥GreenSnow"
    elif ip in MAXMIND_PROXY_IPS:
        botnet = "🔥MaxMind Proxy"
    elif ip in MIRAI_IPS or ip in FEODO_IPS:
        botnet = "🔥Feodo/Mirai"
    elif ip in ALIENVAULT_IPS:
        botnet = "🔥AlienVault"
    elif ip in DSHIELD_IPS:
        botnet = "🔥DShield"
    elif ip in BLOCKLIST_DE_IPS:
        botnet = "🔥Blocklist.de"
    elif ip in SPAMHAUS_IPS:
        botnet = "🔥Spamhaus"
    elif ip in URLHAUS_IPS:
        botnet = "🔥URLhaus"
    elif ip in STOPFORUMSPAM_IPS:
        botnet = "🔥StopForumSpam"
    elif ip in BINARYDEFENSE_IPS:
        botnet = "🔥BinaryDefense"
    elif ip in BRUTEFORCE_IPS:
        botnet = "🔥Bruteforce Blocker"

    for etiqueta in ["🔥Spydi", "🔥Gafgyt", "🔥Kaiji", "🔥Miori", "🔥Hailbot", "🔥Xorbot", "🔥Mirai", "🔥Feodo"]:
        if ip in BOTNET_FAMILIES.get(etiqueta, set()):
            botnet = etiqueta
            break

    if not grupo and not botnet and fuente_detectada:
        botnet = f"🔥{fuente_detectada}"

    return grupo, botnet, fuente_detectada

def actualizar_intel_inicial():
    print(f"{AMARILLO}🔄 Actualizando {len(INTEL_FEEDS)} feeds de inteligencia...{RESET}")
    for url, nombre in INTEL_FEEDS:
        descargar_feed(url, nombre, mostrar=True)
        time.sleep(0.3)
    cargar_intel_en_memoria()
    print(f"{VERDE}✅ Intel actualizada con {len(INTEL_FEEDS)} feeds.{RESET}")

def actualizador_intel_silencioso():
    while True:
        time.sleep(21600)  # cada 6 horas
        for url, nombre in INTEL_FEEDS:
            try:
                headers = {'User-Agent': obtener_user_agent()}
                r = requests.get(url, headers=headers, timeout=15)
                if r.status_code == 200:
                    with open(os.path.join(INTEL_DIR, nombre), 'w', encoding='utf-8') as f:
                        f.write(r.text)
            except:
                pass
            time.sleep(0.3)
        cargar_intel_en_memoria()

# ================= VIRUSTOTAL API =================
def consultar_virustotal(ip):
    if VT_API_KEY == "TU_API_KEY_AQUI":
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values()) if stats else 0
            return f"{malicious}/{total} detecciones" if total > 0 else "Sin detecciones"
        elif r.status_code == 404:
            return "No reportada"
        else:
            return f"Error {r.status_code}"
    except Exception as e:
        return f"Error: {e}"

def generar_enlaces_vt(ips, usar_api=False):
    if not ips:
        print(f"{AMARILLO}No hay IPs para procesar.{RESET}")
        return
    archivo = f"enlaces_vt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(archivo, "w", encoding='utf-8') as f:
            f.write(f"# Enlaces VirusTotal - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total IPs: {len([ip for ip in ips if '/' not in ip])}\n\n")
            for ip in sorted(ips):
                if '/' in ip:
                    continue
                f.write(f"https://www.virustotal.com/gui/ip-address/{ip}\n")
                if usar_api and VT_API_KEY != "TU_API_KEY_AQUI":
                    resultado = consultar_virustotal(ip)
                    if resultado:
                        f.write(f"  -> {resultado}\n")
        print(f"{VERDE}✅ Enlaces guardados en {archivo}{RESET}")
    except Exception as e:
        print(f"{ROJO}❌ Error: {e}{RESET}")

# ================= MONITOR DE ESCANEOS EN TIEMPO REAL =================
def monitor_escaneos():
    print(f"\n{CIAN}{NEGRITA}=== MONITOR NEBULA ANTISCAN EN TIEMPO REAL ==={RESET}")
    print(f"{AMARILLO}Comandos:{RESET}")
    print(f"  {VERDE}vt{RESET} + Enter: generar enlaces VirusTotal")
    print(f"  {ROJO}q{RESET} + Enter: salir")
    print(f"{CIAN}Mostrando IPs cada 30 segundos... (guardado acumulado){RESET}\n")

    ultimas_ips = set()
    corriendo = True

    def mostrar_ips(ips, fuentes_origen):
        print(f"\n{CIAN}[{datetime.now().strftime('%H:%M:%S')}] IPs obtenidas: {len(ips)} únicas{RESET}")
        lista = sorted(ips)
        for i, ip in enumerate(lista):
            if '/' in ip:
                print(f"  {i+1:4}. {ip:<18} {AMARILLO}(rango de red){RESET}")
            else:
                geo = geo_ip(ip)
                fuente_ip = fuentes_origen.get(ip, None)
                grupo, botnet, fuente_detectada = obtener_intel(ip, fuente_ip)
                if geo:
                    pais = geo.get('pais', '?')[:15]
                    asn = geo.get('asn', '')[:12]
                    org = geo.get('org', '')[:20]
                    grupo_str = f"{ROJO}{grupo}{RESET}" if grupo else "-"
                    botnet_str = f"{AMARILLO}{botnet}{RESET}" if botnet else "-"
                    print(f"  {i+1:4}. {ip:<18} {VERDE}{pais:<15}{RESET} ASN:{AMARILLO}{asn:<12}{RESET} {AZUL}{org:<20}{RESET} 🔥{botnet_str:<30} 🚩{grupo_str}")
                else:
                    print(f"  {i+1:4}. {ip:<18} {AMARILLO}(geolocalización no disponible){RESET}")
            if i >= 2999 and len(lista) > 3000:   # ← límite de impresión en 3000
                print(f"\n{AMARILLO}... y {len(lista)-3000} más{RESET}")
                break

    def guardar_ips_todas(ips, fuentes_origen):
        fecha_archivo = datetime.now().strftime('%Y-%m-%d')
        archivo = f"escaneos_{fecha_archivo}.txt"
        hora_actual = datetime.now().strftime('%H:%M:%S')
        try:
            with open(archivo, "a", encoding='utf-8') as f:
                f.write(f"\n# --- Ciclo de las {hora_actual} ---\n")
                if ips:
                    for ip in sorted(ips):
                        fuente = fuentes_origen.get(ip, "")
                        f.write(f"{ip} # {fuente}\n")
            print(f"{VERDE}✅ Datos añadidos a {archivo}{RESET}")
        except Exception as e:
            print(f"{ROJO}❌ Error: {e}{RESET}")

    def escuchar_comandos():
        nonlocal corriendo
        while corriendo:
            try:
                cmd = sys.stdin.readline().strip().lower()
                if cmd == 'q':
                    corriendo = False
                    break
                elif cmd == 'vt':
                    generar_enlaces_vt(ultimas_ips, usar_api=True)
            except:
                pass

    hilo_cmd = threading.Thread(target=escuchar_comandos, daemon=True)
    hilo_cmd.start()

    while corriendo:
        nuevas_ips = set()
        fuentes_origen = {}
        for fuente in FUENTES:
            ips_fuente = descargar_fuente(fuente)
            for ip in ips_fuente:
                nuevas_ips.add(ip)
                if ip not in fuentes_origen:
                    fuentes_origen[ip] = fuente['nombre']
            time.sleep(0.5)

        ultimas_ips = nuevas_ips

        # 🔥 LIMITAR EL NÚMERO DE IPs A PROCESAR (para que no se cuelgue)
        MAX_IPS = 10000
        if len(ultimas_ips) > MAX_IPS:
            ultimas_ips = set(list(ultimas_ips)[:MAX_IPS])
            print(f"{AMARILLO}⚠ Limitando a {MAX_IPS} IPs (había {len(nuevas_ips)}){RESET}")

        mostrar_ips(ultimas_ips, fuentes_origen)
        guardar_ips_todas(ultimas_ips, fuentes_origen)

        datos_ip = []
        for ip in ultimas_ips:
            if '/' not in ip:
                geo = geo_ip(ip) or {}
                fuente_ip = fuentes_origen.get(ip, None)
                grupo, botnet, fuente_detectada = obtener_intel(ip, fuente_ip)
                datos_ip.append({
                    "ip": ip,
                    "pais": geo.get('pais', 'Desconocido'),
                    "codigo_pais": geo.get('codigo_pais', ''),
                    "asn": geo.get('asn', ''),
                    "org": geo.get('org', ''),
                    "grupo": grupo,
                    "botnet": botnet,
                    "fuente_origen": fuente_detectada,
                    "ultima_vista": datetime.now().isoformat()
                })
        guardar_ultimas_ips(datos_ip)

        if corriendo:
            for _ in range(30):
                if not corriendo:
                    break
                time.sleep(1)

    print(f"\n{ROJO}Monitor detenido.{RESET}")

# ================= SERVIDOR WEB (DASHBOARD CYBERPUNK) =================
def obtener_ip_local():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

@app.route('/')
def index():
    return render_template_string(r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEBULA ANTISCAN · Cyber Threat Detection</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
font-family: 'Inter', sans-serif;
background: #0a0c15;
color: #e0e5f0;
padding: 2rem 1rem;
position: relative;
overflow-x: hidden;
}
body::before {
content: '';
position: fixed;
top: 0; left: 0; width: 100%; height: 100%;
background: linear-gradient(90deg, transparent 95%, rgba(0,255,157,0.02) 50%),
            linear-gradient(0deg, transparent 95%, rgba(255,107,74,0.02) 50%);
background-size: 50px 50px;
pointer-events: none;
z-index: -1;
}
.container { max-width: 1600px; margin: 0 auto; }
h1 {
font-size: 2.8rem;
font-weight: 800;
margin-bottom: 0.5rem;
text-align: center;
background: linear-gradient(135deg, #00ff9d, #ff6b4a);
-webkit-background-clip: text;
-webkit-text-fill-color: transparent;
letter-spacing: 1px;
}
.subtitle {
text-align: center;
color: #8892b0;
margin-bottom: 2rem;
font-size: 0.9rem;
text-transform: uppercase;
letter-spacing: 3px;
}
.context-panel {
background: rgba(0,0,0,0.6);
border-left: 4px solid #ff6b4a;
padding: 1rem;
margin-bottom: 2rem;
border-radius: 8px;
}
.context-panel h3 { color: #ff6b4a; margin-bottom: 0.5rem; }
.context-panel ul { margin-left: 1.5rem; color: #a0b0d0; }
.context-panel li { margin: 0.3rem 0; }
.stats-grid {
display: grid;
grid-template-columns: repeat(5, 1fr);
gap: 1.5rem;
margin-bottom: 2rem;
}
.stat-card {
background: rgba(20,25,35,0.9);
backdrop-filter: blur(10px);
border: 1px solid rgba(0,255,157,0.2);
border-radius: 20px;
padding: 1.5rem;
transition: all 0.3s ease;
border-top: 3px solid;
cursor: pointer;
}
.stat-card:hover { transform: translateY(-5px); border-color: #00ff9d; }
.stat-card.ips { border-top-color: #00ff9d; }
.stat-card.paises { border-top-color: #ff6b4a; }
.stat-card.asns { border-top-color: #4a9eff; }
.stat-card.botnets { border-top-color: #ffaa00; }
.stat-card.grupos { border-top-color: #ff00ff; }
.stat-card h2 { font-size: 2rem; font-weight: 700; color: #00ff9d; }
.stat-card p { color: #8892b0; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 1px; margin-top: 0.5rem; }
.stat-card .expand-hint { font-size: 0.65rem; color: #ff6b4a; margin-top: 0.5rem; display: none; }
.stat-card:hover .expand-hint { display: block; }
.modal {
display: none;
position: fixed;
z-index: 1000;
left: 0; top: 0;
width: 100%; height: 100%;
background-color: rgba(0,0,0,0.8);
backdrop-filter: blur(5px);
}
.modal-content {
background: #0f121c;
margin: 5% auto;
padding: 2rem;
border: 1px solid #00ff9d;
border-radius: 20px;
width: 80%;
max-width: 600px;
max-height: 80vh;
overflow-y: auto;
color: #e0e5f0;
position: relative;
}
.modal-content h3 { color: #ff6b4a; margin-bottom: 1rem; font-size: 1.5rem; }
.modal-content ul { list-style: none; padding: 0; }
.modal-content li { padding: 0.5rem; border-bottom: 1px solid rgba(0,255,157,0.2); display: flex; justify-content: space-between; }
.modal-content li span:first-child { font-weight: 600; }
.modal-content li span:last-child { color: #00ff9d; }
.close { position: absolute; right: 1.5rem; top: 1rem; color: #ff6b4a; font-size: 2rem; cursor: pointer; }
.close:hover { color: #00ff9d; }
.controls-bar {
display: flex;
flex-wrap: wrap;
gap: 1rem;
margin-bottom: 1.5rem;
justify-content: space-between;
align-items: center;
}
.filters { display: flex; flex-wrap: wrap; gap: 0.8rem; }
.filter-btn {
background: rgba(30,35,50,0.9);
border: 1px solid rgba(0,255,157,0.3);
color: #a0b0d0;
padding: 0.5rem 1rem;
border-radius: 30px;
cursor: pointer;
font-size: 0.8rem;
transition: all 0.2s;
}
.filter-btn:hover, .filter-btn.active {
background: #00ff9d;
color: #0a0c15;
border-color: #00ff9d;
}
.refresh-btn {
background: rgba(30,35,50,0.9);
border: 1px solid rgba(255,107,74,0.5);
color: #ff6b4a;
padding: 0.5rem 1.2rem;
border-radius: 30px;
cursor: pointer;
font-size: 0.8rem;
font-weight: 600;
}
.refresh-btn:hover { background: #ff6b4a; color: #0a0c15; }
.chart-container {
background: rgba(20,25,35,0.9);
backdrop-filter: blur(10px);
border: 1px solid rgba(0,255,157,0.2);
border-radius: 20px;
padding: 1.5rem;
margin-bottom: 1.5rem;
}
.chart-container h3 { color: #ff6b4a; margin-bottom: 1rem; font-size: 1.1rem; }
canvas { max-height: 300px; }
.card {
background: rgba(20,25,35,0.9);
backdrop-filter: blur(10px);
border: 1px solid rgba(0,255,157,0.2);
border-radius: 20px;
overflow: hidden;
margin-bottom: 1.5rem;
}
.card-header {
background: rgba(0,0,0,0.5);
border-bottom: 1px solid rgba(255,107,74,0.3);
padding: 1rem 1.5rem;
display: flex;
justify-content: space-between;
align-items: center;
flex-wrap: wrap;
gap: 1rem;
}
.card-header h3 { color: #ff6b4a; font-size: 1.1rem; }
.download-link {
color: #00ff9d;
text-decoration: none;
border: 1px solid #00ff9d;
padding: 0.4rem 1rem;
border-radius: 30px;
font-size: 0.8rem;
}
.download-link:hover { background: #00ff9d; color: #0a0c15; }
.table-container { overflow-x: auto; padding: 0 1.5rem 1.5rem 1.5rem; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { background: rgba(30,35,50,0.8); color: #00ff9d; padding: 0.8rem 0.5rem; text-align: left; font-weight: 600; }
td { padding: 0.7rem 0.5rem; border-bottom: 1px solid rgba(255,107,74,0.15); }
tr:hover { background: rgba(0,255,157,0.05); }
.ip { font-family: monospace; color: #00ff9d; font-weight: 600; }
.asn { color: #ffaa00; font-family: monospace; }
.org { color: #4a9eff; }
.badge {
display: inline-block;
padding: 0.2rem 0.6rem;
border-radius: 20px;
font-size: 0.7rem;
font-weight: 600;
background: rgba(0,255,157,0.1);
border: 1px solid #00ff9d;
color: #00ff9d;
}
.badge-botnet { background: rgba(255,107,74,0.15); border-color: #ff6b4a; color: #ff6b4a; }
.badge-grupo { background: rgba(255,107,74,0.15); border-color: #ff6b4a; color: #ff6b4a; }
.badge-fuente { background: rgba(74,158,255,0.15); border-color: #4a9eff; color: #4a9eff; }
.pagination {
display: flex;
justify-content: center;
gap: 0.5rem;
margin-top: 1.5rem;
flex-wrap: wrap;
}
.page-btn {
background: rgba(30,35,50,0.9);
border: 1px solid rgba(0,255,157,0.3);
color: #e0e5f0;
padding: 0.4rem 0.9rem;
border-radius: 8px;
cursor: pointer;
transition: all 0.2s;
font-weight: 500;
}
.page-btn:hover, .page-btn.active { background: #00ff9d; color: #0a0c15; border-color: #00ff9d; }
.page-btn.disabled { opacity: 0.3; cursor: not-allowed; }
.footer { margin-top: 2rem; text-align: center; color: #3a4450; font-size: 0.75rem; }
@media (max-width: 768px) {
.stats-grid { grid-template-columns: repeat(2, 1fr); }
h1 { font-size: 1.8rem; }
.modal-content { width: 95%; margin: 10% auto; }
}
</style>
</head>
<body>
<div class="container">
<h1>★ NEBULA ANTISCAN ★</h1>
<div class="subtitle">AGGRESSIVE SCAN DETECTION · REAL-TIME THREAT INTELLIGENCE</div>
<div class="context-panel" id="context-panel">
<h3>📊 Análisis de Contexto</h3>
<div id="context-insights">Cargando inteligencia...</div>
</div>
<div class="stats-grid">
<div class="stat-card ips" onclick="showModal('total')">
<h2 id="total-ips">0</h2><p>IPs ÚNICAS</p><div class="expand-hint">🔍 Haz clic para ver detalles</div>
</div>
<div class="stat-card paises" onclick="showModal('paises')">
<h2 id="total-paises">0</h2><p>PAÍSES</p><div class="expand-hint">🔍 Haz clic para ver top 20</div>
</div>
<div class="stat-card asns" onclick="showModal('asns')">
<h2 id="total-asns">0</h2><p>ASN DISTINTOS</p><div class="expand-hint">🔍 Haz clic para ver top 20</div>
</div>
<div class="stat-card botnets" onclick="showModal('botnets')">
<h2 id="total-botnets">0</h2><p>BOTNETS</p><div class="expand-hint">🔍 Haz clic para ver top 20</div>
</div>
<div class="stat-card grupos" onclick="showModal('grupos')">
<h2 id="total-grupos">0</h2><p>GRUPOS</p><div class="expand-hint">🔍 Haz clic para ver top 20</div>
</div>
</div>
<div id="statsModal" class="modal">
<div class="modal-content"><span class="close" onclick="closeModal()">&times;</span><h3 id="modalTitle">Estadísticas</h3><ul id="modalList"></ul></div>
</div>
<div class="controls-bar">
<div class="filters" id="filters">
<button class="filter-btn active" data-filter="all">🌍 Todas</button>
<button class="filter-btn" data-filter="botnet">🔥 Con botnet</button>
<button class="filter-btn" data-filter="grupo">🚩 Con grupo</button>
<button class="filter-btn" data-filter="fuente">📡 Por fuente origen</button>
</div>
<button class="refresh-btn" id="manual-refresh">🔄 Actualizar ahora</button>
</div>
<div class="chart-container"><h3>📈 Evolución temporal (últimos 7 días)</h3><canvas id="timelineChart"></canvas></div>
<div class="card">
<div class="card-header"><h3>🌐 ÚLTIMAS IPs DETECTADAS</h3><a href="/download-json" class="download-link">📥 DESCARGAR JSON</a></div>
<div class="table-container">
<table id="ip-table">
<thead>
<th>#</th><th>IP</th><th>PAÍS</th><th>ASN</th><th>ORGANIZACIÓN</th><th>🔥 BOTNET</th><th> 🚩 GRUPO</th><th>📡 FUENTE</th><th>ÚLTIMA VEZ</th>
</thead>
<tbody id="ip-tbody"><tr><td colspan="9" style="text-align:center; padding:2rem;">Cargando datos...<\/td><\/tr><\/tbody>
<\/table>
<\/div>
<div class="pagination" id="pagination"><\/div>
<\/div>
<div class="footer"><p>73 fuentes OSINT · 80+ feeds inteligencia · Grupos APT/Ransomware/Hacktivistas · Actualización cada 30s · 🛡 Condor2026</p><\/div>
<\/div>
<script>
let currentPage = 1, itemsPerPage = 30, allData = [], currentFilter = 'all', timelineChart = null;

function getFlagEmoji(c) {
if (!c || c.length !== 2) return '🌐';
return String.fromCodePoint(...c.toUpperCase().split('').map(c => 127397 + c.charCodeAt()));
}

function formatDate(i) {
if (!i) return '';
const d = new Date(i);
return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) + ' ' + d.toLocaleDateString([], {day:'2-digit', month:'2-digit'});
}

function updateStats(d) {
const total = d.length;
const paises = new Set(d.map(i => i.codigo_pais).filter(c => c));
const asns = new Set(d.map(i => i.asn).filter(a => a));
const botnets = d.filter(i => i.botnet && i.botnet !== '-').length;
const grupos = d.filter(i => i.grupo && i.grupo !== '-').length;

document.getElementById('total-ips').textContent = total;
document.getElementById('total-paises').textContent = paises.size;
document.getElementById('total-asns').textContent = asns.size;
document.getElementById('total-botnets').textContent = botnets;
document.getElementById('total-grupos').textContent = grupos;

window.statsData = { paises: {}, asns: {}, botnets: {}, grupos: {}, fuentes: {} };

d.forEach(item => {
if (item.pais) window.statsData.paises[item.pais] = (window.statsData.paises[item.pais] || 0) + 1;
if (item.asn) window.statsData.asns[item.asn] = (window.statsData.asns[item.asn] || 0) + 1;
if (item.botnet && item.botnet !== '-') window.statsData.botnets[item.botnet] = (window.statsData.botnets[item.botnet] || 0) + 1;
if (item.grupo && item.grupo !== '-') window.statsData.grupos[item.grupo] = (window.statsData.grupos[item.grupo] || 0) + 1;
if (item.fuente_origen) window.statsData.fuentes[item.fuente_origen] = (window.statsData.fuentes[item.fuente_origen] || 0) + 1;
});
}

function showModal(tipo) {
const modal = document.getElementById('statsModal');
const title = document.getElementById('modalTitle');
const list = document.getElementById('modalList');

let data = {}, titleText = '';

if (tipo === 'paises') { data = window.statsData.paises; titleText = '🌍 TOP 20 PAÍSES'; }
else if (tipo === 'asns') { data = window.statsData.asns; titleText = '🔧 TOP 20 ASN'; }
else if (tipo === 'botnets') { data = window.statsData.botnets; titleText = '🔥 TOP 20 BOTNETS'; }
else if (tipo === 'grupos') { data = window.statsData.grupos; titleText = '🚩 TOP 20 GRUPOS'; }
else if (tipo === 'fuentes') { data = window.statsData.fuentes; titleText = '📡 TOP 20 FUENTES'; }
else if (tipo === 'total') {
titleText = '📊 RESUMEN GLOBAL';
list.innerHTML = `<li><span>Total IPs únicas</span><span>${document.getElementById('total-ips').textContent}</span></li>
<li><span>Países distintos</span><span>${document.getElementById('total-paises').textContent}</span></li>
<li><span>ASN distintos</span><span>${document.getElementById('total-asns').textContent}</span></li>
<li><span>Botnets detectadas</span><span>${document.getElementById('total-botnets').textContent}</span></li>
<li><span>Grupos detectados</span><span>${document.getElementById('total-grupos').textContent}</span></li>`;
title.textContent = titleText;
modal.style.display = 'block';
return;
}

const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 20);
list.innerHTML = sorted.map(([k, v]) => `<li><span>${k}</span><span>${v} IPs</span></li>`).join('');
if (sorted.length === 0) list.innerHTML = '<li>No hay datos suficientes</li>';
title.textContent = titleText;
modal.style.display = 'block';
}

function closeModal() { document.getElementById('statsModal').style.display = 'none'; }
window.onclick = function(e) { const m = document.getElementById('statsModal'); if (e.target === m) m.style.display = 'none'; }

function getFilteredData() {
if (currentFilter === 'botnet') return allData.filter(i => i.botnet && i.botnet !== '-');
if (currentFilter === 'grupo') return allData.filter(i => i.grupo && i.grupo !== '-');
if (currentFilter === 'fuente') return allData.filter(i => i.fuente_origen && i.fuente_origen !== '-');
return allData;
}

function renderPage() {
const filtered = getFilteredData();
const totalPages = Math.ceil(filtered.length / itemsPerPage);
if (currentPage > totalPages) currentPage = totalPages;
if (currentPage < 1) currentPage = 1;
const start = (currentPage - 1) * itemsPerPage;
const pageData = filtered.slice(start, start + itemsPerPage);
const tbody = document.getElementById('ip-tbody');
tbody.innerHTML = '';
if (pageData.length === 0) {
tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:2rem;">No hay datos<\/td><\/tr>';
return;
}
pageData.forEach((item, idx) => {
const rowIdx = start + idx + 1;
const botnetDisplay = item.botnet && item.botnet !== '-' ? item.botnet : '-';
const grupoDisplay = item.grupo && item.grupo !== '-' ? item.grupo : '-';
const fuenteDisplay = item.fuente_origen && item.fuente_origen !== '-' ? item.fuente_origen.slice(0, 25) : '-';
const row = `<table>
<td>${rowIdx}<\/td>
<td class="ip">${item.ip}<\/td>
<td><span class="flag">${getFlagEmoji(item.codigo_pais)}<\/span> ${item.pais || 'Desconocido'}<\/td>
<td class="asn">${item.asn || '-'}<\/td>
<td class="org">${(item.org || '-').slice(0, 25)}<\/td>
<td>${botnetDisplay !== '-' ? `<span class="badge badge-botnet">${botnetDisplay}</span>` : '-'}<\/td>
<td>${grupoDisplay !== '-' ? `<span class="badge badge-grupo">${grupoDisplay}</span>` : '-'}<\/td>
<td>${fuenteDisplay !== '-' ? `<span class="badge badge-fuente">${fuenteDisplay}</span>` : '-'}<\/td>
<td>${formatDate(item.ultima_vista)}<\/td>
<\/tr>`;
tbody.insertAdjacentHTML('beforeend', row);
});
renderPagination(totalPages);
}

function renderPagination(totalPages) {
const pagination = document.getElementById('pagination');
pagination.innerHTML = '';
if (totalPages <= 1) return;
const prev = document.createElement('button');
prev.className = 'page-btn' + (currentPage === 1 ? ' disabled' : '');
prev.textContent = '⬅ Anterior';
prev.onclick = function() { if (currentPage > 1) { currentPage--; renderPage(); } };
pagination.appendChild(prev);
let startPage = Math.max(1, currentPage - 2);
let endPage = Math.min(totalPages, currentPage + 2);
if (startPage > 1) {
const first = document.createElement('button');
first.className = 'page-btn';
first.textContent = '1';
first.onclick = function() { currentPage = 1; renderPage(); };
pagination.appendChild(first);
if (startPage > 2) pagination.appendChild(document.createTextNode('...'));
}
for (let i = startPage; i <= endPage; i++) {
const btn = document.createElement('button');
btn.className = 'page-btn' + (i === currentPage ? ' active' : '');
btn.textContent = i;
btn.onclick = function() { currentPage = i; renderPage(); };
pagination.appendChild(btn);
}
if (endPage < totalPages) {
if (endPage < totalPages - 1) pagination.appendChild(document.createTextNode('...'));
const last = document.createElement('button');
last.className = 'page-btn';
last.textContent = totalPages;
last.onclick = function() { currentPage = totalPages; renderPage(); };
pagination.appendChild(last);
}
const next = document.createElement('button');
next.className = 'page-btn' + (currentPage === totalPages ? ' disabled' : '');
next.textContent = 'Siguiente ➔';
next.onclick = function() { if (currentPage < totalPages) { currentPage++; renderPage(); } };
pagination.appendChild(next);
}

function updateTimeline(data) {
if (!timelineChart) {
const ctx = document.getElementById('timelineChart').getContext('2d');
timelineChart = new Chart(ctx, {
type: 'line',
data: { labels: [], datasets: [{ label: 'IPs detectadas', data: [], borderColor: '#00ff9d', backgroundColor: 'rgba(0,255,157,0.1)', fill: true }] },
options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#e0e5f0' } } } }
});
}
const last7Days = [...Array(7)].map((_, i) => {
const d = new Date(); d.setDate(d.getDate() - (6 - i)); return d.toLocaleDateString();
});
const counts = last7Days.map(day => data.filter(item => new Date(item.ultima_vista).toLocaleDateString() === day).length);
timelineChart.data.labels = last7Days;
timelineChart.data.datasets[0].data = counts;
timelineChart.update();
}

function cargarContexto(data) {
const insights = [], grupos = {}, paises = {}, botnets = {}, fuentes = {};
data.forEach(item => {
if (item.grupo && item.grupo !== '-') grupos[item.grupo] = (grupos[item.grupo] || 0) + 1;
if (item.pais) paises[item.pais] = (paises[item.pais] || 0) + 1;
if (item.botnet && item.botnet !== '-') botnets[item.botnet] = (botnets[item.botnet] || 0) + 1;
if (item.fuente_origen && item.fuente_origen !== '-') fuentes[item.fuente_origen] = (fuentes[item.fuente_origen] || 0) + 1;
});
if (Object.keys(grupos).length > 0) {
const tg = Object.entries(grupos).sort((a,b) => b[1] - a[1])[0];
insights.push('⚠ <strong>Grupo activo:</strong> ' + tg[0] + ' (' + tg[1] + ' IPs detectadas)');
}
if (Object.keys(paises).length > 0) {
const tp = Object.entries(paises).sort((a,b) => b[1] - a[1])[0];
insights.push('🌍 <strong>Origen principal:</strong> ' + tp[0] + ' (' + tp[1] + ' IPs)');
}
if (Object.keys(botnets).length > 0) {
const tb = Object.entries(botnets).sort((a,b) => b[1] - a[1])[0];
insights.push('🔥 <strong>Botnet predominante:</strong> ' + tb[0] + ' (' + tb[1] + ' IPs)');
}
if (Object.keys(fuentes).length > 0) {
const tf = Object.entries(fuentes).sort((a,b) => b[1] - a[1])[0];
insights.push('📡 <strong>Fuente más activa:</strong> ' + tf[0] + ' (' + tf[1] + ' IPs)');
}
if (insights.length === 0) insights.push('✅ No se han detectado amenazas significativas en este período.');
document.getElementById('context-insights').innerHTML = '<ul>' + insights.map(x => '<li>' + x + '</li>').join('') + '</ul>';
}

async function cargarDatos() {
try {
const response = await fetch('/api/ips');
const data = await response.json();
allData = data;
updateStats(data);
updateTimeline(data);
cargarContexto(data);
renderPage();
} catch (error) {
console.error('Error:', error);
}
}

document.getElementById('manual-refresh').addEventListener('click', cargarDatos);
document.querySelectorAll('.filter-btn').forEach(btn => {
btn.addEventListener('click', function() {
document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
this.classList.add('active');
currentFilter = this.dataset.filter;
currentPage = 1;
renderPage();
});
});

setInterval(cargarDatos, 30000);
cargarDatos();
</script>
</body>
</html>
""")

@app.route('/api/ips')
def api_ips():
    try:
        with open(ULTIMAS_IPS_JSON, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    except:
        return jsonify([])

@app.route('/download-json')
def download_json():
    try:
        if not os.path.exists(ULTIMAS_IPS_JSON):
            return "Archivo no disponible", 404
        return send_file(ULTIMAS_IPS_JSON, as_attachment=True, download_name='escaneos_ultimas.json', mimetype='application/json')
    except Exception as e:
        return f"Error: {e}", 404

def iniciar_web():
    ip = obtener_ip_local()
    print(f"\n{VERDE}🌐 Servidor web activo en:{RESET}")
    print(f"   📍 Local:   http://localhost:{PUERTO_WEB}")
    print(f"   📍 Red:     http://{ip}:{PUERTO_WEB}")
    print(f"{AMARILLO}Presiona Ctrl+C para volver al menú{RESET}\n")
    app.run(host='127.0.0.1', port=PUERTO_WEB, debug=False, use_reloader=False)

# ================= CICLO ÚNICO (PRUEBA RÁPIDA) =================
def ciclo_unico():
    print(f"\n{CIAN}{NEGRITA}=== CICLO ÚNICO DE ESCANEO ==={RESET}")
    todas_ips = set()
    fuentes_origen = {}
    for fuente in FUENTES:
        ips = descargar_fuente(fuente)
        for ip in ips:
            todas_ips.add(ip)
            if ip not in fuentes_origen:
                fuentes_origen[ip] = fuente['nombre']
        time.sleep(0.5)
    print(f"\n{VERDE}[{datetime.now().strftime('%H:%M:%S')}] IPs obtenidas: {len(todas_ips)} únicas{RESET}")
    lista = sorted(todas_ips)
    for i, ip in enumerate(lista):
        if '/' in ip:
            print(f"  {i+1:4}. {ip:<18} {AMARILLO}(rango de red){RESET}")
        else:
            geo = geo_ip(ip)
            fuente_ip = fuentes_origen.get(ip, None)
            grupo, botnet, fuente_detectada = obtener_intel(ip, fuente_ip)
            if geo:
                pais = geo.get('pais', '?')[:15]
                asn = geo.get('asn', '')[:12]
                org = geo.get('org', '')[:20]
                grupo_str = f"{ROJO}{grupo}{RESET}" if grupo else "-"
                botnet_str = f"{AMARILLO}{botnet}{RESET}" if botnet else "-"
                print(f"  {i+1:4}. {ip:<18} {VERDE}{pais:<15}{RESET} ASN:{AMARILLO}{asn:<12}{RESET} {AZUL}{org:<20}{RESET} 🔥{botnet_str:<30} 🚩{grupo_str}")
            else:
                print(f"  {i+1:4}. {ip:<18} {AMARILLO}(geolocalización no disponible){RESET}")
        if i >= 49 and len(lista) > 50:
            print(f"\n{AMARILLO}... y {len(lista)-50} más{RESET}")
            break

# ================= ESTADÍSTICAS Y ÚLTIMAS IPS =================
def ver_estadisticas():
    datos = cargar_ultimas_ips()
    if not datos:
        print(f"\n{AMARILLO}No hay datos aún.{RESET}")
        return
    total = len(datos)
    paises = Counter(item['pais'] for item in datos)
    asns = Counter(item['asn'] for item in datos if item['asn'])
    botnets = Counter(item['botnet'] for item in datos if item['botnet'] and item['botnet'] != '-')
    fuentes = Counter(item['fuente_origen'] for item in datos if item.get('fuente_origen'))
    grupos = Counter(item['grupo'] for item in datos if item.get('grupo') and item['grupo'] != '-')

    print(f"\n{CIAN}{NEGRITA}📊 ESTADÍSTICAS DE ESCANEOS{RESET}")
    print(f"Total IPs únicas: {total}")
    print(f"\n{AMARILLO}Top 10 países:{RESET}")
    for pais, cnt in paises.most_common(10):
        print(f"  {pais}: {cnt}")
    print(f"\n{AMARILLO}Top 10 ASN:{RESET}")
    for asn, cnt in asns.most_common(10):
        print(f"  {asn}: {cnt}")
    print(f"\n{AMARILLO}Top 10 botnets:{RESET}")
    for botnet, cnt in botnets.most_common(10):
        print(f"  {botnet}: {cnt}")
    print(f"\n{AMARILLO}Top 10 grupos:{RESET}")
    for grupo, cnt in grupos.most_common(10):
        print(f"  {grupo}: {cnt}")
    print(f"\n{AMARILLO}Top 10 fuentes origen:{RESET}")
    for fuente, cnt in fuentes.most_common(10):
        print(f"  {fuente}: {cnt}")

def ver_ultimas():
    datos = cargar_ultimas_ips()
    if not datos:
        print(f"\n{AMARILLO}No hay datos aún. Ejecuta un ciclo primero.{RESET}")
        return
    print(f"\n{CIAN}{NEGRITA}=== ÚLTIMAS 50 IPs DETECTADAS ==={RESET}")
    for i, item in enumerate(datos[-50:][::-1], 1):
        ip = item['ip']
        pais = item['pais']
        asn = item['asn']
        org = item['org']
        botnet = item['botnet'] or '-'
        grupo = item['grupo'] or '-'
        fuente = item.get('fuente_origen', '-')
        print(f"{i:4}. {ip:<18} {VERDE}{pais:<15}{RESET} ASN:{AMARILLO}{asn:<12}{RESET} {AZUL}{org:<20}{RESET} 🔥{botnet:<30} 🚩{grupo} 📡{fuente}")

def menu_virustotal():
    datos = cargar_ultimas_ips()
    if not datos:
        print(f"{AMARILLO}No hay IPs almacenadas. Ejecuta un ciclo primero.{RESET}")
        return
    ips = {item['ip'] for item in datos}
    generar_enlaces_vt(ips, usar_api=True)

# ================= MENÚ CLI =================
def limpiar():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    print(f"""{VERDE}{NEGRITA}
╔═══════════════════════════════════════════════════════════════════════════════════════╗
║                         ███╗   ██╗███████╗██████╗ ██╗   ██╗██╗      █████╗            ║
║                         ████╗  ██║██╔════╝██╔══██╗██║   ██║██║     ██╔══██╗           ║
║                         ██╔██╗ ██║█████╗  ██████╔╝██║   ██║██║     ███████║           ║
║                         ██║╚██╗██║██╔══╝  ██╔══██╗██║   ██║██║     ██╔══██║           ║
║                         ██║ ╚████║███████╗██████╔╝╚██████╔╝███████╗██║  ██║           ║
║                         ╚═╝  ╚═══╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝           ║
║                                                                                       ║
║                              ███████╗ ██████╗ █████╗ ███╗   ██╗                       ║
║                              ██╔════╝██╔════╝██╔══██╗████╗  ██║                       ║
║                              ███████╗██║     ███████║██╔██╗ ██║                       ║
║                              ╚════██║██║     ██╔══██║██║╚██╗██║                       ║
║                              ███████║╚██████╗██║  ██║██║ ╚████║                       ║
║                              ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                       ║
║                                                                                       ║
║ 🛡 NEBULA ANTISCAN v1.3 – Detector de escaneos agresivos en tiempo real                ║
║ 📊 Formato: IP | País | ASN | Organización | 🔥 botnet | 🚩 grupo                     ║
║ # Puerto 5091 · By Condor2026 - SpectrumSecurity                                      ║
║ # FUENTES: 73 listas negras | INTEL: 80+ feeds | Grupos: APT/Ransomware/Hacktivistas  ║
║ # 130 USER-AGENTS · VT API · Dashboard cyberpunk                                      ║
╚═══════════════════════════════════════════════════════════════════════════════════════╝{RESET}
""")

def menu():
    limpiar()
    banner()
    print(f"{VERDE}╔════════════════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{VERDE}║{RESET}                                                                                        {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}  {VERDE}1.{RESET} 🚀 Iniciar monitor en tiempo real (ciclos de 30s)                                  {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}  {CIAN}2.{RESET} ⚡ Ejecutar un solo ciclo de escaneo (prueba rápida)                               {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}  {AMARILLO}3.{RESET} 📊 Ver estadísticas globales (top países, ASN, botnets, grupos)                    {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}  {AZUL}4.{RESET} 📰 Ver últimas 50 IPs detectadas                                                   {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}  {MAGENTA}5.{RESET} 🌐 Iniciar servidor web (dashboard cyberpunk)                                      {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}  {CIAN}6.{RESET} 🔗 Generar enlaces VirusTotal (con API si hay clave)                              {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}  {ROJO}7.{RESET} 🚪 Salir                                                                           {VERDE}║{RESET}")
    print(f"{VERDE}║{RESET}                                                                                        {VERDE}║{RESET}")
    print(f"{VERDE}╚════════════════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print()

def main():
    actualizar_intel_inicial()
    threading.Thread(target=actualizador_intel_silencioso, daemon=True).start()

    while True:
        menu()
        opc = input(f"{CIAN}➤ Elige una opción: {RESET}").strip()
        if opc == '1':
            monitor_escaneos()
        elif opc == '2':
            ciclo_unico()
            input(f"\n{AMARILLO}Presiona Enter para continuar...{RESET}")
        elif opc == '3':
            ver_estadisticas()
            input(f"\n{AMARILLO}Presiona Enter para continuar...{RESET}")
        elif opc == '4':
            ver_ultimas()
            input(f"\n{AMARILLO}Presiona Enter para continuar...{RESET}")
        elif opc == '5':
            try:
                iniciar_web()
            except KeyboardInterrupt:
                print(f"\n{AMARILLO}Volviendo al menú...{RESET}")
        elif opc == '6':
            menu_virustotal()
            input(f"\n{AMARILLO}Presiona Enter para continuar...{RESET}")
        elif opc == '7':
            print(f"{ROJO}¡Hasta la próxima, cazador!{RESET}")
            break
        else:
            print(f"{ROJO}Opción no válida.{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{ROJO}Saliendo...{RESET}")
        sys.exit(0)
