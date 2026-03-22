#!/bin/bash
# Instalador para NEBULA ANTISCAN

echo "🔄 Instalando dependencias de Python..."
pip install -r requirements.txt

echo "📁 Creando directorios necesarios..."
mkdir -p datos_escaneos intel_escaneos images

echo "✅ Instalación completa. Ejecuta: python nebula_antiscan.py"
