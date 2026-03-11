#!/usr/bin/env bash
# setup.sh — Instala las dependencias del Internxt Drive CLI
set -e

echo "=== Setup Internxt Drive CLI ==="

# ── Python deps ───────────────────────────────────────────────────────────────
echo ""
echo "1. Instalando dependencias Python…"
pip install -r "$(dirname "$0")/requirements.txt" --quiet
echo "   ✓ Dependencias Python instaladas"

# ── Alias opcional ────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ALIAS_CMD="alias internxt='python3 $SCRIPT_DIR/internxt.py'"

echo ""
echo "2. Para añadir el alias 'internxt' a tu shell, ejecuta:"
echo "   $ALIAS_CMD"
echo ""
echo "   O añádelo a ~/.bashrc / ~/.zshrc:"
echo "   echo \"$ALIAS_CMD\" >> ~/.bashrc"

# ── Opcional: instalar el CLI oficial via npm (para upload/download) ──────────
echo ""
echo "3. (Opcional) Para upload/download de ficheros necesitas el CLI oficial."
echo "   Requiere Node.js >= 22. Si tienes nvm:"
echo ""
echo "     nvm install 22 && nvm use 22"
echo "     npm install -g @internxt/cli"
echo "     internxt login-legacy   # autenticar el CLI oficial por separado"
echo ""

echo "=== Setup completado ==="
echo ""
echo "Primeros pasos:"
echo "  python3 $SCRIPT_DIR/internxt.py login    # autenticar"
echo "  python3 $SCRIPT_DIR/internxt.py ls       # listar archivos"
echo "  python3 $SCRIPT_DIR/internxt.py info     # ver uso de espacio"
