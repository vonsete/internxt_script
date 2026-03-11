#!/usr/bin/env bash
# ejemplos.sh — Ejemplos de uso del Internxt Drive CLI
# Útil como referencia y para crear scripts de automatización

INTERNXT="python3 $(dirname "$0")/internxt.py"

# ─── Autenticación ────────────────────────────────────────────────────────────

# Opción A: login interactivo (implementa el mismo hash que el SDK oficial)
#   $INTERNXT login

# Opción B: pegar token del navegador (más rápido, sin crypto)
#   $INTERNXT token

# ─── Listar ──────────────────────────────────────────────────────────────────

# Listar la raíz
$INTERNXT ls

# Listar una carpeta específica
$INTERNXT ls /Documentos

# Listar en profundidad (no recursivo, pero puedes encadenar)
$INTERNXT ls /Documentos/Trabajo

# ─── Crear carpetas ───────────────────────────────────────────────────────────

$INTERNXT mkdir /Backups
$INTERNXT mkdir /Backups/2024
$INTERNXT mkdir /Backups/2025/Enero        # los padres deben existir

# ─── Mover y renombrar ────────────────────────────────────────────────────────

# Mover fichero a otra carpeta
$INTERNXT mv /Documentos/informe.pdf /Backups/2024/

# Mover y renombrar en un paso
$INTERNXT mv /Documentos/borrador.docx /Documentos/final.docx

# Mover carpeta entera
$INTERNXT mv /CarpetaVieja /NuevaUbicacion/CarpetaVieja

# Solo renombrar (sin cambiar de carpeta)
$INTERNXT rename /Documentos/viejo-nombre.txt nuevo-nombre.txt

# ─── Eliminar ────────────────────────────────────────────────────────────────

# Mover a papelera (recuperable)
$INTERNXT rm /Documentos/borrar.txt

# Eliminar carpeta (a la papelera)
$INTERNXT rm /CarpetaABorrar

# Eliminar permanentemente (sin papelera)
$INTERNXT rm --permanent /Documentos/definitivo.txt

# ─── Papelera ────────────────────────────────────────────────────────────────

$INTERNXT trash list
$INTERNXT trash clear

# ─── Información de cuenta ────────────────────────────────────────────────────

$INTERNXT info

# ─── Upload / Download (requiere CLI oficial via npm) ─────────────────────────

# Subir un fichero a una carpeta de Internxt
$INTERNXT upload ./foto.jpg /Imágenes/

# Descargar un fichero de Internxt
$INTERNXT download /Documentos/contrato.pdf ./descargas/

# ─── Ejemplos de scripting ────────────────────────────────────────────────────

# Crear estructura de carpetas de forma masiva
for year in 2023 2024 2025; do
    for month in Enero Febrero Marzo Abril Mayo Junio \
                 Julio Agosto Septiembre Octubre Noviembre Diciembre; do
        $INTERNXT mkdir "/Fotos/$year/$month" 2>/dev/null || true
    done
done

# Listar y filtrar sólo PDFs (la API devuelve todos; filtrar en local)
$INTERNXT ls /Documentos | grep "\.pdf"

# Mover múltiples ficheros de un listado
FILES=("informe1.pdf" "informe2.pdf" "informe3.pdf")
for f in "${FILES[@]}"; do
    $INTERNXT mv "/Pendiente/$f" "/Procesado/$f"
done
