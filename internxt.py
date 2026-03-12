#!/usr/bin/env python3
"""
Internxt Drive CLI
Gestiona archivos en Internxt Drive usando la API web directamente.
Bypassa la restricción de plan del CLI oficial autenticando vía el endpoint web.

Uso:
    python internxt.py login
    python internxt.py ls [/ruta/carpeta]
    python internxt.py mkdir /ruta/nueva-carpeta
    python internxt.py mv /origen/archivo.txt /destino/
    python internxt.py rm /ruta/archivo.txt
    python internxt.py info
    python internxt.py upload /fichero/local /ruta/internxt/
    python internxt.py download /ruta/internxt/archivo.txt ./local/
"""

import argparse
import binascii
import getpass
import hashlib
import json
import os
import sys
import urllib.parse
from pathlib import Path

import requests

# ── Constantes de la API ──────────────────────────────────────────────────────

DRIVE_API  = "https://gateway.internxt.com/drive"
NETWORK_API = "https://gateway.internxt.com/network"

# Constantes criptográficas del CLI oficial (archivo .env.template público)
APP_CRYPTO_SECRET = "6KYQBP847D4ATSFA"
CLIENT_NAME       = "internxt-cli"
CLIENT_VERSION    = "1.6.3"

CONFIG_FILE = Path.home() / ".internxt-tools" / "credentials.json"

# ── Criptografía (CryptoJS-compatible AES + PBKDF2) ──────────────────────────

def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    """OpenSSL EVP_BytesToKey — misma derivación que usa CryptoJS."""
    d, d_i = b"", b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d  += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


def _aes_decrypt_cryptojs(data: str, password: str) -> str:
    """
    Descifra un string cifrado con CryptoJS AES-256-CBC.
    Acepta tanto base64 como hex (el servidor devuelve hex en el campo sKey).
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        _die("Instala las dependencias: pip install -r requirements.txt")

    import base64
    # El servidor puede devolver hex o base64
    try:
        raw = bytes.fromhex(data)
    except ValueError:
        raw = base64.b64decode(data)
    assert raw[:8] == b"Salted__", "Formato de salt inválido"
    salt, ct = raw[8:16], raw[16:]
    key, iv  = _evp_bytes_to_key(password.encode(), salt)
    cipher   = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    plain    = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    pad      = plain[-1]
    return plain[:-pad].decode("utf-8")


def _aes_encrypt_cryptojs(plaintext: str, password: str) -> str:
    """
    Cifra un string con AES-256-CBC (compatible con la implementación Node del SDK).
    IMPORTANTE: devuelve hex, no base64 — así lo hace encryptTextWithKey en el CLI.
    Formato: hex("Salted__" + salt_8bytes + ciphertext)
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        _die("Instala las dependencias: pip install -r requirements.txt")

    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(password.encode(), salt)
    pt = plaintext.encode("utf-8")
    pad_len = 16 - (len(pt) % 16)
    pt += bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    ct = cipher.encryptor().update(pt) + cipher.encryptor().finalize()
    return (b"Salted__" + salt + ct).hex()


def _hash_password(password: str, encrypted_salt: str) -> str:
    """
    Internxt password hashing (igual que el SDK oficial):
    1. Descifra el salt que envía el servidor (cifrado con APP_CRYPTO_SECRET)
    2. Aplica PBKDF2-SHA1 (10000 iteraciones, 32 bytes)
    3. Vuelve a cifrar el resultado para enviarlo al servidor
    """
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        _die("Instala las dependencias: pip install -r requirements.txt")

    plain_salt = _aes_decrypt_cryptojs(encrypted_salt, APP_CRYPTO_SECRET)
    # El salt descifrado es un hex string → convertir a bytes raw (Buffer.from(salt, 'hex') en Node.js)
    salt_bytes = bytes.fromhex(plain_salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,
        salt=salt_bytes,
        iterations=10000,
        backend=default_backend(),
    )
    hash_bytes = kdf.derive(password.encode("utf-8"))
    hash_hex   = binascii.hexlify(hash_bytes).decode()
    return _aes_encrypt_cryptojs(hash_hex, APP_CRYPTO_SECRET)


# ── Cliente HTTP ──────────────────────────────────────────────────────────────

class InternxtClient:
    def __init__(self, token: str, new_token: str | None = None):
        self.token     = token
        self.new_token = new_token or token
        self.session   = requests.Session()
        self.session.headers.update({
            "Authorization":    f"Bearer {self.new_token}",
            "internxt-client":  CLIENT_NAME,
            "internxt-version": CLIENT_VERSION,
            "Content-Type":     "application/json",
        })

    def get(self, path, **kwargs):
        return self._req("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self._req("POST", path, **kwargs)

    def put(self, path, **kwargs):
        return self._req("PUT", path, **kwargs)

    def patch(self, path, **kwargs):
        return self._req("PATCH", path, **kwargs)

    def delete(self, path, **kwargs):
        return self._req("DELETE", path, **kwargs)

    def _req(self, method, path, base=None, **kwargs):
        base = base or DRIVE_API
        url  = f"{base}{path}"
        r    = self.session.request(method, url, **kwargs)
        if not r.ok:
            try:
                err = r.json()
            except Exception:
                err = r.text
            _die(f"Error {r.status_code} en {method} {url}: {err}")
        return r.json() if r.content else {}


# ── Autenticación ─────────────────────────────────────────────────────────────

def _get_security_details(email: str) -> dict:
    """
    Paso 1 del login: obtiene el salt cifrado y si la cuenta tiene 2FA activo.
    El mismo endpoint devuelve ambas cosas en una sola llamada.
    El servidor devuelve el salt en el campo 'sKey' (hex) o 'encryptedSalt' (base64).
    """
    r = requests.post(
        f"{DRIVE_API}/auth/login",
        json={"email": email},
        headers={
            "internxt-client":  CLIENT_NAME,
            "internxt-version": CLIENT_VERSION,
            "Content-Type":     "application/json",
        },
    )
    if not r.ok:
        _die(f"Error al obtener security details: {r.status_code} {r.text}")
    security = r.json()
    salt = security.get("sKey") or security.get("encryptedSalt") or security.get("encrypted_salt")
    if not salt:
        _die(f"Respuesta inesperada del servidor: {security}")
    return security


def _authenticate(email: str, password: str, security: dict, tfa: str | None = None) -> dict:
    """
    Paso 2 del login: hashea la contraseña con el salt ya obtenido y
    obtiene el token usando el endpoint web estándar (NO el CLI-específico,
    que es el que Internxt restringe por plan).
    """
    encrypted_salt = security.get("sKey") or security.get("encryptedSalt") or security.get("encrypted_salt")
    pw_hash = _hash_password(password, encrypted_salt)

    payload = {"email": email, "password": pw_hash}
    if tfa:
        payload["tfa"] = tfa

    r = requests.post(
        f"{DRIVE_API}/auth/login/access",
        json=payload,
        headers={
            "internxt-client":  CLIENT_NAME,
            "internxt-version": CLIENT_VERSION,
            "Content-Type":     "application/json",
        },
    )
    if not r.ok:
        _die(f"Login fallido: {r.status_code} {r.text}")
    return r.json()


def cmd_login(args):
    """Inicia sesión y guarda las credenciales localmente."""
    print("─── Internxt Login ───")
    email    = input("Email: ").strip()
    password = getpass.getpass("Contraseña: ")

    # Una sola llamada: obtiene salt cifrado + flag de 2FA
    security = _get_security_details(email)

    tfa = None
    if security.get("tfa", False):
        tfa = input("Código 2FA: ").strip()

    print("Autenticando…")
    data = _authenticate(email, password, security, tfa)

    token     = data.get("token") or data.get("newToken")
    new_token = data.get("newToken") or token
    user      = data.get("user", {})

    # El mnemónico viene cifrado con la contraseña del usuario — descifrarlo ahora
    # (misma función decryptTextWithKey del SDK)
    encrypted_mnemonic = user.get("mnemonic", "")
    try:
        plain_mnemonic = _aes_decrypt_cryptojs(encrypted_mnemonic, password)
    except Exception:
        plain_mnemonic = encrypted_mnemonic  # si no es AES, guardarlo tal cual

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    creds = {
        "token":            token,
        "new_token":        new_token,
        "email":            email,
        "root_folder_uuid": user.get("rootFolderUuid") or user.get("rootFolderId") or user.get("root_folder_id"),
        "mnemonic":         plain_mnemonic,
        "bucket":           user.get("bucket"),
        "bridge_user":      user.get("bridgeUser"),
        "user_id":          user.get("userId"),
        "user":             user,
    }
    CONFIG_FILE.write_text(json.dumps(creds, indent=2))
    print(f"✓ Sesión iniciada como {email}")
    print(f"  Credenciales guardadas en {CONFIG_FILE}")


def cmd_token(args):
    """Guarda un token extraído manualmente del navegador."""
    print("Para extraer el token del navegador:")
    print("  1. Abre drive.internxt.com y haz login")
    print("  2. Pulsa F12 → Aplicación → Local Storage → drive.internxt.com")
    print("  3. Copia el valor de 'xNewToken' (o 'xToken')")
    print()
    token = input("Pega el token aquí: ").strip()
    if not token:
        _die("Token vacío")

    # Verificar el token obteniendo info del usuario
    r = requests.get(
        f"{DRIVE_API}/users/me",
        headers={
            "Authorization":    f"Bearer {token}",
            "internxt-client":  CLIENT_NAME,
            "internxt-version": CLIENT_VERSION,
        },
    )
    if not r.ok:
        _die(f"Token inválido: {r.status_code}")
    user = r.json()

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    creds = {
        "token":            token,
        "new_token":        token,
        "email":            user.get("email"),
        "root_folder_uuid": user.get("rootFolderUuid"),
        "user":             user,
    }
    CONFIG_FILE.write_text(json.dumps(creds, indent=2))
    print(f"✓ Token guardado para {user.get('email')}")


def _load_creds() -> dict:
    if not CONFIG_FILE.exists():
        _die("No hay sesión iniciada. Ejecuta: python internxt.py login")
    return json.loads(CONFIG_FILE.read_text())


def _client() -> tuple[InternxtClient, dict]:
    creds  = _load_creds()
    client = InternxtClient(creds["token"], creds.get("new_token"))
    return client, creds


# ── Resolución de rutas ───────────────────────────────────────────────────────

def _resolve_path(client: InternxtClient, creds: dict, path: str) -> tuple[str, str, bool]:
    """
    Convierte una ruta tipo '/Documentos/subcarpeta/archivo.txt'
    al UUID de Internxt. Devuelve (uuid, name, is_folder).
    """
    path = path.strip("/")
    if not path:
        uuid = creds["root_folder_uuid"]
        return uuid, "", True

    parts  = path.split("/")
    parent = creds["root_folder_uuid"]

    for i, part in enumerate(parts):
        is_last = i == len(parts) - 1
        found   = None

        # Buscar en subcarpetas
        offset = 0
        while True:
            data = client.get(f"/folders/content/{parent}/folders",
                              params={"limit": 50, "offset": offset})
            items = data if isinstance(data, list) else data.get("folders", [])
            for f in items:
                if f.get("plainName") == part or f.get("name") == part:
                    found = ("folder", f.get("uuid") or f.get("id"), f.get("plainName") or f.get("name"))
                    break
            if found or not items or len(items) < 50:
                break
            offset += 50

        if not found:
            # Buscar en ficheros (solo en el último segmento)
            if is_last:
                offset = 0
                while True:
                    data = client.get(f"/folders/content/{parent}/files",
                                      params={"limit": 50, "offset": offset})
                    items = data if isinstance(data, list) else data.get("files", [])
                    for f in items:
                        fname = f.get("plainName") or f.get("name") or ""
                        if fname == part:
                            found = ("file", f.get("uuid") or f.get("id"), fname)
                            break
                    if found or not items or len(items) < 50:
                        break
                    offset += 50

        if not found:
            _die(f"Ruta no encontrada: /{'/'.join(parts[:i+1])}")

        kind, uuid, name = found
        if not is_last and kind == "file":
            _die(f"'{part}' es un fichero, no una carpeta")
        parent = uuid

    return uuid, name, (kind == "folder")


def _find_file_in_folder(client: InternxtClient, folder_uuid: str, filename: str) -> dict | None:
    """Devuelve el dict del fichero si existe en la carpeta con ese nombre, o None."""
    offset = 0
    while True:
        data  = client.get(f"/folders/content/{folder_uuid}/files",
                           params={"limit": 50, "offset": offset})
        items = data if isinstance(data, list) else data.get("files", [])
        for f in items:
            fname = f.get("plainName") or f.get("name") or ""
            if fname == filename:
                return f
        if not items or len(items) < 50:
            return None
        offset += 50


def _list_folder(client: InternxtClient, uuid: str) -> tuple[list, list]:
    """Devuelve (carpetas, ficheros) de una carpeta por UUID."""
    folders, files = [], []

    offset = 0
    while True:
        data  = client.get(f"/folders/content/{uuid}/folders",
                           params={"limit": 50, "offset": offset})
        items = data if isinstance(data, list) else data.get("folders", [])
        folders.extend(items)
        if not items or len(items) < 50:
            break
        offset += 50

    offset = 0
    while True:
        data  = client.get(f"/folders/content/{uuid}/files",
                           params={"limit": 50, "offset": offset})
        items = data if isinstance(data, list) else data.get("files", [])
        files.extend(items)
        if not items or len(items) < 50:
            break
        offset += 50

    return folders, files


# ── Comandos ──────────────────────────────────────────────────────────────────

def cmd_ls(args):
    client, creds = _client()
    path = getattr(args, "path", None) or "/"
    uuid, name, is_folder = _resolve_path(client, creds, path)
    if not is_folder:
        _die(f"'{path}' es un fichero, no una carpeta")

    folders, files = _list_folder(client, uuid)
    print(f"📁  {path or '/'}")
    for f in sorted(folders, key=lambda x: (x.get("plainName") or x.get("name") or "").lower()):
        print(f"  📁  {f.get('plainName') or f.get('name')}/")
    for f in sorted(files, key=lambda x: (x.get("plainName") or x.get("name") or "").lower()):
        size  = int(f.get("size") or 0)
        sz    = _human_size(size)
        fname = f.get("plainName") or f.get("name") or ""
        print(f"  📄  {fname:<40} {sz:>8}")
    print(f"\n  {len(folders)} carpetas, {len(files)} ficheros")


def cmd_mkdir(args):
    client, creds = _client()
    path = args.path.strip("/")
    if not path:
        _die("Ruta no válida")

    parts  = path.split("/")
    name   = parts[-1]
    parent_path = "/".join(parts[:-1])

    if parent_path:
        parent_uuid, _, is_folder = _resolve_path(client, creds, parent_path)
        if not is_folder:
            _die(f"'{parent_path}' no es una carpeta")
    else:
        parent_uuid = creds["root_folder_uuid"]

    # Obtener el ID numérico del padre (necesario para createFolder)
    parent_meta = client.get(f"/folders/{parent_uuid}/meta")
    parent_id   = parent_meta.get("id")

    result = client.post("/folders", json={
        "name":             name,
        "plainName":        name,
        "parentId":         parent_id,
        "parentFolderUuid": parent_uuid,
    })
    print(f"✓ Carpeta creada: /{path}")
    if args.verbose:
        print(json.dumps(result, indent=2))


def cmd_mv(args):
    client, creds = _client()
    src_path = args.src.strip("/")
    dst_path = args.dst.strip("/")

    src_uuid, src_name, src_is_folder = _resolve_path(client, creds, src_path)

    # El destino puede ser una carpeta existente o una nueva ruta (con renombrado)
    dst_parts       = dst_path.split("/")
    dst_parent_path = "/".join(dst_parts[:-1])
    dst_name        = dst_parts[-1]

    # Intentar resolver el destino como carpeta existente
    try:
        dst_uuid, _, dst_is_folder = _resolve_path(client, creds, dst_path)
        if dst_is_folder:
            # mv archivo.txt /carpeta_destino/  → mover dentro
            target_folder_uuid = dst_uuid
            new_name           = None
        else:
            _die(f"El destino '{dst_path}' ya existe y es un fichero")
    except SystemExit:
        # El destino no existe → la carpeta padre debe existir, y el último segmento es el nuevo nombre
        if dst_parent_path:
            target_uuid, _, is_folder = _resolve_path(client, creds, dst_parent_path)
            if not is_folder:
                _die(f"'{dst_parent_path}' no es una carpeta")
            target_folder_uuid = target_uuid
        else:
            target_folder_uuid = creds["root_folder_uuid"]
        new_name = dst_name

    if src_is_folder:
        client.patch(f"/folders/{src_uuid}", json={"destinationFolder": target_folder_uuid})
        if new_name and new_name != src_name:
            client.put(f"/folders/{src_uuid}/meta", json={"plainName": new_name})
    else:
        client.patch(f"/files/{src_uuid}", json={"destinationFolder": target_folder_uuid})
        if new_name and new_name != src_name:
            client.put(f"/files/{src_uuid}/meta", json={"plainName": new_name})

    print(f"✓ Movido: /{src_path} → /{dst_path}")


def cmd_rename(args):
    client, creds = _client()
    path    = args.path.strip("/")
    newname = args.newname

    uuid, _, is_folder = _resolve_path(client, creds, path)
    if is_folder:
        client.put(f"/folders/{uuid}/meta", json={"plainName": newname})
    else:
        client.put(f"/files/{uuid}/meta", json={"plainName": newname})
    print(f"✓ Renombrado a '{newname}'")


def cmd_rm(args):
    client, creds = _client()
    path = args.path.strip("/")
    uuid, name, is_folder = _resolve_path(client, creds, path)

    if args.permanent:
        item_type = "folder" if is_folder else "file"
        client.delete("/storage/trash", json={
            "items": [{"uuid": uuid, "type": item_type}]
        })
        print(f"✓ Eliminado permanentemente: /{path}")
    else:
        item_type = "folder" if is_folder else "file"
        client.post("/storage/trash/add", json={
            "items": [{"uuid": uuid, "type": item_type}]
        })
        print(f"✓ Movido a la papelera: /{path}")
        print("  (usa --permanent para eliminar definitivamente)")


def cmd_trash(args):
    client, creds = _client()
    sub = getattr(args, "trash_cmd", "list")

    if sub == "list":
        all_items = []
        for item_type in ("files", "folders"):
            offset = 0
            limit = 50
            while True:
                data = client.get(
                    f"/storage/trash/paginated?limit={limit}&offset={offset}&type={item_type}&root=true"
                )
                chunk = (data if isinstance(data, list)
                         else data.get("result", data.get("items", [])))
                for it in chunk:
                    it["_kind"] = item_type
                all_items.extend(chunk)
                if len(chunk) < limit:
                    break
                offset += limit
        if not all_items:
            print("La papelera está vacía.")
            return
        print(f"🗑️  Papelera ({len(all_items)} elementos):")
        for it in all_items:
            name = it.get("plainName") or it.get("name") or it.get("id")
            kind = "folder" if it.get("_kind") == "folders" else "file"
            deleted_at = it.get("deletedAt", "")[:10]
            print(f"  {'📁' if kind == 'folder' else '📄'}  {name}  [{kind}]  {deleted_at}  id={it.get('uuid') or it.get('id')}")

    elif sub == "clear":
        client.delete("/storage/trash/all")
        print("✓ Papelera vaciada")

    elif sub == "restore":
        if not args.id:
            _die("Indica el ID del elemento: internxt.py trash restore <id>")
        client.post(f"/storage/trash/restore/file", json={"fileId": args.id})
        print(f"✓ Restaurado: {args.id}")


def cmd_info(args):
    client, creds = _client()
    try:
        usage = client.get("/users/usage")
        limit = client.get("/users/limit")
    except SystemExit:
        # Fallback endpoints
        usage = client.get("/usage")
        limit = client.get("/limit")

    used      = usage.get("total", usage.get("drive", 0))
    max_bytes = limit.get("maxSpaceBytes", limit.get("maxSpace", 0))
    pct       = (used / max_bytes * 100) if max_bytes else 0

    email = creds.get("email", "?")
    print(f"👤  {email}")
    print(f"💾  Usado:     {_human_size(used)}")
    print(f"📦  Total:     {_human_size(max_bytes)}")
    print(f"📊  Ocupado:   {pct:.1f}%")


def cmd_versions(args):
    """Gestiona versiones de un fichero (listar, restaurar, eliminar)."""
    client, creds = _client()
    sub  = getattr(args, "versions_cmd", None) or "list"

    # Comprobar si el plan tiene versioning habilitado
    limits = client.get("/files/limits")
    versioning = limits.get("versioning", {})
    if not versioning.get("enabled"):
        _die(
            "El versionado de ficheros no está disponible en tu plan actual.\n"
            "  Actívalo en: https://drive.internxt.com/settings/account"
        )

    path = args.path.strip("/")
    uuid, _, is_folder = _resolve_path(client, creds, path)
    if is_folder:
        _die(f"'{args.path}' es una carpeta, no un fichero")

    if sub == "list":
        versions = client.get(f"/files/{uuid}/versions")
        if not versions:
            print("Este fichero no tiene versiones previas.")
            return
        print(f"📋  Versiones de /{path}:")
        for v in versions:
            vid      = v.get("id")
            size     = _human_size(int(v.get("size") or 0))
            created  = (v.get("createdAt") or "")[:19].replace("T", " ")
            expires  = (v.get("expiresAt") or "")[:10]
            print(f"  {vid}  {size:>8}  {created}  (expira: {expires})")
        print(f"\n  {len(versions)} versión(es)")

    elif sub == "restore":
        vid = args.version_id
        result = client.post(f"/files/{uuid}/versions/{vid}/restore")
        print(f"✓ Versión {vid} restaurada")
        if getattr(args, "verbose", False):
            print(json.dumps(result, indent=2))

    elif sub == "delete":
        vid = args.version_id
        client.delete(f"/files/{uuid}/versions/{vid}")
        print(f"✓ Versión {vid} eliminada")


def _network_headers(bridge_user: str, user_id: str) -> dict:
    """
    Basic Auth para el Network API.
    user: bridgeUser (email)
    pass: sha256(userId) — donde userId es el hash bcrypt del usuario
    Igual que: sha256(Buffer.from(creds.pass)) en inxt-js/uploadFileV2
    """
    import base64, hashlib
    bridge_pass = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
    token = base64.b64encode(f"{bridge_user}:{bridge_pass}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "internxt-client":  CLIENT_NAME,
        "internxt-version": CLIENT_VERSION,
        "Content-Type": "application/json",
    }


def _derive_file_key(mnemonic: str, bucket_id: str, index_bytes: bytes) -> bytes:
    """
    Derivación de clave de fichero (GenerateFileKey en inxt-js):
      seed       = PBKDF2-SHA512(mnemonic, salt=b'mnemonic', iter=2048, len=64)
      bucket_key = SHA512(seed + bytes.fromhex(bucket_id))
      file_key   = SHA512(bucket_key[:32] + index_bytes)[:32]
    """
    import hashlib
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048, 64)
    bucket_key = hashlib.sha512(seed + bytes.fromhex(bucket_id)).digest()
    file_key   = hashlib.sha512(bucket_key[:32] + index_bytes).digest()[:32]
    return file_key


def _aes256ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def _aes256ctr_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def _content_hash(data: bytes) -> str:
    """RIPEMD160(SHA256(data)) — hash que espera el Network API."""
    import hashlib
    sha = hashlib.sha256(data).digest()
    rmd = hashlib.new("ripemd160", sha).digest()
    return rmd.hex()


def cmd_upload(args):
    """Subida nativa de ficheros con cifrado E2E (AES-256-CTR + clave derivada del mnemónico)."""
    creds  = _load_creds()
    client = InternxtClient(creds["token"], creds.get("new_token"))

    local_path = Path(args.local)
    if not local_path.exists():
        _die(f"Fichero no encontrado: {local_path}")
    if local_path.is_dir():
        _die("El comando upload es para ficheros, no carpetas")

    mnemonic    = creds.get("mnemonic", "")
    bucket_id   = creds.get("bucket") or creds["user"].get("bucket")
    bridge_user = creds.get("bridge_user") or creds["user"].get("bridgeUser")
    user_id     = creds.get("user_id") or creds["user"].get("userId")

    if not mnemonic or not bucket_id or not user_id:
        _die("Faltan credenciales de red. Vuelve a hacer login: python internxt.py login")

    # Resolver carpeta destino
    remote = args.remote.strip("/") if args.remote and args.remote != "/" else ""
    if remote:
        folder_uuid, _, is_folder = _resolve_path(client, creds, remote)
        if not is_folder:
            _die(f"'{args.remote}' no es una carpeta")
    else:
        folder_uuid = creds["root_folder_uuid"]

    file_size = local_path.stat().st_size
    file_name = local_path.name
    file_ext  = local_path.suffix.lstrip(".")
    plain_name = local_path.stem if file_ext else file_name

    print(f"↑  {local_path.name}  ({_human_size(file_size)})")

    # 1. Leer y cifrar el fichero
    print("   Cifrando…")
    index_bytes  = os.urandom(32)                          # 32 bytes aleatorios
    iv           = index_bytes[:16]                        # primeros 16 = IV
    file_key     = _derive_file_key(mnemonic, bucket_id, index_bytes)
    raw_data     = local_path.read_bytes()
    encrypted    = _aes256ctr_encrypt(raw_data, file_key, iv)
    file_hash    = _content_hash(encrypted)
    index_hex    = index_bytes.hex()                       # 64-char hex

    # 2. Iniciar subida en el Network API
    net_headers = _network_headers(bridge_user, user_id)
    r = requests.post(
        f"{NETWORK_API}/v2/buckets/{bucket_id}/files/start?multiparts=1",
        json={"uploads": [{"index": 0, "size": file_size}]},
        headers=net_headers,
    )
    if not r.ok:
        _die(f"Error al iniciar subida: {r.status_code} {r.text}")
    upload_info = r.json()["uploads"][0]
    upload_url  = upload_info["url"]
    shard_uuid  = upload_info["uuid"]

    # 3. Subir el contenido cifrado al URL de almacenamiento
    print("   Subiendo…")
    put_r = requests.put(
        upload_url,
        data=encrypted,
        headers={"Content-Type": "application/octet-stream",
                 "Content-Length": str(len(encrypted))},
    )
    if not put_r.ok:
        _die(f"Error al subir datos: {put_r.status_code} {put_r.text}")

    # 4. Finalizar subida en el Network API → obtiene fileId
    r2 = requests.post(
        f"{NETWORK_API}/v2/buckets/{bucket_id}/files/finish",
        json={"index": index_hex, "shards": [{"hash": file_hash, "uuid": shard_uuid}]},
        headers=net_headers,
    )
    if not r2.ok:
        _die(f"Error al finalizar subida: {r2.status_code} {r2.text}")
    file_id = r2.json().get("id") or r2.json().get("fileId")

    # 5. Registrar el fichero en el Drive API (o reemplazar si ya existe → crea versión)
    import datetime
    now = datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")

    existing = _find_file_in_folder(client, folder_uuid, file_name)
    if existing:
        existing_uuid = existing.get("uuid") or existing.get("id")
        replace_payload = {
            "fileId":           file_id,
            "size":             file_size,
            "modificationTime": now,
        }
        result = client.put(f"/files/{existing_uuid}", json=replace_payload)
        print(f"✓  Actualizado (versión creada): {file_name}  (id: {existing_uuid})")
    else:
        drive_payload = {
            "name":             file_name,
            "plainName":        file_name,
            "bucket":           bucket_id,
            "fileId":           file_id,
            "encryptVersion":   "Aes03",
            "folderUuid":       folder_uuid,
            "size":             file_size,
            "type":             file_ext or "",
            "modificationTime": now,
            "date":             now,
        }
        result = client.post("/files", json=drive_payload)
        print(f"✓  Subido: {file_name}  (id: {result.get('uuid') or file_id})")


def cmd_download(args):
    """Descarga nativa de ficheros con descifrado E2E (AES-256-CTR)."""
    creds  = _load_creds()
    client = InternxtClient(creds["token"], creds.get("new_token"))

    mnemonic    = creds.get("mnemonic", "")
    bucket_id   = creds.get("bucket") or creds["user"].get("bucket")
    bridge_user = creds.get("bridge_user") or creds["user"].get("bridgeUser")
    user_id     = creds.get("user_id") or creds["user"].get("userId")

    if not mnemonic or not bucket_id or not user_id:
        _die("Faltan credenciales de red. Vuelve a hacer login: python internxt.py login")

    remote = args.remote.strip("/")
    uuid, fname, is_folder = _resolve_path(client, creds, remote)
    if is_folder:
        _die("El comando download es para ficheros, no carpetas")

    # Obtener metadata del fichero (fileId, size, bucket)
    meta    = client.get(f"/files/{uuid}/meta")
    file_id = meta.get("fileId") or meta.get("file_id")
    size    = int(meta.get("size") or 0)
    fbucket = meta.get("bucket") or bucket_id

    print(f"↓  {fname or remote.split('/')[-1]}  ({_human_size(size)})")

    # Obtener links de descarga del Network API
    net_headers = _network_headers(bridge_user, user_id)
    r = requests.get(
        f"{NETWORK_API}/buckets/{fbucket}/files/{file_id}/info",
        headers={**net_headers, "x-api-version": "2"},
    )
    if not r.ok:
        _die(f"Error al obtener info de descarga: {r.status_code} {r.text}")
    info       = r.json()
    index_hex  = info.get("index")
    shards     = info.get("shards", [])

    if not index_hex or not shards:
        _die(f"Respuesta inesperada del network: {info}")

    # Derivar clave
    index_bytes = bytes.fromhex(index_hex)
    iv          = index_bytes[:16]
    file_key    = _derive_file_key(mnemonic, fbucket, index_bytes)

    # Descargar shards (ordenados por index)
    shards_sorted = sorted(shards, key=lambda s: s.get("index", 0))
    print("   Descargando…")
    encrypted_chunks = []
    for shard in shards_sorted:
        shard_url = shard.get("url") or shard.get("farmer", {}).get("address")
        if not shard_url:
            _die(f"Shard sin URL: {shard}")
        resp = requests.get(shard_url)
        if not resp.ok:
            _die(f"Error al descargar shard: {resp.status_code}")
        encrypted_chunks.append(resp.content)

    encrypted = b"".join(encrypted_chunks)

    # Descifrar
    print("   Descifrando…")
    decrypted = _aes256ctr_decrypt(encrypted, file_key, iv)

    # Guardar
    dest_path = Path(args.dest)
    if dest_path.is_dir():
        dest_path = dest_path / (fname or remote.split("/")[-1])
    dest_path.write_bytes(decrypted)
    print(f"✓  Guardado en: {dest_path}")


# ── Utilidades ────────────────────────────────────────────────────────────────

def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


def _die(msg: str):
    print(f"✗ {msg}", file=sys.stderr)
    sys.exit(1)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Internxt Drive CLI — gestión de archivos sin plan premium",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python internxt.py login                         # iniciar sesión
  python internxt.py token                         # guardar token del navegador
  python internxt.py ls                            # listar raíz
  python internxt.py ls /Documentos/Trabajo
  python internxt.py mkdir /Documentos/NuevaCarpeta
  python internxt.py mv /origen/doc.pdf /Documentos/
  python internxt.py mv /origen/doc.pdf /Documentos/doc-renombrado.pdf
  python internxt.py rename /Documentos/viejo.txt nuevo.txt
  python internxt.py rm /Documentos/borrar.txt
  python internxt.py rm --permanent /Documentos/borrar.txt
  python internxt.py trash list
  python internxt.py trash clear
  python internxt.py info
  python internxt.py upload ./foto.jpg /Imágenes/
  python internxt.py download /Documentos/doc.pdf ./local/
  python internxt.py versions /Documentos/informe.pdf
  python internxt.py versions /Documentos/informe.pdf list
  python internxt.py versions /Documentos/informe.pdf restore <versionId>
  python internxt.py versions /Documentos/informe.pdf delete <versionId>
        """,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # login
    sub.add_parser("login", help="Iniciar sesión con email/contraseña")
    sub.add_parser("token", help="Guardar token extraído del navegador")

    # ls
    ls_p = sub.add_parser("ls", help="Listar carpeta")
    ls_p.add_argument("path", nargs="?", default="/", help="Ruta de la carpeta")

    # mkdir
    mk_p = sub.add_parser("mkdir", help="Crear carpeta")
    mk_p.add_argument("path")
    mk_p.add_argument("-v", "--verbose", action="store_true")

    # mv
    mv_p = sub.add_parser("mv", help="Mover/renombrar fichero o carpeta")
    mv_p.add_argument("src", help="Ruta origen")
    mv_p.add_argument("dst", help="Ruta destino (carpeta o nueva ruta con nombre)")

    # rename
    rn_p = sub.add_parser("rename", help="Renombrar (solo el nombre, no la ruta)")
    rn_p.add_argument("path", help="Ruta del elemento")
    rn_p.add_argument("newname", help="Nuevo nombre")

    # rm
    rm_p = sub.add_parser("rm", help="Eliminar (por defecto a la papelera)")
    rm_p.add_argument("path")
    rm_p.add_argument("--permanent", "-f", action="store_true",
                       help="Eliminar definitivamente (sin papelera)")

    # trash
    tr_p  = sub.add_parser("trash", help="Gestionar papelera")
    tr_sub = tr_p.add_subparsers(dest="trash_cmd", required=False)
    tr_sub.add_parser("list",    help="Listar papelera")
    tr_sub.add_parser("clear",   help="Vaciar papelera")
    rs_p  = tr_sub.add_parser("restore", help="Restaurar elemento")
    rs_p.add_argument("id", help="UUID del elemento a restaurar")

    # info
    sub.add_parser("info", help="Ver uso de almacenamiento")

    # versions
    vr_p  = sub.add_parser("versions", help="Gestionar versiones de un fichero (pdf, docx, xlsx, csv)")
    vr_p.add_argument("path", help="Ruta del fichero en Internxt")
    vr_sub = vr_p.add_subparsers(dest="versions_cmd", required=False)
    vr_sub.add_parser("list", help="Listar versiones (por defecto)")
    vs_p = vr_sub.add_parser("restore", help="Restaurar una versión")
    vs_p.add_argument("version_id", help="ID de la versión")
    vs_p.add_argument("-v", "--verbose", action="store_true")
    vd_p = vr_sub.add_parser("delete", help="Eliminar una versión")
    vd_p.add_argument("version_id", help="ID de la versión")

    # upload
    up_p = sub.add_parser("upload", help="Subir fichero local a Internxt")
    up_p.add_argument("local",  help="Ruta local del fichero")
    up_p.add_argument("remote", nargs="?", default="/", help="Carpeta destino en Internxt (por defecto: raíz)")

    # download
    dl_p = sub.add_parser("download", help="Descargar fichero de Internxt")
    dl_p.add_argument("remote", help="Ruta del fichero en Internxt")
    dl_p.add_argument("dest",   nargs="?", default=".", help="Carpeta local destino")

    args = p.parse_args()
    dispatch = {
        "login":    cmd_login,
        "token":    cmd_token,
        "ls":       cmd_ls,
        "mkdir":    cmd_mkdir,
        "mv":       cmd_mv,
        "rename":   cmd_rename,
        "rm":       cmd_rm,
        "trash":    cmd_trash,
        "info":     cmd_info,
        "upload":   cmd_upload,
        "download": cmd_download,
        "versions": cmd_versions,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    main()
