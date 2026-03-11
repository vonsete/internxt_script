# Internxt Drive CLI — Documentación Técnica Completa

> **Propósito de este documento**: registro exhaustivo de todo el proceso de ingeniería
> inversa, análisis de fuentes y desarrollo que permitió construir un CLI Python nativo
> capaz de gestionar Internxt Drive sin depender del CLI oficial de pago.

---

## Índice

1. [Contexto y motivación](#1-contexto-y-motivación)
2. [Fuentes de información](#2-fuentes-de-información)
3. [La restricción de Internxt](#3-la-restricción-de-internxt)
4. [Autenticación — ingeniería inversa completa](#4-autenticación--ingeniería-inversa-completa)
5. [Criptografía de contraseñas](#5-criptografía-de-contraseñas)
6. [Tokens y headers HTTP](#6-tokens-y-headers-http)
7. [API REST de Drive](#7-api-rest-de-drive)
8. [Cifrado E2E de ficheros](#8-cifrado-e2e-de-ficheros)
9. [Protocolo de subida (upload)](#9-protocolo-de-subida-upload)
10. [Protocolo de descarga (download)](#10-protocolo-de-descarga-download)
11. [Gestión de la papelera](#11-gestión-de-la-papelera)
12. [Bugs encontrados y cómo se resolvieron](#12-bugs-encontrados-y-cómo-se-resolvieron)
13. [Mapa de endpoints verificados](#13-mapa-de-endpoints-verificados)

---

## 1. Contexto y motivación

Internxt es un servicio de almacenamiento en la nube con cifrado de extremo a extremo
(E2E). A mediados de 2024/2025, Internxt restringió su CLI oficial
(`@internxt/cli`, publicado en npm) de manera que el endpoint de autenticación
específico para CLI — `/auth/cli/login/access` — sólo responde con éxito a cuentas
con plan de pago. Los usuarios del plan gratuito reciben un error de autorización al
intentar autenticarse desde el CLI oficial.

El objetivo fue crear un CLI alternativo en Python que:

- Autentique al usuario usando el mismo protocolo criptográfico del SDK oficial,
  pero apuntando al endpoint web en lugar del CLI-específico.
- Implemente nativamente el cifrado E2E de ficheros en Python.
- No requiera Node.js para operaciones básicas de gestión (ls, mkdir, mv, rm, etc.).
- Sea completamente transparente en su funcionamiento.

---

## 2. Fuentes de información

### 2.1 Código fuente oficial publicado en GitHub (público)

Internxt publica su SDK y aplicaciones bajo licencias AGPL/MIT en GitHub. Se
analizaron los siguientes repositorios:

| Repositorio | Qué se extrajo |
|---|---|
| `internxt/sdk` (`@internxt/sdk`) | Implementación de la crypto, endpoints de auth, modelos de datos |
| `internxt/inxt-js` | Implementación de subida/descarga de ficheros, derivación de claves |
| `internxt/cli` (`@internxt/cli`) | Flujo de autenticación CLI, constantes, estructura de comandos |
| `internxt/drive-web` | Confirmación de endpoints y comportamiento de la web app |

### 2.2 Paquete npm instalado localmente

Para analizar código compilado y confirmado que se ejecuta en producción, se instaló
el SDK de Internxt en un directorio de prueba:

```bash
mkdir /tmp/internxt-sdk-test
cd /tmp/internxt-sdk-test
npm install @internxt/sdk @internxt/cli
```

Esto permitió leer los ficheros `.js` compilados en
`node_modules/@internxt/sdk/dist/` y `node_modules/@internxt/cli/dist/`, que
contienen el código que realmente se ejecuta. Cuando el código TypeScript fuente
resultaba ambiguo, el `.js` compilado era la fuente definitiva.

### 2.3 Inspección de tráfico de red (DevTools del navegador)

Para confirmar el comportamiento real de la API, se utilizaron las herramientas de
desarrollador de Firefox/Chrome sobre `drive.internxt.com`:

- **Network tab**: para ver las peticiones HTTP reales que hace la web app,
  incluyendo headers, cuerpos de petición y respuesta.
- **Application > Local Storage**: para extraer los tokens JWT y confirmar los
  nombres de campos (`xToken`, `xNewToken`).

Este método fue especialmente útil para confirmar el nombre exacto del campo del
salt (`sKey` vs `encryptedSalt`) y la estructura de la respuesta del servidor, ya
que el código fuente a veces tiene abstracciones que oscurecen el contrato HTTP real.

### 2.4 Exploración iterativa (prueba y error)

Para endpoints no documentados (como la papelera), se realizaron peticiones
HTTP directas con `requests` de Python, analizando códigos de error y mensajes de
respuesta para inferir el comportamiento esperado.

---

## 3. La restricción de Internxt

### El problema técnico

El CLI oficial usa el endpoint:
```
POST https://gateway.internxt.com/drive/auth/cli/login/access
```

Este endpoint devuelve `403 Forbidden` a usuarios sin plan premium. Internxt
implementa la restricción en el servidor: valida el plan del usuario antes de
emitir el token.

### La solución

La aplicación web de Internxt usa un endpoint diferente para autenticarse:
```
POST https://gateway.internxt.com/drive/auth/login/access
```

Este endpoint **no tiene la restricción de plan**. El protocolo de autenticación
(parámetros, crypto) es idéntico en ambos endpoints. La única diferencia es la URL.

Descubrir esto fue inmediato al inspeccionar el tráfico de red del navegador al
hacer login en `drive.internxt.com`. La petición de autenticación va a
`/auth/login/access`, no a `/auth/cli/login/access`.

---

## 4. Autenticación — ingeniería inversa completa

### 4.1 Paso 1: obtención del salt cifrado

**Endpoint**:
```
POST /drive/auth/login
Body: {"email": "usuario@ejemplo.com"}
```

**Fuente**: `@internxt/sdk/dist/auth/index.js`, método `login()`:
```javascript
login(payload) {
    return this.client.post('/auth/login', { email: payload.email }, this.headers());
}
```

**Respuesta del servidor** (campos relevantes):
```json
{
  "sKey": "53616c7465645f5f...",
  "tfa": true,
  "hasKeys": true,
  "hasKyberKeys": true,
  "hasEccKeys": true
}
```

**Análisis del campo `sKey`**:

El campo se llama `sKey` en la versión actual del servidor (no `encryptedSalt` como
aparece en algunas versiones del SDK). El valor es una cadena hexadecimal que, al
decodificarse, empieza por `Salted__` (los primeros 8 bytes en ASCII), que es el
formato OpenSSL/CryptoJS de datos cifrados con AES-CBC.

El código Python implementa fallback para ambos nombres de campo:
```python
salt = security.get("sKey") or security.get("encryptedSalt") or security.get("encrypted_salt")
```

**Campo `tfa`**:

Indica si la cuenta tiene autenticación de dos factores activa. Si es `true`, hay
que pedirle al usuario el código TOTP antes de proceder. Este campo se obtiene en la
misma llamada del paso 1, evitando una petición adicional.

### 4.2 Paso 2: autenticación con hash de contraseña

**Endpoint**:
```
POST /drive/auth/login/access
Body: {"email": "...", "password": "<hash_cifrado>", "tfa": "<código_2fa_opcional>"}
```

**Fuente**: `@internxt/sdk/dist/auth/index.js`, método `loginAccess()`.

**Campo `tfa`**: Este fue uno de los errores iniciales. El SDK usa el campo `tfa` en
el body de la petición (no `twoFactorCode` como se podría intuir, ni `totpCode`, ni
`otp`). Verificado en el código compilado del SDK:
```javascript
const payload = { email, password, tfa }
return this.client.post('/auth/login/access', payload, this.headers())
```

**Respuesta exitosa**:
```json
{
  "token": "<jwt_legacy>",
  "newToken": "<jwt_nuevo>",
  "user": {
    "uuid": "...",
    "email": "...",
    "mnemonic": "<mnemónico_cifrado_en_AES>",
    "bucket": "<bucket_id_hex>",
    "bridgeUser": "usuario@ejemplo.com",
    "userId": "$2a$08$...",
    "rootFolderUuid": "...",
    "rootFolderId": "...",
    ...
  }
}
```

---

## 5. Criptografía de contraseñas

Este es el núcleo más complejo del sistema. Internxt no transmite la contraseña
en claro ni con un simple hash. El proceso implica tres capas criptográficas.

### 5.1 Capa externa: AES-256-CBC compatible con CryptoJS

**Fuente**: `@internxt/sdk/src/shared/utils/encryptionUtils.ts`:
```typescript
export function encryptTextWithKey(textToEncrypt: string, key: string): string {
  const bytes = CryptoJS.AES.encrypt(textToEncrypt, key);
  return bytes.toString();  // devuelve base64 en CryptoJS estándar
}
```

Sin embargo, el CLI devuelve **hex**, no base64. Esto se descubrió al analizar
el código compilado `.js` en `node_modules/@internxt/cli/dist/`, donde la función
`encryptTextWithKey` tenía una implementación ligeramente distinta que producía hex.
El servidor rechazaba base64 con error `401 Unauthorized`.

**Implementación Python** (`_aes_encrypt_cryptojs`):
```python
def _aes_encrypt_cryptojs(plaintext: str, password: str) -> str:
    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(password.encode(), salt)
    # ... cifrado AES-CBC con PKCS7 padding ...
    return (b"Salted__" + salt + ct).hex()  # hex, no base64
```

**Formato del ciphertext** (OpenSSL "Salted" format):
```
Salted__ | salt(8 bytes) | ciphertext
53616c74 | 6564 5f5f | <8 bytes aleatorios> | <AES-CBC output>
```

**Derivación de clave**: OpenSSL EVP_BytesToKey con MD5 (no SHA-256, no PBKDF2):
```python
def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    d, d_i = b"", b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d  += d_i
    return d[:key_len], d[key_len:key_len + iv_len]
```
Esto produce una clave AES de 256 bits y un IV de 128 bits. Es la derivación de
clave que usa CryptoJS por defecto (herencia del formato OpenSSL).

**Constante `APP_CRYPTO_SECRET`**: `"6KYQBP847D4ATSFA"`. Extraída del fichero
`.env.template` del repositorio `internxt/cli` en GitHub, que es público. Esta
constante se usa como "contraseña" para el AES que cifra/descifra el salt y el
hash de contraseña. Es una constante hardcodeada en todos los clientes oficiales.

### 5.2 Capa media: PBKDF2-SHA1

**Fuente**: `@internxt/sdk/src/shared/utils/passToHash.ts`:
```typescript
export function passToHash(passObject: PassObjectInterface): HashObjectInterface {
  try {
    const salt = passObject.salt
      ? CryptoJS.enc.Hex.parse(passObject.salt)
      : CryptoJS.lib.WordArray.random(128 / 8);
    const hash = CryptoJS.PBKDF2(passObject.password, salt, {
      keySize: 256 / 32,
      iterations: 10000,
    });
    return { salt: salt.toString(), hash: hash.toString() };
  } catch { ... }
}
```

El bug crítico aquí fue la **interpretación del salt**:

`CryptoJS.enc.Hex.parse(salt)` convierte el string hexadecimal a bytes crudos,
equivalente a `Buffer.from(salt, 'hex')` en Node.js.

La primera implementación Python usaba `plain_salt.encode('utf-8')`, que interpreta
el string hex como texto ASCII (32 bytes de caracteres `0-9a-f`). Esto produce
un PBKDF2 completamente diferente.

**Implementación correcta**:
```python
plain_salt = _aes_decrypt_cryptojs(encrypted_salt, APP_CRYPTO_SECRET)
salt_bytes = bytes.fromhex(plain_salt)   # Buffer.from(salt, 'hex') en Node.js
kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=salt_bytes, iterations=10000)
hash_bytes = kdf.derive(password.encode("utf-8"))
hash_hex = hash_bytes.hex()              # 64-char hex string
```

**Por qué SHA1**: CryptoJS.PBKDF2 usa SHA1 por defecto, no SHA256 ni SHA512. Es
un detalle de implementación heredado. La seguridad viene del número de iteraciones
y de la capa adicional de AES, no del algoritmo HMAC.

### 5.3 Flujo completo de `_hash_password`

```
contraseña_usuario (texto plano)
        ↓
[paso 1] Servidor devuelve sKey (hex)
        ↓
[paso 2] AES_decrypt(sKey, APP_CRYPTO_SECRET) → salt_hex (string hex, ~32 chars)
        ↓
[paso 3] bytes.fromhex(salt_hex) → salt_bytes (16 bytes raw)
        ↓
[paso 4] PBKDF2-SHA1(password, salt_bytes, iter=10000, len=32) → hash_bytes (32 bytes)
        ↓
[paso 5] hash_bytes.hex() → hash_hex (64-char hex string)
        ↓
[paso 6] AES_encrypt(hash_hex, APP_CRYPTO_SECRET) → pw_hash (hex string)
        ↓
[envío] POST /auth/login/access con {"password": pw_hash}
```

---

## 6. Tokens y headers HTTP

### 6.1 Tokens JWT

El servidor devuelve dos tokens:

- `token`: token "legacy", aceptado por endpoints más antiguos del API.
- `newToken`: token actual, preferido. La web app lo guarda como `xNewToken` en
  localStorage.

Para máxima compatibilidad, el CLI guarda ambos y usa `newToken` en el header
`Authorization`.

### 6.2 Headers requeridos

Todos los endpoints del Drive API requieren estos headers:

```http
Authorization: Bearer <newToken>
internxt-client: internxt-cli
internxt-version: 1.6.3
Content-Type: application/json
```

Los headers `internxt-client` e `internxt-version` son **obligatorios**. El servidor
los valida y puede rechazar peticiones sin ellos con `400 Bad Request`. Los valores
exactos (`internxt-cli`, `1.6.3`) se extrajeron del fichero de configuración del
CLI oficial.

### 6.3 UUIDs vs IDs numéricos

Internxt tiene un sistema de IDs dual, fruto de su evolución histórica:

- **IDs numéricos** (legacy): enteros como `41230090`, `186088125`. Son los IDs
  internos de base de datos.
- **UUIDs** (modernos): strings UUID-v4 como
  `3285b174-c5cc-4530-9646-30a07030d493`. Son los identificadores de la API moderna.

Casi todos los endpoints modernos esperan UUIDs. Algunos endpoints de creación aún
requieren el ID numérico del padre (campo `parentId` en `POST /folders`), que se
obtiene consultando primero los metadatos de la carpeta padre.

El `root_folder_uuid` que se guarda en las credenciales es el UUID de la carpeta
raíz del usuario, que viene en el campo `user.rootFolderUuid` de la respuesta de
login (no `user.root_folder_id`, que es numérico).

---

## 7. API REST de Drive

**Base URL**: `https://gateway.internxt.com/drive`

Todos los endpoints se descubrieron combinando:
1. Lectura del código fuente del SDK (`@internxt/sdk`).
2. Inspección de tráfico del navegador en `drive.internxt.com`.
3. Prueba directa con `curl`/`requests`.

### 7.1 Información de usuario

```
GET /users/me         → objeto completo del usuario
GET /users/usage      → {"total": bytes_usados, "drive": ..., "photos": ...}
GET /users/limit      → {"maxSpaceBytes": bytes_totales}
```

### 7.2 Navegación de carpetas

```
GET /folders/content/{uuid}/folders?limit=50&offset=0
    → {"folders": [{uuid, id, plainName, name, ...}, ...]}

GET /folders/content/{uuid}/files?limit=50&offset=0
    → {"files": [{uuid, id, plainName, name, size, type, ...}, ...]}

GET /folders/{uuid}/meta
    → {uuid, id, plainName, parentId, parentUuid, ...}
```

La paginación es necesaria: el servidor tiene un límite por petición (50 elementos
en la práctica). El cliente itera con `offset` hasta que recibe menos elementos que
el `limit`.

El campo `plainName` es el nombre en texto plano (descifrado). El campo `name`
contiene el nombre cifrado con AES. Siempre se usa `plainName` para mostrar al
usuario.

### 7.3 Operaciones de carpetas

```
POST /folders
    Body: {
        "name": "<nombre_cifrado>",     # legacy
        "plainName": "<nombre>",         # moderno
        "parentId": <id_numerico>,       # legacy, requerido
        "parentFolderUuid": "<uuid>"     # moderno, requerido
    }

PUT /folders/{uuid}/meta
    Body: {"plainName": "<nuevo_nombre>"}

PATCH /folders/{uuid}
    Body: {"destinationFolder": "<uuid_carpeta_destino>"}

DELETE /folders/{uuid}
```

**Bug encontrado con `mkdir`**: La API rechazaba la petición con el error
`"parentFolderUuid must be a UUID"` cuando se usaba el campo `parentUuid` en lugar
de `parentFolderUuid`. Son nombres distintos aunque semánticamente equivalentes.
Verificado en el código compilado del SDK.

**Bug encontrado con `mv`**: La API rechazaba la petición con el error
`"destinationFolder must be a UUID"` cuando se pasaba el ID numérico en lugar del
UUID. El campo `destinationFolder` en el PATCH espera un UUID.

### 7.4 Operaciones de ficheros

```
GET /files/{uuid}/meta
    → {uuid, fileId, bucket, size, type, plainName, folderUuid, ...}

PUT /files/{uuid}/meta
    Body: {"plainName": "<nuevo_nombre>"}

PATCH /files/{uuid}
    Body: {"destinationFolder": "<uuid_carpeta_destino>"}

POST /files
    Body: {
        "name": "<nombre>",
        "plainName": "<nombre>",
        "bucket": "<bucket_id>",
        "fileId": "<network_file_id>",
        "encryptVersion": "Aes03",
        "folderUuid": "<uuid_carpeta>",
        "size": <bytes>,
        "type": "<extension>",
        "modificationTime": "<iso8601>",
        "date": "<iso8601>"
    }
```

---

## 8. Cifrado E2E de ficheros

El cifrado de ficheros es independiente del cifrado de contraseñas. Los ficheros
se cifran con **AES-256-CTR** usando una clave derivada del **mnemónico BIP39**
del usuario.

### 8.1 El mnemónico BIP39

El mnemónico es una frase de 12 palabras (estándar BIP39) que actúa como raíz
criptográfica del usuario. Viene cifrado en la respuesta de login:

```json
{
  "user": {
    "mnemonic": "4f70656e53534c5f41455..." // hex, AES-CBC cifrado con la contraseña del usuario
  }
}
```

Se descifra en el momento del login:
```python
plain_mnemonic = _aes_decrypt_cryptojs(user["mnemonic"], password)
```

Y se almacena en texto plano en `~/.internxt-tools/credentials.json`. Esto es
deliberado: el CLI necesita el mnemónico para cifrar/descifrar ficheros, y pedirle
la contraseña al usuario en cada operación sería impracticable en scripts.

**Fuente**: `@internxt/sdk/src/crypto/services/cryptography.service.ts`.

### 8.2 Derivación de la clave de fichero

**Fuente**: `inxt-js/src/lib/utils/generateFileKey.ts`:

```typescript
export async function GenerateFileKey(
  mnemonic: string,
  bucketId: string,
  index: Buffer
): Promise<Buffer> {
  const seed = await mnemonicToSeed(mnemonic);  // PBKDF2-SHA512, 2048 iter, 64 bytes
  const bucketKey = crypto.createHash('sha512')
    .update(Buffer.concat([seed, Buffer.from(bucketId, 'hex')]))
    .digest();
  const fileKey = crypto.createHash('sha512')
    .update(Buffer.concat([bucketKey.slice(0, 32), index]))
    .digest()
    .slice(0, 32);
  return fileKey;
}
```

`mnemonicToSeed` es la función estándar de BIP39:
`PBKDF2-SHA512(mnemonic_utf8, salt=b"mnemonic", iterations=2048, length=64)`.

**Implementación Python** (`_derive_file_key`):
```python
def _derive_file_key(mnemonic: str, bucket_id: str, index_bytes: bytes) -> bytes:
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048, 64)
    bucket_key = hashlib.sha512(seed + bytes.fromhex(bucket_id)).digest()
    file_key = hashlib.sha512(bucket_key[:32] + index_bytes).digest()[:32]
    return file_key
```

**Cadena de derivación completa**:
```
mnemónico (12 palabras BIP39)
    │
    └─ PBKDF2-SHA512(mnemonic, b"mnemonic", 2048, 64) ──→ seed (64 bytes)
                                                                │
    bucket_id (hex, ej: "0563d27a8d276a574e2092e9")           │
        │                                                       │
        └─ bytes.fromhex(bucket_id) (12 bytes) ────────────────┘
                                                    SHA512(seed + bucket_bytes)
                                                        → bucket_key (64 bytes)
                                                                │
    index (32 bytes aleatorios por fichero)                    │
        │                                                       │
        └───────────────────────────────────────────────────────┘
                                            SHA512(bucket_key[:32] + index)
                                                → file_key (primeros 32 bytes)
```

### 8.3 Estructura del `index`

El `index` es un array de 32 bytes aleatorios generados en el momento de la subida
con `os.urandom(32)`. Sirve para dos propósitos:

1. **Semilla de derivación de clave**: la clave AES se deriva a partir del index,
   por lo que cada fichero tiene una clave única.
2. **IV del cifrado**: los primeros 16 bytes del index se usan como IV del
   AES-256-CTR.

El index se almacena en el Network API y se recupera en la descarga. Se transmite
como string hexadecimal de 64 caracteres.

### 8.4 El cifrado AES-256-CTR

**Modo CTR** (Counter Mode): a diferencia de CBC, CTR no requiere padding y puede
procesar el plaintext en streaming. Internxt usa CTR porque permite cifrar ficheros
de cualquier tamaño sin modificar la longitud.

```python
def _aes256ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()
```

### 8.5 Hash del contenido cifrado

El Network API requiere un hash del contenido para verificar la integridad del
fichero subido. El algoritmo es `RIPEMD160(SHA256(data))`:

```python
def _content_hash(data: bytes) -> str:
    sha = hashlib.sha256(data).digest()
    rmd = hashlib.new("ripemd160", sha).digest()
    return rmd.hex()
```

**Fuente**: `inxt-js/src/services/ObjectStorageGateway.ts`. Este es el mismo
algoritmo hash que usa Bitcoin para direcciones (`Hash160`), una elección inusual
para un sistema de almacenamiento pero consistente con los orígenes cripto de Internxt.

---

## 9. Protocolo de subida (upload)

La subida implica dos APIs distintas: el **Drive API** (metadatos) y el
**Network API** (datos cifrados).

### 9.1 Autenticación del Network API

El Network API usa **HTTP Basic Auth**, no Bearer JWT. La construcción es:

```
username: user.bridgeUser  (normalmente el email del usuario)
password: sha256(user.userId).hexdigest()
```

**Origen de `userId`**: es el campo `user.userId` de la respuesta de login, que
contiene el **hash bcrypt** del usuario (un string que empieza por `$2a$08$...`).
No es el UUID del usuario ni es el sha256 del mnemónico.

Este fue el error de autenticación más difícil de depurar: el servidor devolvía
`401 Invalid email or password` porque se estaba usando `sha256(mnemonic)` como
contraseña del Network API.

**Fuente**: `inxt-js/src/lib/upload/uploadFileV2.ts`:
```typescript
const creds = {
  user: networkCredentials.user,        // bridgeUser
  pass: networkCredentials.pass,        // userId (bcrypt hash)
};
// La librería construye Basic Auth con sha256(creds.pass)
```

**Implementación Python**:
```python
def _network_headers(bridge_user: str, user_id: str) -> dict:
    bridge_pass = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
    token = base64.b64encode(f"{bridge_user}:{bridge_pass}".encode()).decode()
    return {"Authorization": f"Basic {token}", ...}
```

### 9.2 Flujo de subida (4 pasos)

**Paso 1**: Iniciar la subida en el Network API.
```
POST https://gateway.internxt.com/network/v2/buckets/{bucket_id}/files/start?multiparts=1
Auth: Basic <network_credentials>
Body: {"uploads": [{"index": 0, "size": <bytes>}]}

Respuesta: {"uploads": [{"url": "<presigned_url_s3>", "uuid": "<shard_uuid>"}]}
```

El `url` es un URL pre-firmado de S3 (u objeto storage compatible) con tiempo de
expiración. El `uuid` es el identificador del shard en el sistema de Internxt.

**Paso 2**: Subir el contenido cifrado directamente al storage.
```
PUT <presigned_url>
Content-Type: application/octet-stream
Body: <bytes_cifrados_AES256CTR>
```

Esta petición va directamente al proveedor de almacenamiento (S3, Backblaze, etc.),
**no** pasa por los servidores de Internxt. Este es el diseño E2E: Internxt nunca
ve el contenido descifrado.

**Paso 3**: Notificar al Network API que la subida se completó.
```
POST https://gateway.internxt.com/network/v2/buckets/{bucket_id}/files/finish
Auth: Basic <network_credentials>
Body: {
    "index": "<index_hex_64_chars>",
    "shards": [{"hash": "<ripemd160_sha256_hex>", "uuid": "<shard_uuid>"}]
}

Respuesta: {"id": "<network_file_id>"}
```

**Paso 4**: Registrar el fichero en el Drive API (metadatos).
```
POST https://gateway.internxt.com/drive/files
Auth: Bearer <jwt>
Body: {
    "name": "<nombre_fichero>",
    "plainName": "<nombre_fichero>",
    "bucket": "<bucket_id>",
    "fileId": "<network_file_id>",
    "encryptVersion": "Aes03",
    "folderUuid": "<uuid_carpeta_destino>",
    "size": <bytes_originales>,
    "type": "<extension_sin_punto>",
    "modificationTime": "<iso8601>",
    "date": "<iso8601>"
}
```

El campo `encryptVersion: "Aes03"` es el identificador de versión del protocolo
de cifrado actual de Internxt. Las versiones anteriores (01, 02) usaban esquemas
distintos.

---

## 10. Protocolo de descarga (download)

### 10.1 Flujo de descarga (3 pasos)

**Paso 1**: Obtener metadatos del fichero desde el Drive API.
```
GET https://gateway.internxt.com/drive/files/{uuid}/meta
Auth: Bearer <jwt>

Respuesta: {
    "fileId": "<network_file_id>",
    "bucket": "<bucket_id>",
    "size": <bytes>,
    ...
}
```

**Paso 2**: Obtener el index y los URLs de descarga del Network API.
```
GET https://gateway.internxt.com/network/buckets/{bucket}/files/{file_id}/info
Auth: Basic <network_credentials>
Headers: x-api-version: 2

Respuesta: {
    "index": "<index_hex_64_chars>",
    "shards": [{"url": "<presigned_url>", "index": 0, ...}]
}
```

El header `x-api-version: 2` es necesario para obtener la respuesta en el formato
moderno. Sin él, la respuesta usa el formato legacy que no incluye URLs directos.

**Paso 3**: Descargar y descifrar.
```
GET <presigned_url>
→ <bytes_cifrados>

index_bytes = bytes.fromhex(index_hex)
iv = index_bytes[:16]
file_key = _derive_file_key(mnemonic, bucket, index_bytes)
plaintext = AES256CTR_decrypt(encrypted, file_key, iv)
```

---

## 11. Gestión de la papelera

Este fue el módulo que más investigación requirió, ya que la documentación pública
es inexistente y el comportamiento del servidor no era obvio.

### 11.1 Descubrimiento del endpoint correcto

**Primera aproximación (fallida)**:
```
GET /storage/trash → 404 "Cannot GET /api/storage/trash"
```

El 404 indicaba que este endpoint simplemente no existe en la versión del gateway
actual (existe en el SDK como `getTrash()` pero el servidor no lo implementa).

**Segunda aproximación (parcialmente correcta)**:
```
GET /storage/trash/paginated → 400 Bad Request
```

El 400 en lugar de 404 confirmó que el endpoint existe pero faltan parámetros. Para
descubrir los parámetros correctos, se inspeccionó el fichero:
```
node_modules/@internxt/sdk/dist/drive/trash/index.js
```

El método relevante:
```javascript
Trash.prototype.getTrashedFilesPaginated = function(limit, offset, type, root, folderId) {
    var endpoint = '/storage/trash/paginated';
    var folderIdQuery = folderId !== undefined ? "folderId=" + folderId + "&" : '';
    var url = endpoint + "?" + folderIdQuery + "limit=" + limit + "&offset=" + offset
              + "&type=" + type + "&root=" + root;
    return this.client.get(url, this.headers());
};
```

Parámetros requeridos:
- `limit`: número de elementos por página.
- `offset`: desplazamiento para paginación.
- `type`: `"files"` o `"folders"` (no `"file"` en singular — otro bug inicial).
- `root`: booleano `true` para listar desde la raíz de la papelera.

**Respuesta**: el servidor devuelve `{"result": [...]}`, no `{"items": [...]}` como
sugería el tipo TypeScript del SDK. El nombre del campo se confirmó haciendo la
petición real.

### 11.2 Endpoints de papelera

| Operación | Método | Endpoint | Payload |
|---|---|---|---|
| Listar (ficheros) | GET | `/storage/trash/paginated?type=files&root=true&limit=N&offset=N` | — |
| Listar (carpetas) | GET | `/storage/trash/paginated?type=folders&root=true&limit=N&offset=N` | — |
| Mover a papelera | POST | `/storage/trash/add` | `{"items": [{"uuid": "...", "type": "file\|folder"}]}` |
| Vaciar papelera | DELETE | `/storage/trash/all` | — |
| Borrar permanente | DELETE | `/storage/trash` | `{"items": [{"uuid": "...", "type": "file\|folder"}]}` |

**Bug con el payload de `trash/add`**: la primera implementación usaba `{"id": uuid}`
pero el servidor esperaba `{"uuid": uuid}`. El error del servidor era `500 Internal
Server Error` (no un 400 descriptivo), lo que dificultó la depuración. Se resolvió
probando ambas variantes y confirmando con el código del SDK.

---

## 12. Bugs encontrados y cómo se resolvieron

Esta sección documenta cada error encontrado durante el desarrollo, en orden
cronológico.

### Bug 1: `encryptedSalt` vs `sKey`

**Síntoma**: `KeyError: 'encryptedSalt'` al intentar hacer login.

**Causa**: El código inicial buscaba el campo `encryptedSalt` en la respuesta del
servidor, pero el servidor real devuelve `sKey`.

**Diagnóstico**: Se observó la respuesta real del servidor:
```json
{"sKey": "53616c7465645f5f...", "tfa": true, ...}
```

**Fix**: Añadir fallback a múltiples nombres de campo:
```python
salt = security.get("sKey") or security.get("encryptedSalt") or security.get("encrypted_salt")
```

---

### Bug 2: AES usa hex, no base64

**Síntoma**: `401 Unauthorized` al enviar el hash de contraseña.

**Causa**: La implementación inicial de `_aes_encrypt_cryptojs` devolvía base64
(comportamiento por defecto de CryptoJS). El servidor espera hex.

**Diagnóstico**: Al inspeccionar el código compilado del CLI en lugar del código
TypeScript fuente, se descubrió que la función `encryptTextWithKey` tiene una
ligera variación que produce hex.

**Fix**:
```python
return (b"Salted__" + salt + ct).hex()  # hex, no base64
```

---

### Bug 3: `_aes_decrypt_cryptojs` sólo aceptaba base64

**Síntoma**: `ValueError: non-hexadecimal number found in fromhex()` al descifrar
el `sKey` de la respuesta del servidor.

**Causa**: El campo `sKey` viene en hex (lo que tiene sentido: AES devuelve bytes,
y los bytes se codifican en hex). La función de descifrado inicialmente sólo
aceptaba base64.

**Fix**: Intentar hex primero, caer a base64 si falla:
```python
try:
    raw = bytes.fromhex(data)
except ValueError:
    raw = base64.b64decode(data)
```

---

### Bug 4: PBKDF2 salt con codificación incorrecta

**Síntoma**: `401 Unauthorized`. Login fallaba incluso con contraseña copiada
literalmente.

**Causa**: El salt descifrado es un string hexadecimal (ej: `"ad0caeea..."`). Al
pasarlo a PBKDF2 como `plain_salt.encode('utf-8')`, Python lo interpreta como
32 bytes ASCII (los caracteres del string hex). Node.js lo interpreta como
16 bytes raw (`Buffer.from(salt, 'hex')`). Produce un PBKDF2 completamente diferente.

Este fue el bug más difícil de encontrar porque el error era silencioso (el servidor
simplemente devolvía 401) y requería entender exactamente qué hace CryptoJS
internamente.

**Diagnóstico**: Leer el código fuente de CryptoJS y del SDK de Internxt juntos:
`CryptoJS.enc.Hex.parse(passObject.salt)` convierte de hex a WordArray de bytes.

**Fix**:
```python
salt_bytes = bytes.fromhex(plain_salt)   # CRÍTICO: no .encode('utf-8')
```

---

### Bug 5: Campo 2FA incorrecto

**Síntoma**: `400 Bad Request` con el código 2FA.

**Causa**: Se enviaba el código en el campo `twoFactorCode`. El servidor espera `tfa`.

**Fix**:
```python
payload["tfa"] = tfa  # no "twoFactorCode"
```

---

### Bug 6: `root_folder_uuid` era numérico

**Síntoma**: `400 Bad Request` o `"uuid must be a UUID string"` al listar la carpeta
raíz.

**Causa**: Se guardaba `user.root_folder_id` (entero: `41230090`) en lugar de
`user.rootFolderUuid` (UUID: `"3285b174-..."`).

**Diagnóstico**: La respuesta de login contiene ambos campos. La API moderna requiere
el UUID.

**Fix**:
```python
"root_folder_uuid": user.get("rootFolderUuid") or user.get("rootFolderId") or user.get("root_folder_id")
```

---

### Bug 7: `size` como string en la respuesta de ficheros

**Síntoma**: `TypeError: '<' not supported between instances of 'str' and 'int'`.

**Causa**: El campo `size` de un fichero en la API a veces llega como string
`"948"` en lugar de entero `948`.

**Fix**:
```python
size = int(f.get("size") or 0)
```

---

### Bug 8: Network API auth con hash de mnemónico

**Síntoma**: `401 Invalid email or password` al subir o descargar ficheros.

**Causa**: Se usaba `sha256(mnemonic)` como contraseña del Network API. El campo
correcto es `sha256(user.userId)` donde `userId` es el hash bcrypt del usuario.

**Diagnóstico**: Lectura del fichero `inxt-js/src/lib/upload/uploadFileV2.ts` y
rastreo de la variable `networkCredentials.pass` hasta su origen en el objeto de
usuario.

**Fix**:
```python
bridge_pass = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
# donde user_id = user["userId"] = "$2a$08$..."
```

---

### Bug 9: `parentUuid` vs `parentFolderUuid`

**Síntoma**: `400 Bad Request: "parentFolderUuid must be a UUID"` al crear carpetas.

**Causa**: El payload de `POST /folders` usaba el campo `parentUuid`. El servidor
espera exactamente `parentFolderUuid`.

**Fix**:
```python
{"parentFolderUuid": parent_uuid}  # no "parentUuid"
```

---

### Bug 10: `destinationFolder` esperaba UUID, no ID numérico

**Síntoma**: `400 Bad Request: "destinationFolder must be a UUID"` al mover
elementos.

**Causa**: El PATCH de mover usaba el ID numérico del padre obtenido de los
metadatos. El campo `destinationFolder` del PATCH espera un UUID.

**Fix**: Pasar directamente el UUID de la carpeta destino (ya disponible de
`_resolve_path`) sin convertirlo a ID numérico.

---

### Bug 11: Endpoint `trash/add` usa `uuid`, no `id`

**Síntoma**: `500 Internal Server Error` al mover a la papelera.

**Causa**: El payload usaba `{"id": uuid}`. El servidor espera `{"uuid": uuid}`.

**Diagnóstico**: Prueba directa con ambas variantes. El error 500 (en lugar de 400)
dificultó la depuración.

**Fix**:
```python
{"items": [{"uuid": uuid, "type": item_type}]}
```

---

### Bug 12: `trash list` devuelve `result`, no `items`

**Síntoma**: La papelera siempre aparecía vacía aunque hubiera elementos.

**Causa**: El campo en la respuesta es `result`, no `items`:
```json
{"result": [...]}
```

El tipo TypeScript del SDK declaraba `items` pero el servidor real devuelve `result`.

**Fix**:
```python
chunk = data.get("result", data.get("items", []))
```

---

### Bug 13: `trash clear` usaba POST, no DELETE

**Síntoma**: `405 Method Not Allowed`.

**Causa**: Se usaba `POST /storage/trash/clear`. El endpoint correcto es
`DELETE /storage/trash/all`.

**Fix**:
```python
client.delete("/storage/trash/all")
```

---

## 13. Mapa de endpoints verificados

Todos los endpoints de esta tabla han sido probados en producción y funcionan
correctamente con las credenciales de un usuario del plan gratuito.

### Drive API (`https://gateway.internxt.com/drive`)

| Método | Endpoint | Función | Auth |
|--------|----------|---------|------|
| POST | `/auth/login` | Obtener salt + flag 2FA | Ninguna |
| POST | `/auth/login/access` | Autenticar, obtener JWT | Ninguna |
| GET | `/users/me` | Info del usuario | Bearer JWT |
| GET | `/users/usage` | Bytes usados | Bearer JWT |
| GET | `/users/limit` | Límite de espacio | Bearer JWT |
| GET | `/folders/content/{uuid}/folders` | Listar subcarpetas | Bearer JWT |
| GET | `/folders/content/{uuid}/files` | Listar ficheros | Bearer JWT |
| GET | `/folders/{uuid}/meta` | Metadatos de carpeta | Bearer JWT |
| POST | `/folders` | Crear carpeta | Bearer JWT |
| PUT | `/folders/{uuid}/meta` | Renombrar carpeta | Bearer JWT |
| PATCH | `/folders/{uuid}` | Mover carpeta | Bearer JWT |
| GET | `/files/{uuid}/meta` | Metadatos de fichero | Bearer JWT |
| POST | `/files` | Registrar fichero subido | Bearer JWT |
| PUT | `/files/{uuid}/meta` | Renombrar fichero | Bearer JWT |
| PATCH | `/files/{uuid}` | Mover fichero | Bearer JWT |
| POST | `/storage/trash/add` | Mover a papelera | Bearer JWT |
| GET | `/storage/trash/paginated` | Listar papelera | Bearer JWT |
| DELETE | `/storage/trash/all` | Vaciar papelera | Bearer JWT |
| DELETE | `/storage/trash` | Borrar permanentemente | Bearer JWT |

### Network API (`https://gateway.internxt.com/network`)

| Método | Endpoint | Función | Auth |
|--------|----------|---------|------|
| POST | `/v2/buckets/{bucket}/files/start` | Iniciar subida | Basic (bridge) |
| POST | `/v2/buckets/{bucket}/files/finish` | Confirmar subida | Basic (bridge) |
| GET | `/buckets/{bucket}/files/{fileId}/info` | Info de descarga | Basic (bridge) |

### Storage directo (S3/compatible)

| Método | Descripción | Auth |
|--------|-------------|------|
| PUT `<presigned_url>` | Subir bytes cifrados | URL pre-firmada |
| GET `<presigned_url>` | Descargar bytes cifrados | URL pre-firmada |

---

## Notas finales

El sistema de cifrado de Internxt es genuino: los datos suben cifrados con una clave
derivada del mnemónico del usuario, y Internxt nunca tiene acceso a la clave. El
servidor sólo ve ciphertext opaco.

La restricción que motivó este proyecto opera **exclusivamente en la capa de
autenticación** (endpoint `/auth/cli/login/access` vs `/auth/login/access`) y no
afecta a ninguna funcionalidad criptográfica o de almacenamiento. Una vez obtenido
el JWT mediante el endpoint web, el resto de la API funciona igual para todos los
usuarios independientemente del plan.

---

*Generado el 2026-03-11. Código en `/home/alfonso/internxt/internxt.py`.*

---