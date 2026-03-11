# Internxt Drive CLI — Complete Technical Documentation

> **Purpose of this document**: exhaustive record of the entire reverse engineering
> process, source analysis and development that made it possible to build a native
> Python CLI capable of managing Internxt Drive without depending on the paid
> official CLI.

---

## Table of Contents

1. [Context and Motivation](#1-context-and-motivation)
2. [Sources of Information](#2-sources-of-information)
3. [The Internxt Restriction](#3-the-internxt-restriction)
4. [Authentication — Complete Reverse Engineering](#4-authentication--complete-reverse-engineering)
5. [Password Cryptography](#5-password-cryptography)
6. [Tokens and HTTP Headers](#6-tokens-and-http-headers)
7. [Drive REST API](#7-drive-rest-api)
8. [File E2E Encryption](#8-file-e2e-encryption)
9. [Upload Protocol](#9-upload-protocol)
10. [Download Protocol](#10-download-protocol)
11. [Trash Management](#11-trash-management)
12. [Bugs Found and How They Were Fixed](#12-bugs-found-and-how-they-were-fixed)
13. [Verified Endpoint Map](#13-verified-endpoint-map)

---

## 1. Context and Motivation

Internxt is a cloud storage service with end-to-end (E2E) encryption. In mid
2024/2025, Internxt restricted its official CLI (`@internxt/cli`, published on npm)
so that the CLI-specific authentication endpoint — `/auth/cli/login/access` — only
responds successfully to accounts with a paid plan. Free-plan users receive an
authorization error when trying to authenticate from the official CLI.

The goal was to create an alternative Python CLI that:

- Authenticates the user using the same cryptographic protocol as the official SDK,
  but pointing to the web endpoint instead of the CLI-specific one.
- Natively implements file E2E encryption in Python.
- Does not require Node.js for basic management operations (ls, mkdir, mv, rm, etc.).
- Is completely transparent in its operation.

---

## 2. Sources of Information

### 2.1 Official Source Code Published on GitHub (public)

Internxt publishes its SDK and applications under AGPL/MIT licences on GitHub. The
following repositories were analysed:

| Repository | What was extracted |
|---|---|
| `internxt/sdk` (`@internxt/sdk`) | Crypto implementation, auth endpoints, data models |
| `internxt/inxt-js` | File upload/download implementation, key derivation |
| `internxt/cli` (`@internxt/cli`) | CLI authentication flow, constants, command structure |
| `internxt/drive-web` | Endpoint confirmation and web app behaviour |

### 2.2 npm Package Installed Locally

To analyse compiled code confirmed to run in production, the Internxt SDK was
installed in a test directory:

```bash
mkdir /tmp/internxt-sdk-test
cd /tmp/internxt-sdk-test
npm install @internxt/sdk @internxt/cli
```

This made it possible to read the compiled `.js` files in
`node_modules/@internxt/sdk/dist/` and `node_modules/@internxt/cli/dist/`, which
contain the code that actually runs. When the TypeScript source was ambiguous, the
compiled `.js` was the definitive source.

### 2.3 Network Traffic Inspection (Browser DevTools)

To confirm the real behaviour of the API, Firefox/Chrome developer tools were used
against `drive.internxt.com`:

- **Network tab**: to see the real HTTP requests made by the web app, including
  headers, request and response bodies.
- **Application > Local Storage**: to extract JWT tokens and confirm field names
  (`xToken`, `xNewToken`).

This method was especially useful to confirm the exact name of the salt field
(`sKey` vs `encryptedSalt`) and the structure of the server response, since the
source code sometimes has abstractions that obscure the real HTTP contract.

### 2.4 Iterative Exploration (Trial and Error)

For undocumented endpoints (such as the trash), direct HTTP requests were made with
Python's `requests` library, analysing error codes and response messages to infer
expected behaviour.

---

## 3. The Internxt Restriction

### The Technical Problem

The official CLI uses the endpoint:
```
POST https://gateway.internxt.com/drive/auth/cli/login/access
```

This endpoint returns `403 Forbidden` to users without a premium plan. Internxt
implements the restriction server-side: it validates the user's plan before issuing
a token.

### The Solution

The Internxt web application uses a different endpoint to authenticate:
```
POST https://gateway.internxt.com/drive/auth/login/access
```

This endpoint **has no plan restriction**. The authentication protocol (parameters,
crypto) is identical on both endpoints. The only difference is the URL.

Discovering this was immediate by inspecting the browser's network traffic when
logging into `drive.internxt.com`. The authentication request goes to
`/auth/login/access`, not to `/auth/cli/login/access`.

---

## 4. Authentication — Complete Reverse Engineering

### 4.1 Step 1: Obtaining the Encrypted Salt

**Endpoint**:
```
POST /drive/auth/login
Body: {"email": "user@example.com"}
```

**Source**: `@internxt/sdk/dist/auth/index.js`, method `login()`:
```javascript
login(payload) {
    return this.client.post('/auth/login', { email: payload.email }, this.headers());
}
```

**Server response** (relevant fields):
```json
{
  "sKey": "53616c7465645f5f...",
  "tfa": true,
  "hasKeys": true,
  "hasKyberKeys": true,
  "hasEccKeys": true
}
```

**Analysis of the `sKey` field**:

The field is called `sKey` in the current server version (not `encryptedSalt` as
appears in some SDK versions). The value is a hexadecimal string that, when decoded,
starts with `Salted__` (the first 8 bytes in ASCII), which is the OpenSSL/CryptoJS
format for AES-CBC encrypted data.

The Python code implements a fallback for both field names:
```python
salt = security.get("sKey") or security.get("encryptedSalt") or security.get("encrypted_salt")
```

**`tfa` field**:

Indicates whether the account has two-factor authentication active. If `true`, the
user must be asked for the TOTP code before proceeding. This field is obtained in
the same step-1 call, avoiding an additional request.

### 4.2 Step 2: Authentication with Password Hash

**Endpoint**:
```
POST /drive/auth/login/access
Body: {"email": "...", "password": "<encrypted_hash>", "tfa": "<optional_2fa_code>"}
```

**Source**: `@internxt/sdk/dist/auth/index.js`, method `loginAccess()`.

**`tfa` field**: This was one of the initial errors. The SDK uses the field `tfa` in
the request body (not `twoFactorCode` as one might intuit, nor `totpCode`, nor
`otp`). Verified in the compiled SDK code:
```javascript
const payload = { email, password, tfa }
return this.client.post('/auth/login/access', payload, this.headers())
```

**Successful response**:
```json
{
  "token": "<legacy_jwt>",
  "newToken": "<new_jwt>",
  "user": {
    "uuid": "...",
    "email": "...",
    "mnemonic": "<mnemonic_encrypted_with_AES>",
    "bucket": "<bucket_id_hex>",
    "bridgeUser": "user@example.com",
    "userId": "$2a$08$...",
    "rootFolderUuid": "...",
    "rootFolderId": "...",
    ...
  }
}
```

---

## 5. Password Cryptography

This is the most complex core of the system. Internxt does not transmit the password
in plain text or with a simple hash. The process involves three cryptographic layers.

### 5.1 Outer Layer: AES-256-CBC compatible with CryptoJS

**Source**: `@internxt/sdk/src/shared/utils/encryptionUtils.ts`:
```typescript
export function encryptTextWithKey(textToEncrypt: string, key: string): string {
  const bytes = CryptoJS.AES.encrypt(textToEncrypt, key);
  return bytes.toString();  // returns base64 in standard CryptoJS
}
```

However, the CLI returns **hex**, not base64. This was discovered by analysing the
compiled `.js` code in `node_modules/@internxt/cli/dist/`, where the
`encryptTextWithKey` function had a slightly different implementation that produced
hex. The server rejected base64 with `401 Unauthorized`.

**Python implementation** (`_aes_encrypt_cryptojs`):
```python
def _aes_encrypt_cryptojs(plaintext: str, password: str) -> str:
    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(password.encode(), salt)
    # ... AES-CBC encryption with PKCS7 padding ...
    return (b"Salted__" + salt + ct).hex()  # hex, not base64
```

**Ciphertext format** (OpenSSL "Salted" format):
```
Salted__ | salt(8 bytes) | ciphertext
53616c74 | 6564 5f5f | <8 random bytes> | <AES-CBC output>
```

**Key derivation**: OpenSSL EVP_BytesToKey with MD5 (not SHA-256, not PBKDF2):
```python
def _evp_bytes_to_key(password: bytes, salt: bytes, key_len=32, iv_len=16):
    d, d_i = b"", b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d  += d_i
    return d[:key_len], d[key_len:key_len + iv_len]
```
This produces a 256-bit AES key and a 128-bit IV. It is the key derivation that
CryptoJS uses by default (inherited from the OpenSSL format).

**`APP_CRYPTO_SECRET` constant**: `"6KYQBP847D4ATSFA"`. Extracted from the
`.env.template` file of the `internxt/cli` repository on GitHub, which is public.
This constant is used as the "password" for the AES that encrypts/decrypts the salt
and the password hash. It is a hardcoded constant in all official clients.

### 5.2 Middle Layer: PBKDF2-SHA1

**Source**: `@internxt/sdk/src/shared/utils/passToHash.ts`:
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

The critical bug here was the **interpretation of the salt**:

`CryptoJS.enc.Hex.parse(salt)` converts the hexadecimal string to raw bytes,
equivalent to `Buffer.from(salt, 'hex')` in Node.js.

The first Python implementation used `plain_salt.encode('utf-8')`, which interprets
the hex string as ASCII text (32 bytes of `0-9a-f` characters). This produces a
completely different PBKDF2.

**Correct implementation**:
```python
plain_salt = _aes_decrypt_cryptojs(encrypted_salt, APP_CRYPTO_SECRET)
salt_bytes = bytes.fromhex(plain_salt)   # Buffer.from(salt, 'hex') in Node.js
kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=32, salt=salt_bytes, iterations=10000)
hash_bytes = kdf.derive(password.encode("utf-8"))
hash_hex = hash_bytes.hex()              # 64-char hex string
```

**Why SHA1**: CryptoJS.PBKDF2 uses SHA1 by default, not SHA256 or SHA512. It is a
legacy implementation detail. Security comes from the number of iterations and the
additional AES layer, not from the HMAC algorithm.

### 5.3 Complete `_hash_password` Flow

```
user_password (plain text)
        ↓
[step 1] Server returns sKey (hex)
        ↓
[step 2] AES_decrypt(sKey, APP_CRYPTO_SECRET) → salt_hex (hex string, ~32 chars)
        ↓
[step 3] bytes.fromhex(salt_hex) → salt_bytes (16 raw bytes)
        ↓
[step 4] PBKDF2-SHA1(password, salt_bytes, iter=10000, len=32) → hash_bytes (32 bytes)
        ↓
[step 5] hash_bytes.hex() → hash_hex (64-char hex string)
        ↓
[step 6] AES_encrypt(hash_hex, APP_CRYPTO_SECRET) → pw_hash (hex string)
        ↓
[send] POST /auth/login/access with {"password": pw_hash}
```

---

## 6. Tokens and HTTP Headers

### 6.1 JWT Tokens

The server returns two tokens:

- `token`: "legacy" token, accepted by older API endpoints.
- `newToken`: current token, preferred. The web app saves it as `xNewToken` in
  localStorage.

For maximum compatibility, the CLI saves both and uses `newToken` in the
`Authorization` header.

### 6.2 Required Headers

All Drive API endpoints require these headers:

```http
Authorization: Bearer <newToken>
internxt-client: internxt-cli
internxt-version: 1.6.3
Content-Type: application/json
```

The `internxt-client` and `internxt-version` headers are **mandatory**. The server
validates them and may reject requests without them with `400 Bad Request`. The exact
values (`internxt-cli`, `1.6.3`) were extracted from the official CLI configuration
file.

### 6.3 UUIDs vs Numeric IDs

Internxt has a dual ID system, a result of its historical evolution:

- **Numeric IDs** (legacy): integers like `41230090`, `186088125`. These are
  internal database IDs.
- **UUIDs** (modern): UUID-v4 strings like
  `3285b174-c5cc-4530-9646-30a07030d493`. These are the identifiers of the modern
  API.

Almost all modern endpoints expect UUIDs. Some creation endpoints still require the
numeric parent ID (field `parentId` in `POST /folders`), obtained by first querying
the parent folder metadata.

The `root_folder_uuid` saved in credentials is the UUID of the user's root folder,
found in the `user.rootFolderUuid` field of the login response (not
`user.root_folder_id`, which is numeric).

---

## 7. Drive REST API

**Base URL**: `https://gateway.internxt.com/drive`

All endpoints were discovered by combining:
1. Reading the SDK source code (`@internxt/sdk`).
2. Inspecting browser traffic on `drive.internxt.com`.
3. Direct testing with `curl`/`requests`.

### 7.1 User Information

```
GET /users/me         → full user object
GET /users/usage      → {"total": bytes_used, "drive": ..., "photos": ...}
GET /users/limit      → {"maxSpaceBytes": total_bytes}
```

### 7.2 Folder Navigation

```
GET /folders/content/{uuid}/folders?limit=50&offset=0
    → {"folders": [{uuid, id, plainName, name, ...}, ...]}

GET /folders/content/{uuid}/files?limit=50&offset=0
    → {"files": [{uuid, id, plainName, name, size, type, ...}, ...]}

GET /folders/{uuid}/meta
    → {uuid, id, plainName, parentId, parentUuid, ...}
```

Pagination is necessary: the server has a per-request limit (50 elements in
practice). The client iterates with `offset` until it receives fewer elements than
the `limit`.

The `plainName` field is the plain text (decrypted) name. The `name` field contains
the AES-encrypted name. `plainName` is always used to display to the user.

### 7.3 Folder Operations

```
POST /folders
    Body: {
        "name": "<encrypted_name>",      # legacy
        "plainName": "<name>",           # modern
        "parentId": <numeric_id>,        # legacy, required
        "parentFolderUuid": "<uuid>"     # modern, required
    }

PUT /folders/{uuid}/meta
    Body: {"plainName": "<new_name>"}

PATCH /folders/{uuid}
    Body: {"destinationFolder": "<destination_folder_uuid>"}

DELETE /folders/{uuid}
```

**Bug found with `mkdir`**: The API rejected the request with the error
`"parentFolderUuid must be a UUID"` when `parentUuid` was used instead of
`parentFolderUuid`. They are different names even though semantically equivalent.
Verified in the compiled SDK code.

**Bug found with `mv`**: The API rejected the request with the error
`"destinationFolder must be a UUID"` when the numeric ID was passed instead of the
UUID. The `destinationFolder` field in the PATCH expects a UUID.

### 7.4 File Operations

```
GET /files/{uuid}/meta
    → {uuid, fileId, bucket, size, type, plainName, folderUuid, ...}

PUT /files/{uuid}/meta
    Body: {"plainName": "<new_name>"}

PATCH /files/{uuid}
    Body: {"destinationFolder": "<destination_folder_uuid>"}

POST /files
    Body: {
        "name": "<file_name>",
        "plainName": "<file_name>",
        "bucket": "<bucket_id>",
        "fileId": "<network_file_id>",
        "encryptVersion": "Aes03",
        "folderUuid": "<folder_uuid>",
        "size": <bytes>,
        "type": "<extension_without_dot>",
        "modificationTime": "<iso8601>",
        "date": "<iso8601>"
    }
```

---

## 8. File E2E Encryption

File encryption is independent of password encryption. Files are encrypted with
**AES-256-CTR** using a key derived from the user's **BIP39 mnemonic**.

### 8.1 The BIP39 Mnemonic

The mnemonic is a 12-word phrase (BIP39 standard) that acts as the user's
cryptographic root. It comes encrypted in the login response:

```json
{
  "user": {
    "mnemonic": "4f70656e53534c5f41455..." // hex, AES-CBC encrypted with user password
  }
}
```

It is decrypted at login time:
```python
plain_mnemonic = _aes_decrypt_cryptojs(user["mnemonic"], password)
```

And stored in plain text in `~/.internxt-tools/credentials.json`. This is
deliberate: the CLI needs the mnemonic to encrypt/decrypt files, and asking the user
for the password on every operation would be impractical in scripts.

**Source**: `@internxt/sdk/src/crypto/services/cryptography.service.ts`.

### 8.2 File Key Derivation

**Source**: `inxt-js/src/lib/utils/generateFileKey.ts`:

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

`mnemonicToSeed` is the standard BIP39 function:
`PBKDF2-SHA512(mnemonic_utf8, salt=b"mnemonic", iterations=2048, length=64)`.

**Python implementation** (`_derive_file_key`):
```python
def _derive_file_key(mnemonic: str, bucket_id: str, index_bytes: bytes) -> bytes:
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048, 64)
    bucket_key = hashlib.sha512(seed + bytes.fromhex(bucket_id)).digest()
    file_key = hashlib.sha512(bucket_key[:32] + index_bytes).digest()[:32]
    return file_key
```

**Full derivation chain**:
```
mnemonic (12 BIP39 words)
    │
    └─ PBKDF2-SHA512(mnemonic, b"mnemonic", 2048, 64) ──→ seed (64 bytes)
                                                                │
    bucket_id (hex, e.g.: "0563d27a8d276a574e2092e9")         │
        │                                                       │
        └─ bytes.fromhex(bucket_id) (12 bytes) ────────────────┘
                                                    SHA512(seed + bucket_bytes)
                                                        → bucket_key (64 bytes)
                                                                │
    index (32 random bytes per file)                           │
        │                                                       │
        └───────────────────────────────────────────────────────┘
                                            SHA512(bucket_key[:32] + index)
                                                → file_key (first 32 bytes)
```

### 8.3 The `index` Structure

The `index` is an array of 32 random bytes generated at upload time with
`os.urandom(32)`. It serves two purposes:

1. **Key derivation seed**: the AES key is derived from the index, so each file has
   a unique key.
2. **Encryption IV**: the first 16 bytes of the index are used as the AES-256-CTR IV.

The index is stored in the Network API and retrieved during download. It is
transmitted as a 64-character hexadecimal string.

### 8.4 AES-256-CTR Encryption

**CTR mode** (Counter Mode): unlike CBC, CTR does not require padding and can
process the plaintext in streaming. Internxt uses CTR because it allows encrypting
files of any size without modifying the length.

```python
def _aes256ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()
```

### 8.5 Encrypted Content Hash

The Network API requires a content hash to verify the integrity of the uploaded
file. The algorithm is `RIPEMD160(SHA256(data))`:

```python
def _content_hash(data: bytes) -> str:
    sha = hashlib.sha256(data).digest()
    rmd = hashlib.new("ripemd160", sha).digest()
    return rmd.hex()
```

**Source**: `inxt-js/src/services/ObjectStorageGateway.ts`. This is the same hash
algorithm that Bitcoin uses for addresses (`Hash160`), an unusual choice for a
storage system but consistent with Internxt's crypto origins.

---

## 9. Upload Protocol

Upload involves two distinct APIs: the **Drive API** (metadata) and the
**Network API** (encrypted data).

### 9.1 Network API Authentication

The Network API uses **HTTP Basic Auth**, not Bearer JWT. The construction is:

```
username: user.bridgeUser  (normally the user's email)
password: sha256(user.userId).hexdigest()
```

**Origin of `userId`**: it is the `user.userId` field from the login response,
which contains the user's **bcrypt hash** (a string starting with `$2a$08$...`).
It is not the user's UUID nor the sha256 of the mnemonic.

This was the most difficult authentication error to debug: the server returned
`401 Invalid email or password` because `sha256(mnemonic)` was being used as the
Network API password.

**Source**: `inxt-js/src/lib/upload/uploadFileV2.ts`:
```typescript
const creds = {
  user: networkCredentials.user,        // bridgeUser
  pass: networkCredentials.pass,        // userId (bcrypt hash)
};
// The library builds Basic Auth with sha256(creds.pass)
```

**Python implementation**:
```python
def _network_headers(bridge_user: str, user_id: str) -> dict:
    bridge_pass = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
    token = base64.b64encode(f"{bridge_user}:{bridge_pass}".encode()).decode()
    return {"Authorization": f"Basic {token}", ...}
```

### 9.2 Upload Flow (4 steps)

**Step 1**: Start the upload on the Network API.
```
POST https://gateway.internxt.com/network/v2/buckets/{bucket_id}/files/start?multiparts=1
Auth: Basic <network_credentials>
Body: {"uploads": [{"index": 0, "size": <bytes>}]}

Response: {"uploads": [{"url": "<s3_presigned_url>", "uuid": "<shard_uuid>"}]}
```

The `url` is an S3 (or compatible object storage) pre-signed URL with an expiry
time. The `uuid` is the shard identifier in Internxt's system.

**Step 2**: Upload the encrypted content directly to storage.
```
PUT <presigned_url>
Content-Type: application/octet-stream
Body: <AES256CTR_encrypted_bytes>
```

This request goes directly to the storage provider (S3, Backblaze, etc.),
**not** through Internxt's servers. This is the E2E design: Internxt never sees
the decrypted content.

**Step 3**: Notify the Network API that the upload is complete.
```
POST https://gateway.internxt.com/network/v2/buckets/{bucket_id}/files/finish
Auth: Basic <network_credentials>
Body: {
    "index": "<index_hex_64_chars>",
    "shards": [{"hash": "<ripemd160_sha256_hex>", "uuid": "<shard_uuid>"}]
}

Response: {"id": "<network_file_id>"}
```

**Step 4**: Register the file in the Drive API (metadata).
```
POST https://gateway.internxt.com/drive/files
Auth: Bearer <jwt>
Body: {
    "name": "<file_name>",
    "plainName": "<file_name>",
    "bucket": "<bucket_id>",
    "fileId": "<network_file_id>",
    "encryptVersion": "Aes03",
    "folderUuid": "<destination_folder_uuid>",
    "size": <original_bytes>,
    "type": "<extension_without_dot>",
    "modificationTime": "<iso8601>",
    "date": "<iso8601>"
}
```

The field `encryptVersion: "Aes03"` is the version identifier for Internxt's
current encryption protocol. Earlier versions (01, 02) used different schemes.

---

## 10. Download Protocol

### 10.1 Download Flow (3 steps)

**Step 1**: Get file metadata from the Drive API.
```
GET https://gateway.internxt.com/drive/files/{uuid}/meta
Auth: Bearer <jwt>

Response: {
    "fileId": "<network_file_id>",
    "bucket": "<bucket_id>",
    "size": <bytes>,
    ...
}
```

**Step 2**: Get the index and download URLs from the Network API.
```
GET https://gateway.internxt.com/network/buckets/{bucket}/files/{file_id}/info
Auth: Basic <network_credentials>
Headers: x-api-version: 2

Response: {
    "index": "<index_hex_64_chars>",
    "shards": [{"url": "<presigned_url>", "index": 0, ...}]
}
```

The `x-api-version: 2` header is necessary to get the response in the modern format.
Without it, the response uses the legacy format that does not include direct URLs.

**Step 3**: Download and decrypt.
```
GET <presigned_url>
→ <encrypted_bytes>

index_bytes = bytes.fromhex(index_hex)
iv = index_bytes[:16]
file_key = _derive_file_key(mnemonic, bucket, index_bytes)
plaintext = AES256CTR_decrypt(encrypted, file_key, iv)
```

---

## 11. Trash Management

This was the module that required the most investigation, since public documentation
is non-existent and server behaviour was not obvious.

### 11.1 Discovering the Correct Endpoint

**First approach (failed)**:
```
GET /storage/trash → 404 "Cannot GET /api/storage/trash"
```

The 404 indicated that this endpoint simply does not exist in the current gateway
version (it exists in the SDK as `getTrash()` but the server does not implement it).

**Second approach (partially correct)**:
```
GET /storage/trash/paginated → 400 Bad Request
```

The 400 instead of 404 confirmed that the endpoint exists but parameters are
missing. To discover the correct parameters, the file was inspected:
```
node_modules/@internxt/sdk/dist/drive/trash/index.js
```

The relevant method:
```javascript
Trash.prototype.getTrashedFilesPaginated = function(limit, offset, type, root, folderId) {
    var endpoint = '/storage/trash/paginated';
    var folderIdQuery = folderId !== undefined ? "folderId=" + folderId + "&" : '';
    var url = endpoint + "?" + folderIdQuery + "limit=" + limit + "&offset=" + offset
              + "&type=" + type + "&root=" + root;
    return this.client.get(url, this.headers());
};
```

Required parameters:
- `limit`: number of items per page.
- `offset`: offset for pagination.
- `type`: `"files"` or `"folders"` (not `"file"` in singular — another initial bug).
- `root`: boolean `true` to list from the trash root.

**Response**: the server returns `{"result": [...]}`, not `{"items": [...]}` as the
SDK's TypeScript type suggested. The field name was confirmed by making the real
request.

### 11.2 Trash Endpoints

| Operation | Method | Endpoint | Payload |
|---|---|---|---|
| List (files) | GET | `/storage/trash/paginated?type=files&root=true&limit=N&offset=N` | — |
| List (folders) | GET | `/storage/trash/paginated?type=folders&root=true&limit=N&offset=N` | — |
| Move to trash | POST | `/storage/trash/add` | `{"items": [{"uuid": "...", "type": "file\|folder"}]}` |
| Empty trash | DELETE | `/storage/trash/all` | — |
| Delete permanently | DELETE | `/storage/trash` | `{"items": [{"uuid": "...", "type": "file\|folder"}]}` |

**Bug with `trash/add` payload**: the first implementation used `{"id": uuid}` but
the server expected `{"uuid": uuid}`. The server error was `500 Internal Server
Error` (not a descriptive 400), which made debugging difficult. It was resolved by
testing both variants and confirming with the SDK code.

---

## 12. Bugs Found and How They Were Fixed

This section documents each error found during development, in chronological order.

### Bug 1: `encryptedSalt` vs `sKey`

**Symptom**: `KeyError: 'encryptedSalt'` when trying to log in.

**Cause**: The initial code looked for the `encryptedSalt` field in the server
response, but the real server returns `sKey`.

**Diagnosis**: The real server response was observed:
```json
{"sKey": "53616c7465645f5f...", "tfa": true, ...}
```

**Fix**: Add fallback for multiple field names:
```python
salt = security.get("sKey") or security.get("encryptedSalt") or security.get("encrypted_salt")
```

---

### Bug 2: AES uses hex, not base64

**Symptom**: `401 Unauthorized` when sending the password hash.

**Cause**: The initial implementation of `_aes_encrypt_cryptojs` returned base64
(CryptoJS default behaviour). The server expects hex.

**Diagnosis**: By inspecting the compiled CLI code instead of the TypeScript source,
it was discovered that the `encryptTextWithKey` function has a slight variation that
produces hex.

**Fix**:
```python
return (b"Salted__" + salt + ct).hex()  # hex, not base64
```

---

### Bug 3: `_aes_decrypt_cryptojs` only accepted base64

**Symptom**: `ValueError: non-hexadecimal number found in fromhex()` when
decrypting the `sKey` from the server response.

**Cause**: The `sKey` field comes in hex (which makes sense: AES returns bytes, and
bytes are encoded in hex). The decryption function initially only accepted base64.

**Fix**: Try hex first, fall back to base64 if it fails:
```python
try:
    raw = bytes.fromhex(data)
except ValueError:
    raw = base64.b64decode(data)
```

---

### Bug 4: PBKDF2 salt with incorrect encoding

**Symptom**: `401 Unauthorized`. Login failed even with the password copied
literally.

**Cause**: The decrypted salt is a hexadecimal string (e.g.: `"ad0caeea..."`). When
passing it to PBKDF2 as `plain_salt.encode('utf-8')`, Python interprets it as 32
ASCII bytes (the characters of the hex string). Node.js interprets it as 16 raw
bytes (`Buffer.from(salt, 'hex')`). They produce completely different PBKDF2
outputs.

This was the hardest bug to find because the error was silent (the server simply
returned 401) and required understanding exactly what CryptoJS does internally.

**Diagnosis**: Reading the CryptoJS source code and the Internxt SDK together:
`CryptoJS.enc.Hex.parse(passObject.salt)` converts from hex to a WordArray of bytes.

**Fix**:
```python
salt_bytes = bytes.fromhex(plain_salt)   # CRITICAL: not .encode('utf-8')
```

---

### Bug 5: Incorrect 2FA field name

**Symptom**: `400 Bad Request` with the 2FA code.

**Cause**: The code was sent in the `twoFactorCode` field. The server expects `tfa`.

**Fix**:
```python
payload["tfa"] = tfa  # not "twoFactorCode"
```

---

### Bug 6: `root_folder_uuid` was numeric

**Symptom**: `400 Bad Request` or `"uuid must be a UUID string"` when listing the
root folder.

**Cause**: `user.root_folder_id` (integer: `41230090`) was saved instead of
`user.rootFolderUuid` (UUID: `"3285b174-..."`).

**Diagnosis**: The login response contains both fields. The modern API requires the
UUID.

**Fix**:
```python
"root_folder_uuid": user.get("rootFolderUuid") or user.get("rootFolderId") or user.get("root_folder_id")
```

---

### Bug 7: `size` as a string in file responses

**Symptom**: `TypeError: '<' not supported between instances of 'str' and 'int'`.

**Cause**: The `size` field of a file in the API sometimes arrives as the string
`"948"` instead of the integer `948`.

**Fix**:
```python
size = int(f.get("size") or 0)
```

---

### Bug 8: Network API auth with mnemonic hash

**Symptom**: `401 Invalid email or password` when uploading or downloading files.

**Cause**: `sha256(mnemonic)` was used as the Network API password. The correct
field is `sha256(user.userId)` where `userId` is the user's bcrypt hash.

**Diagnosis**: Reading `inxt-js/src/lib/upload/uploadFileV2.ts` and tracing the
`networkCredentials.pass` variable back to its origin in the user object.

**Fix**:
```python
bridge_pass = hashlib.sha256(user_id.encode("utf-8")).hexdigest()
# where user_id = user["userId"] = "$2a$08$..."
```

---

### Bug 9: `parentUuid` vs `parentFolderUuid`

**Symptom**: `400 Bad Request: "parentFolderUuid must be a UUID"` when creating
folders.

**Cause**: The `POST /folders` payload used the field `parentUuid`. The server
expects exactly `parentFolderUuid`.

**Fix**:
```python
{"parentFolderUuid": parent_uuid}  # not "parentUuid"
```

---

### Bug 10: `destinationFolder` expected UUID, not numeric ID

**Symptom**: `400 Bad Request: "destinationFolder must be a UUID"` when moving
items.

**Cause**: The move PATCH used the numeric parent ID obtained from metadata. The
`destinationFolder` field in the PATCH expects a UUID.

**Fix**: Pass the destination folder UUID directly (already available from
`_resolve_path`) without converting it to a numeric ID.

---

### Bug 11: `trash/add` uses `uuid`, not `id`

**Symptom**: `500 Internal Server Error` when moving to trash.

**Cause**: The payload used `{"id": uuid}`. The server expects `{"uuid": uuid}`.

**Diagnosis**: Direct testing with both variants. The 500 error (instead of 400)
made debugging difficult.

**Fix**:
```python
{"items": [{"uuid": uuid, "type": item_type}]}
```

---

### Bug 12: `trash list` returns `result`, not `items`

**Symptom**: Trash always appeared empty even though there were items in it.

**Cause**: The response field is `result`, not `items`:
```json
{"result": [...]}
```

The SDK's TypeScript type declared `items` but the real server returns `result`.

**Fix**:
```python
chunk = data.get("result", data.get("items", []))
```

---

### Bug 13: `trash clear` used POST, not DELETE

**Symptom**: `405 Method Not Allowed`.

**Cause**: `POST /storage/trash/clear` was used. The correct endpoint is
`DELETE /storage/trash/all`.

**Fix**:
```python
client.delete("/storage/trash/all")
```

---

## 13. Verified Endpoint Map

All endpoints in this table have been tested in production and work correctly with
credentials from a free-plan user.

### Drive API (`https://gateway.internxt.com/drive`)

| Method | Endpoint | Function | Auth |
|--------|----------|----------|------|
| POST | `/auth/login` | Get salt + 2FA flag | None |
| POST | `/auth/login/access` | Authenticate, get JWT | None |
| GET | `/users/me` | User info | Bearer JWT |
| GET | `/users/usage` | Bytes used | Bearer JWT |
| GET | `/users/limit` | Space limit | Bearer JWT |
| GET | `/folders/content/{uuid}/folders` | List subfolders | Bearer JWT |
| GET | `/folders/content/{uuid}/files` | List files | Bearer JWT |
| GET | `/folders/{uuid}/meta` | Folder metadata | Bearer JWT |
| POST | `/folders` | Create folder | Bearer JWT |
| PUT | `/folders/{uuid}/meta` | Rename folder | Bearer JWT |
| PATCH | `/folders/{uuid}` | Move folder | Bearer JWT |
| GET | `/files/{uuid}/meta` | File metadata | Bearer JWT |
| POST | `/files` | Register uploaded file | Bearer JWT |
| PUT | `/files/{uuid}/meta` | Rename file | Bearer JWT |
| PATCH | `/files/{uuid}` | Move file | Bearer JWT |
| POST | `/storage/trash/add` | Move to trash | Bearer JWT |
| GET | `/storage/trash/paginated` | List trash | Bearer JWT |
| DELETE | `/storage/trash/all` | Empty trash | Bearer JWT |
| DELETE | `/storage/trash` | Delete permanently | Bearer JWT |

### Network API (`https://gateway.internxt.com/network`)

| Method | Endpoint | Function | Auth |
|--------|----------|----------|------|
| POST | `/v2/buckets/{bucket}/files/start` | Start upload | Basic (bridge) |
| POST | `/v2/buckets/{bucket}/files/finish` | Confirm upload | Basic (bridge) |
| GET | `/buckets/{bucket}/files/{fileId}/info` | Download info | Basic (bridge) |

### Direct Storage (S3/compatible)

| Method | Description | Auth |
|--------|-------------|------|
| PUT `<presigned_url>` | Upload encrypted bytes | Pre-signed URL |
| GET `<presigned_url>` | Download encrypted bytes | Pre-signed URL |

---

## Final Notes

Internxt's encryption system is genuine: data is uploaded encrypted with a key
derived from the user's mnemonic, and Internxt never has access to the key. The
server only ever sees opaque ciphertext.

The restriction that motivated this project operates **exclusively at the
authentication layer** (endpoint `/auth/cli/login/access` vs `/auth/login/access`)
and does not affect any cryptographic or storage functionality. Once the JWT is
obtained via the web endpoint, the rest of the API works identically for all users
regardless of plan.

---

*Generated on 2026-03-11. Code at `/home/alfonso/internxt/internxt.py`.*
