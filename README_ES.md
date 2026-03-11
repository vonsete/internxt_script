# Internxt Drive CLI

A Python CLI to manage your Internxt Drive files without requiring a premium plan.

Internxt restricted their official CLI (`@internxt/cli`) to paid plans. This script
authenticates through the standard web endpoint instead of the plan-gated CLI
endpoint, giving free users full access to their drive via the command line.

## Features

- List files and folders
- Create folders
- Move and rename files and folders
- Delete (to trash or permanently)
- Manage trash (list, clear)
- Upload files with native E2E encryption (AES-256-CTR)
- Download files with native E2E decryption
- Two-factor authentication (2FA) support
- No Node.js required

## Requirements

- Python 3.10+
- `requests`
- `cryptography`

## Installation

```bash
git clone https://github.com/vonsete/internxt_script.git
cd internxt_script
pip install -r requirements.txt
```

Optional alias:

```bash
alias internxt='python3 /path/to/internxt.py'
```

## Authentication

### Option A — Interactive login (recommended)

```bash
python3 internxt.py login
```

Prompts for email, password, and 2FA code if enabled. Credentials are saved to
`~/.internxt-tools/credentials.json`.

### Option B — Browser token

If you prefer not to enter your password in the terminal:

1. Log in at [drive.internxt.com](https://drive.internxt.com)
2. Open DevTools → Application → Local Storage → `drive.internxt.com`
3. Copy the value of `xNewToken`

```bash
python3 internxt.py token
```

## Usage

```bash
# List root
python3 internxt.py ls

# List a folder
python3 internxt.py ls /Documents/Work

# Create a folder
python3 internxt.py mkdir /Backups/2025

# Move a file into a folder
python3 internxt.py mv /Documents/report.pdf /Backups/2025/

# Move and rename in one step
python3 internxt.py mv /Documents/draft.docx /Documents/final.docx

# Rename only (no path change)
python3 internxt.py rename /Documents/old-name.txt new-name.txt

# Move to trash
python3 internxt.py rm /Documents/file.txt

# Delete permanently (bypass trash)
python3 internxt.py rm --permanent /Documents/file.txt

# Trash management
python3 internxt.py trash list
python3 internxt.py trash clear

# Account storage info
python3 internxt.py info

# Upload a file
python3 internxt.py upload ./photo.jpg /Photos/

# Download a file
python3 internxt.py download /Documents/contract.pdf ./local/
```

## How it works

Internxt uses end-to-end encryption for all files. This script reimplements the
full cryptographic stack in pure Python:

- **Authentication**: AES-256-CBC (CryptoJS-compatible) + PBKDF2-SHA1 password
  hashing, identical to the official SDK.
- **File encryption**: AES-256-CTR with a key derived from your BIP39 mnemonic
  via a SHA-512 chain (`seed → bucket_key → file_key`).
- **File hash**: `RIPEMD160(SHA256(encrypted))` for Network API integrity checks.

Files are uploaded directly to Internxt's object storage (pre-signed URLs) —
the server never sees plaintext content.

For the full technical breakdown, including the complete reverse engineering
process, all API endpoints, and every bug found and fixed, see:

- [`TECHNICAL_ES.md`](TECHNICAL_ES.md) — Spanish
- [`TECHNICAL_EN.md`](TECHNICAL_EN.md) — English

## Credentials storage

Credentials are saved in `~/.internxt-tools/credentials.json` (plain JSON,
not encrypted). This file contains your decrypted mnemonic. Keep it secure and
do not share it.

## Limitations

- Upload/download works for single files only (no recursive folder upload).
- Trash restore is not fully tested.
- No progress bar for large file uploads.

## License

MIT
