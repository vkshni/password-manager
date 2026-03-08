# Shield — CLI Password Manager

A command-line password vault built with pure Python. No external dependencies. No encryption libraries. Security through hashing, authentication flow, and access control logic.

Built as Week 4 of a systems programming curriculum — the first project where design mistakes have real security consequences.

---

## What It Does

Shield stores your service credentials (username + password) behind a single master password. You remember one password. Shield remembers the rest.

- One master password protects the entire vault
- Passwords are stored in plain text inside the vault — security comes from the authentication gate, not encryption
- The master password is never stored — only its SHA-256 hash
- Brute-force protection via lockout after 3 failed attempts
- Lockout persists across restarts — cannot be bypassed by closing the program
- Multiple accounts per service supported via labels (e.g. `instagram/personal`, `instagram/work`)

---

## Security Model

```
vault_data.json (plain text passwords)
        ↑
        │  protected by
        ↓
Master password gate (SHA-256 hash verification)
        ↑
        │  timing-attack resistant via
        ↓
hmac.compare_digest() constant-time comparison
```

**What is protected:** The master password itself — hashed with SHA-256, compared with `hmac.compare_digest()` to prevent timing attacks. Failed attempts are persisted to disk so lockout cannot be bypassed by restarting.

**What is not protected:** The credential records themselves are plain text on disk. If someone gains filesystem access to `vault_data.json`, they can read passwords directly. This is a deliberate scope constraint — the project trains authentication flow, not encryption.

**If the master password file is deleted:** The vault data becomes permanently inaccessible through Shield. This is correct behavior — the data without the key is useless.

---

## Project Structure

```
password-manager/
│
├── shield.py          ← CLI entry point. All commands and session loop.
├── vault.py           ← Core vault operations. Enforces auth on all actions.
├── authservice.py     ← Authentication, session state, lockout logic.
├── shield_db.py       ← Storage layer. Reads and writes all JSON files.
├── pwd_entity.py      ← Credential data model. Serialization and validation.
├── setup.py           ← Setuptools config. Installs the 'shield' command.
├── test.py            ← Test suite. Run after install to verify everything works.
│
└── database/          ← Auto-created on first run.
    ├── vault_meta.json    ← Master password hash only.
    ├── vault_data.json    ← All credential records.
    └── attempts.json      ← Failed login attempts and lockout state.
```

---

## Requirements

- Python 3.10 or higher
- No external packages — standard library only

---

## Installation

Clone or download the project, then from the project root:

```bash
pip install -e .
```

This installs the `shield` command globally so you can run it from any directory.

### Verify Installation

After installing, run the test suite to confirm everything works correctly:

```bash
python test.py
```

All 25 tests should pass. The test suite creates its own isolated database files and deletes them automatically after running — your vault data is never touched.

---

## Usage

### First Run — Create Your Vault

```bash
shield setup
```

You will be prompted to create a master password (input is hidden). This runs once. If you run it again after a vault exists, it will be blocked.

### Open Your Vault

```bash
shield login
```

Enter your master password. After 3 wrong attempts the vault locks for 30 seconds. On success, the interactive menu opens.

### Interactive Menu

```
  [1]  List services
  [2]  Add credential
  [3]  Get credential
  [4]  Update credential
  [5]  Delete credential
  [6]  Exit
```

Navigate by typing the number and pressing Enter. The session stays open until you choose Exit or press Ctrl+C.

### Viewing a Password

Selecting **Get credential** shows the username immediately but requires you to re-enter the master password before the actual password is revealed. This re-authentication does not count toward the lockout limit.

---

## Layer Architecture

```
shield.py        ← CLI layer. Input, output, error display.
     ↓
vault.py         ← Business logic. Auth enforcement, uniqueness rules.
     ↓
authservice.py   ← Auth layer. Hashing, verification, session, lockout.
     ↓
shield_db.py     ← Storage layer. JSON read/write only. No logic.
     ↓
pwd_entity.py    ← Data model. Serialization, validation.
```

Each layer only talks to the layer directly below it. The CLI never touches the database. The database never enforces business rules.

---

## What This Project Trains

- Hashing and verification without reversibility
- Constant-time comparison to prevent timing attacks
- Persistent brute-force protection across restarts
- Session state management in a CLI loop
- Separation of authentication from data operations
- Layered architecture with clear responsibility boundaries
- Defensive programming — every operation validates before acting

---

## Limitations (By Design)

These are intentional constraints, not missing features:

- No encryption — credentials are plain text on disk
- No password generator
- No password strength checker
- No clipboard copy
- No multi-user support
- No export
- No account recovery if master password is lost