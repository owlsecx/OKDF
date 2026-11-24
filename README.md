# 🦉 OKDF

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-Crypto%20/%20Cipher-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-GPL--3.0-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0-cyan?style=flat-square"/>
</p>

> **OKDF** — Key-derivation playground (pbkdf2/HKDF; scrypt/argon2id/bcrypt notes) ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

OKDF — Key-derivation playground (pbkdf2/HKDF; scrypt/argon2id/bcrypt notes). Key-Derivation Playground (PBKDF2 / HKDF) PBKDF2 (RFC 2898) and HKDF (RFC 5869) implemented from scratch on crypto/hmac and the SHA-2 family. Derive keys, verify password hashes in constant time, calibrate iteration cost, and document the memory-hard KDFs (scrypt/Argon2id/bcrypt) that live outside the standard library.

---

## ✨ Features

- Interactive key-derivation playground for PBKDF2 and HKDF
- Documented notes for scrypt, argon2id and bcrypt parameters
- Compare iteration/memory trade-offs for password-based keys
- Safe local experimentation with stdlib cryptography
- Clear parameter validation and example workflows
- Export derived-key experiment reports

---

## ⚙️ Requirements

- **Linux**
- **Go 1.21+** (stdlib only; `CGO_ENABLED=0`)

---

## 🚀 Usage

```bash
go build -ldflags="-s -w" -o OKDF OKDF.go
./OKDF --help
./OKDF --algo pbkdf2 --password secret --salt deadbeef
./OKDF --algo hkdf --format json
./OKDF --demo
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

**GNU General Public License v3.0** — © 2026 Owlsec LLC

This tool is free software: its full source code is published in this repository and you may study, modify and redistribute it under the GPL-3.0.

> Other OwlSec tools are separate, independent programs under their own terms; many remain proprietary.
