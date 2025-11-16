
<<<<<<< HEAD
<p align="center">
  <img src="./assets/branding/sadran.png" width="260" />
</p>


# Sadran Security

Sadran Security is an open-source, next-generation WordPress security framework offering deep hardening, malware detection, integrity monitoring, login protection, and guided server-level remediation.  
Designed for developers, agencies, and site owners who want transparent, high-quality security without paywalls or restrictions.

---

## 🚀 Features

### 🔒 Core Hardening
- Disable vulnerable WordPress features (XML-RPC, file editor, unsafe REST endpoints).
- Must-Use Plugin mode to prevent deactivation by attackers.
- Prevent PHP execution in uploads and unsafe directories.
- Enforce safer permissions and configuration rules.

### 🛡 Intrusion Detection
- File integrity monitoring with baseline hashing.
- Suspicious file detection (PHP shells, obfuscated payloads).
- Plugin/theme tampering alerts.
- Admin account creation auditing.

### 🔐 Login & Firewall Protection
- Brute force protection and login rate limiting.
- IP blocking and temporary lockouts.
- Early-stage request filtering (WAF-style behavior).
- Optional 2FA enforcement (planned).

### 🧬 Malware Detection
- Signature-based detection for known malware families.
- Heuristic scanning for altered or suspicious code.
- Pattern-based detection for common WordPress exploit kits.

### 🧰 Remediation Engine
- Auto-generated Linux hardening script based on detected issues.
- Guidance for hosting-panel users without SSH access.
- Recommended fixes for PHP config, permissions, and server settings.

### 🧱 Developer-Friendly Architecture
- Modular scanners (extendable).
- Fully namespaced codebase.
- WP-CLI command support (planned).
- Clear class-based structure for easy contributions.

---

## 📦 Installation

### Standard WordPress Plugin Installation
Place the folder here:

wp-content/plugins/sadran-security/

Activate normally in the WordPress dashboard.

### MU-Plugin (Always-On Protection)
Place the MU file here:

wp-content/mu-plugins/sadran-security.php


This prevents attackers from disabling the security engine.

---

## 📂 Project Structure


sadran-security/
│ sadran-security.php
│ README.md
│ LICENSE
│ composer.json
│ .gitignore
│
├── admin/
├── includes/
│ ├── Scanners/
│ ├── Hardening/
│ └── Utils/
│
├── assets/
│ ├── css/
│ └── js/
│
├── src/
├── tests/
└── mu-plugin/
└── sadran-security-mu.php



---

## 🗺 Roadmap

- Full signature-based malware engine  
- Offsite integrity baseline support  
- Threat-intelligence update system  
- CLI scanner integration  
- Real-time logging / telemetry  
- Security policy profiles (Basic / Hardened / Enterprise)  
- Per-website config sync for multisite  

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome.  
Please submit pull requests with clear descriptions and follow the project’s coding style.

---

## 📜 License

This project is licensed under the **GNU General Public License v2.0 or later (GPL-2.0-or-later)**, fully compatible with WordPress core and the open-source plugin ecosystem.

---

## 🛡 Credits

Created by the **Sadran Security Project** — a free, community-driven effort to provide real WordPress security for everyone, on every hosting platform.
=======
# sadran-security
A next-generation WordPress security framework providing deep hardening, malware detection, integrity monitoring, and guided server-level remediation.

=======
>>>>>>> 8ba57a632fc753f198c84320deae1674e067d030
