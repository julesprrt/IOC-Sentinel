# 🛡️ IOC Sentinel – Browser Extension for CTI & SOC Analysts

[![Chrome](https://img.shields.io/badge/Chrome-Extension-blue?logo=googlechrome)](https://chrome.google.com/webstore) 
[![Edge](https://img.shields.io/badge/Edge-Extension-green?logo=microsoftedge)](https://microsoftedge.microsoft.com/addons) 
[![License](https://img.shields.io/badge/license-Custom-orange.svg)](#license)

**IOC Sentinel** is a lightweight browser extension that helps CTI and SOC analysts extract, clean, and investigate Indicators of Compromise (IOCs) directly from web pages.  
No more manual copy-paste — get clean IOCs, ready to export or hunt in your SIEM/EDR.

---

## ✨ Features

✅ **Multi-type IOC extraction**  
- IPv4, domains, URLs (`http/https`, `ftp`, `tcp/udp`)  
- Email addresses  
- File artifacts (`.exe`, `.dll`, `.bat`, etc.)  
- Hashes: **MD5, SHA1, SHA256** (auto-detection)  

✅ **Smart de-obfuscation**  
- Converts `hxxp`, `[.]`, `(.)`, `[@]`, and similar formats automatically.  

✅ **IOC Management & Actions**  
- Copy, export **CSV/JSON**  
- Open directly in **VirusTotal**  
- Generate ready-to-use **KQL queries** for Microsoft Defender / Sentinel  

✅ **Whitelist Manager**  
- Exclude known-good IOCs (IPs, domains, URLs, hashes, emails, files)  
- Supports **CIDR ranges** and **wildcards** (`*.example.com`)  

✅ **Modern UI**  
- Dark/Light mode toggle 🌙☀️  
- Category tabs with counters  
- Quick actions per IOC and global batch actions  

---

## 🎯 Why IOC Sentinel?

- Save **hours of manual copy-paste** during CTI analysis  
- Standardize IOC collection across the SOC  
- Go from **blog post → IOC hunt** in a few clicks  
- Lightweight, **no external dependencies**, everything stays in your browser  

---

## 🚀 Installation

### Manual
1. Clone this repository:  
   ```bash
   git clone https://github.com/julesprrt/ioc-sentinel.git
   ```
2. Open **chrome://extensions/** (Chrome) or **edge://extensions/** (Edge).  
3. Enable **Developer mode**.  
4. Click **Load unpacked** and select the project folder.  
5. The 🛡️ IOC Sentinel icon will appear in your browser toolbar.

---

## 📌 Example Workflow

1. Open a CTI report or pastebin dump with obfuscated IOCs.  
2. IOC Sentinel automatically **detects, refangs, and classifies** them.  
3. Copy/export IOCs or generate a **KQL hunting query** in one click.  
4. Validate in **VirusTotal** or enrich with **WHOIS lookups**.  
5. Add legitimate entries (Google, Microsoft, etc.) to the **whitelist**.

---

## 🛠️ Roadmap

- [ ] Add support for SHA-512 / NTLM hashes  
- [ ] Sigma / YARA rule generation  
- [ ] MISP / OpenCTI API integration  
- [ ] Collaborative mode (share whitelists across a team)  

---

## 📸 Screenshots

*(insert screenshots of your popup UI, whitelist manager, and pirate logo here)*

---

## 📜 License

Custom license – internal/SOC usage.  
Adapt according to your organization’s needs.  

---

## 🤝 Contributing

Pull requests and feature requests are welcome!  
Feel free to open an issue if you spot a bug or have an idea 💡.

