
# 🕵️ Mini Log Analyzer for Threat Hunting

A **Python-powered log analysis tool** that simulates how a SOC analyst hunts for suspicious activity in logs.

This tool can **parse JSON-formatted Windows/Sysmon logs**, detect **suspicious commands**, and flag potential **malicious activities** using both static signatures and simple behavior detection.

---

## ⚡ Features

* **Dynamic log input** – analyze any log file by providing its path.
* **Suspicious activity detection** – flags:

  * LOLBins like `powershell.exe`, `mshta.exe`, `certutil.exe`.
  * Encoded PowerShell or command-line obfuscation.
  * Unusual external IP connections.
* **Color-coded output** for easy reading.
* **Customizable signatures** – extend the detection with your own rules.

---

## 📦 Installation

1. **Clone the repository:**

```bash
git clone https://github.com/YourUsername/mini-log-analyzer.git
cd mini-log-analyzer
```

2. **Install dependencies:**

```bash
pip install colorama
```

*(Optional: Install `rich` for fancier terminal output)*

---

## ▶ Usage

Run the script and provide your log file path:

```bash
python mini_log_analyzer.py
```

Example prompt:

```
Enter path to JSON log file: C:\logs\sysmon_logs.json
```

---

## 🔍 Example Detection

Sample output:

```
[ALERT] Suspicious Command Detected:
Process: powershell.exe
Command Line: powershell -enc SQBtAGcAbwAgACcAYwBvAG0AcAB1AHQAZQByACcA

[ALERT] Possible Lateral Movement:
Source IP: 192.168.1.10
Destination IP: 45.77.120.50
```

---

## 📖 How It Works

1. Reads JSON-formatted log files.
2. Compares each log entry against a **signature list** of suspicious behaviors.
3. Prints alerts for potential threats.

---

## ⚠ Disclaimer

This tool is for **educational purposes only**.
Use only on **test logs** or in environments where you have permission.

---

## 👨‍💻 Author

**Cybernuel**

* [LinkedIn](https://linkedin.com/in/thedamilare)
* [GitHub](https://github.com/Cybernuel)

