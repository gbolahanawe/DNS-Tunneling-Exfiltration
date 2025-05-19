# DNS Tunneling Exfiltration Lab

This lab demonstrates how data can be covertly exfiltrated using DNS tunneling techniques. The project simulates a controlled environment with a victim machine and a listener, and uses `DNSExfiltrator` for the attack.

## 🔧 Tools Used
- DNSExfiltrator (PowerShell)
- Wireshark
- Auditd
- Kali Linux / Windows VM
- Custom domain: `mydomain.local`

## 🧪 Lab Objectives
- Simulate DNS-based data exfiltration
- Capture and analyze DNS traffic
- Detect and log suspicious DNS queries
- Implement mitigations and monitoring

## 📁 Project Structure
```
dns-tunneling-lab/
├── README.md
├── setup-guide.md
├── exfiltration-script.ps1
├── wireshark-capture-sample.pcapng
├── auditd-rules.conf
└── screenshots/
```

## 🚀 How to Use
1. Follow the instructions in `setup-guide.md`
2. Run the DNSExfiltrator script from the victim machine
3. Monitor network traffic and Auditd logs
4. Analyze findings with Wireshark

## 📸 Screenshots
Screenshots of execution and detection are stored in the `screenshots/` directory.

## 📚 References
- https://github.com/Arno0x/DNSExfiltrator
