# 🛡️ Rule-Based Network Intrusion Detection System (NIDS)

A lightweight **Network Intrusion Detection System (NIDS)** built in Python using **Scapy** and **PyShark** for rule-based packet analysis.  
This project monitors live network traffic (or `.pcap` files), applies predefined security rules, and generates **real-time alerts** and **log files** for suspicious activities.  

---

## 📌 Features
- Capture live network packets or read from saved `.pcap` files.  
- Rule-based detection of common threats:
  - Excessive requests from a single IP (possible DoS).  
  - Access attempts from blacklisted IPs.  
  - Unusual or restricted port usage.  
- Real-time alerts in the terminal.  
- Logging of all flagged activities with timestamp and details.  
- Lightweight implementation without machine learning complexity.  

---

## ⚙️ Technologies Used
- **Python 3.x**  
- **Scapy** (packet capture and analysis)  
- **PyShark** (alternative packet parsing)  
- **Pandas** (log management & data handling)  
- **Wireshark** (for verification & packet inspection)  

---

## 📂 Project Structure
