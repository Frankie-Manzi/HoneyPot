# HoneyPot

## Objective

The HoneyPot project aimed to deploy and monitor a T-Pot HoneyPot to capture and analyse real-world cyber threats. The primary focus was to use Elastic Stack (Kibana) for log visualisation and VirusTotal for threat intelligence to identify malicious actors, attack patterns and high risk IPs. This hands on experience was designed to deepen my understanding of: threat detection, incident response and poractive cybersecurity defense through log analysis, network forensics and automated threat intelligence enrichment

### Skills Learned

- Log analysis with ELK Stack - KQL language.
- Improved threat detection and analysis.
- Enhanced knowledge of network forensics.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.
- Strengthened pattern recognition and attack behaviour

### Tools Used

- Tpot - multi-honeypot platform using various honeypots to capture attacks.
- ELK Stack - used for log collection, visualisation and analysis of honeypot activity.
- Suricata (IDS) - To detect malicious network activity.
- VirusTotal - To check if an attacker's IP address is flagged as malicious by other vendors
- Firewall monitoring - Protect honeypot, only host IP can connect to main frame, allowed inbound connections from all other IPs - for log acquisition
- [Python script to parse logs generated from Suricata](https://github.com/frankie-manzi/Python-Scripts/blob/main/Log-Parsing-Scripts/Honeypot-Analyser/Honeypot-Analyser-Final.py)


## Steps

- Main dashboard of the TPot setup with different dashboards to enter
![Screenshot 2025-03-27 195754](https://github.com/user-attachments/assets/b0aefbec-895a-48aa-bf05-99f4ac07804e)
- Attack map consisting of the first event after configuring fire wall to allow inbound connections from all IPs 
![Screenshot 2025-03-27 200240](https://github.com/user-attachments/assets/ee8b5d12-2190-4f2c-bdd7-192f93dc3a59)
- Attack map after 10 minutes - shows an influx of inbound connections from numerous IPs belonging to multiple geographical locations
![Screenshot 2025-03-27 200724](https://github.com/user-attachments/assets/a2050c64-61d3-4e8c-b101-86480ec28476)
- Kibana dashboard shows logs of all events, that i used to parse and practise my KQL language and syntax
![Screenshot 2025-03-27 200605](https://github.com/user-attachments/assets/5533ccff-6bd1-4c34-ae29-4906f69472d2)
- Browser on the left shows an IP that established an inbound connection to one of the honeypots, containing information such as source IP as well as source port used. Browser on the right shows OSINT of the IP, that established an inbound connection to the honeypot, and it was flagged as malicious by 4 vendors and flagged as suspicious by 2 vendors on VirusTotal
![Screenshot 2025-03-27 211856](https://github.com/user-attachments/assets/02b4c82e-a6ab-4f8b-bede-09eb762ec887)
- Attack map over an hour later - consists of hundreds of connections from various IPs and countries as well as the service each IP was attempting to connect to
![Screenshot 2025-03-27 211207](https://github.com/user-attachments/assets/2a65c1c6-9be3-47da-a86c-a221a8a9b2d2)
- Dasboard that provides more information about the inbound connections of the various IPs, information such as: the attacker reputation, which honeypot was targetted, attacks by country and port used, what operating system was used and attacks by country
![Screenshot 2025-03-27 211315](https://github.com/user-attachments/assets/42a665ea-6257-43d1-9d4e-b22deee6f660)
- More information from the dashboard shows each honeypot that was attacked and how many times and shows a bar chat reflecting that data and shows a smaller version of the attack map with dots reflecting the country the inbound connection was received from
![Screenshot 2025-03-27 211326](https://github.com/user-attachments/assets/006b22bd-78a1-4acf-94b4-c4c4f59e0c0c)
- Shows a bar chart in Kibana after filtering for the top 5 source_IP values
![Screenshot 2025-03-27 211649](https://github.com/user-attachments/assets/f99012d1-5a20-4d63-95dd-90f3246212d8)
- Query in kibana to filter for failed login attempts from a particular source IP address that had made a high frequency of inbound connections. Shows evidence of a brute force attack - high frequency of failed login attempts for a variety of usernames and passwords
![Screenshot 2025-03-28 201253](https://github.com/user-attachments/assets/d6e83b18-58a2-4c36-abe7-212692aba73e)
- Running the source IP address in VirusTotal to gain more knowledge about the reputation of the IP address. Shows 15 other vendors flagged as malicious with possible malware and phishing attempts.
- ![Screenshot 2025-03-28 201313](https://github.com/user-attachments/assets/fee94c09-ce39-4883-a9d8-e5d1ae0b3666)






