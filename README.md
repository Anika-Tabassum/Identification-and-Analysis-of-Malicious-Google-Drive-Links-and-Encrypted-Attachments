# Identification-and-Analysis-of-Malicious-Google-Drive-Links-and-Encrypted-Attachments
🚀 This project automates the detection and analysis of potentially malicious Google Drive links and encrypted email attachments. It helps identify threats by scanning and evaluating suspicious content using VirusTotal within a Dockerized environment.


🛠️ Tech Stack
- Python (Core logic and analysis)
- Docker (Containerized execution environment)


⚙️ Prerequisites:
1. Email address
2. App password
3. Virus total API key


📦 Installation steps:
1. Clone the repository.
2. Ensure you have Docker installed. If not, install it from [here](https://www.docker.com/).
3. Build the Docker image: ```docker build -t image_name "path to the folder containing your docker file"```
4. Build the Docker container and execute the app in it: ```docker run -it --rm image_name python3 /app/app_file_name.py```


✅ Features
- Detects potentially malicious Google Drive links
- Scans encrypted attachments for threats
- VirusTotal API integration for threat detection and report generation
- Dockerized for isolation and safety


👨‍💻 Author:
Khalida Anika Tabassum
