# SOC Automation Script

## Overview

This script is designed for SOC (Security Operations Center) analysts to automate network traffic capture, process PCAP files, and detect IOCs (Indicators of Compromise). It leverages tools like `tshark` and `jq` for packet analysis and integrates with VirusTotal for malware detection.

## Features

- **Traffic Capture**: Continuously captures network traffic and saves it as PCAP files.
- **PCAP Processing**: Monitors and processes the latest PCAP files for DNS queries and HTTP requests.
- **IOC Detection**: Matches DNS queries and responses against configured IPs and URLs.
- **File Extraction**: Extracts files from HTTP traffic and calculates their hashes.
- **VirusTotal Integration**: Queries VirusTotal for hash analysis to identify malicious files.
- **Automated Cleanup**: Ensures resources are cleaned up when the script exits.

## Prerequisites

- **Operating System**: Linux
- **Dependencies**:
  - `tshark`
  - `jq`
  - `curl`
  - `sha256sum`

## Installation

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/crimsoncybr/SOChunter.git
    cd SOChunter
    ```

2. **Ensure Dependencies are Installed**:
    The script will check for `tshark` and `jq` and install them if they are not present.

3. **Configuration**:
    - Modify `configuration/hunter.conf` to set `FILE_SIZE` and other parameters.
    - Add IPs to `configuration/IOC_IP.conf`.
    - Add URLs to `configuration/IOC_URL.conf`.
    - Insert your VirusTotal API key in the `virus_total` function within the script.

## Usage

Run the script using the following command:
```bash
./hunter.sh
