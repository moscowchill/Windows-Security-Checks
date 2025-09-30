# Windows-Security-Checks

A comprehensive PowerShell script that performs modern security checks on Windows 10/11 systems. Updated for 2023-2024 security features including VBS, Credential Guard, TPM 2.0, Attack Surface Reduction, and enhanced Windows Defender protections.

## Security Checks Performed

### Core Windows 11 Security (2023-2024)
- **Virtualization-Based Security (VBS)** - Checks VBS and Memory Integrity (HVCI) status
- **Credential Guard** - Verifies credential theft protection
- **TPM 2.0** - Validates TPM presence, version, and readiness
- **Secure Boot** - Confirms UEFI Secure Boot status

### Windows Defender - Enhanced Checks
- **Enhanced Defender Status** - Real-time protection, cloud protection, network protection, tamper protection, PUA protection, and signature age
- **Attack Surface Reduction (ASR) Rules** - Checks configured ASR rules that prevent Office exploits and script-based attacks
- **Controlled Folder Access** - Anti-ransomware protection for user folders

### Traditional Security Checks (Updated)
- **Firewall** - All profile statuses
- **User Account Control (UAC)** - Prompt configuration
- **Windows Update** - Service status, pending updates, and last update time
- **BitLocker** - Drive encryption status

### Authentication & Access Control
- **Windows Hello for Business** - Modern authentication configuration
- **Guest Account** - Disabled/enabled status
- **Windows LAPS** - Modern built-in LAPS and legacy LAPS detection

### Network Security
- **Remote Desktop (RDP)** - Status, NLA, SSL/TLS encryption, port configuration
- **SMBv1** - Deprecated protocol status
- **SMB Signing & Encryption** - Client/server signing requirements and encryption
- **Network Sharing** - File and printer sharing status

### System Configuration
- **PowerShell Execution Policy** - Script execution restrictions
- **Audit Policy** - Logon/Logoff auditing configuration

The script generates a comprehensive report with color-coded results and outputs it to a text file. This tool can be used to quickly assess the security posture of Windows systems, especially for VDI environments, and identify potential security gaps.

Created by Joe Shenouda (www.shenouda.nl)

## Usage

1. Save the script as a PowerShell file (e.g. check.ps1).
2. Open PowerShell as an administrator.
3. Navigate to the directory where the script is saved.
4. Run the script using the command `PowerShell.exe -ExecutionPolicy Bypass -File "C:\path\to\check.ps1"`.
5. Follow the prompts.

## Support

If you would like to support this project, you can make a donation through PayPal:

[![Donate with PayPal](https://img.shields.io/badge/Donate-PayPal-blue)](https://www.paypal.com/donate/?business=P9L4Y9YQYEW3Y&no_recurring=0&currency_code=EUR)

Don't forget to give this repo a ✨ STAR!

## Disclaimer

This script is provided as-is and without warranty. Use at your own risk. The author is not responsible for any damages or losses caused by the use of this script.
