# Windows-Security-Checks

A comprehensive PowerShell script that performs modern security checks on Windows 10/11 systems. Updated for 2023-2024 security features including VBS, Credential Guard, TPM 2.0, Attack Surface Reduction, and enhanced Windows Defender protections.
<img width="1963" height="816" alt="image" src="https://github.com/user-attachments/assets/25d0751a-9705-4dfa-90dc-867cc3f36459" />


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
- **Defender Exclusions** - Lists and counts path, extension, process, and IP exclusions (security risk if excessive)

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

### Running as Administrator (Recommended)

For complete security assessment with all checks:

1. Open PowerShell **as Administrator**
2. Navigate to the directory where the script is saved
3. Run the script:
   ```powershell
   PowerShell.exe -ExecutionPolicy Bypass -File "C:\path\to\check.ps1"
   ```
4. Review the generated security report

### Running as Standard User (VDI/Workstations)

The script now supports **non-administrator execution** for environments where users don't have local admin rights (VDI, locked-down workstations):

1. Open PowerShell (no admin rights required)
2. Navigate to the directory where the script is saved
3. Run the script:
   ```powershell
   PowerShell.exe -ExecutionPolicy Bypass -File "C:\path\to\check.ps1"
   ```

**Note:** When running as a standard user:
- Most checks will still work (Defender status, VBS, Credential Guard, Secure Boot, UAC, RDP, etc.)
- Some checks require admin privileges and will show a warning message:
  - **TPM 2.0 status** - Hardware security module queries require elevation
  - **BitLocker encryption status** - Drive encryption queries require elevation
  - **SMBv1 status** - Optional features query requires elevation
  - **SMB Signing & Encryption** - SMB configuration requires elevation
  - **Audit Policy configuration** - Security audit settings require elevation
  - **Defender Exclusions** - Detailed exclusion list requires elevation
  - **Network adapter settings** - May vary by system configuration
- The script will clearly indicate which checks were skipped due to insufficient privileges
- **Secure Boot** uses registry fallback and works for non-admin users

## Support

If you would like to support this project, you can make a donation through PayPal:

[![Donate with PayPal](https://img.shields.io/badge/Donate-PayPal-blue)](https://www.paypal.com/donate/?business=P9L4Y9YQYEW3Y&no_recurring=0&currency_code=EUR)

Don't forget to give this repo a ✨ STAR!

## Disclaimer

This script is provided as-is and without warranty. Use at your own risk. The author is not responsible for any damages or losses caused by the use of this script.
