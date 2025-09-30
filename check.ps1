# Admin check
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator privileges are required for this script. Please run the script as an Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    exit
}

# --- Function Definitions ---

function Get-FirewallStatus {
    try {
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled
        $messages = @()
        $allEnabled = $true
        foreach ($fwProfile in $firewallProfiles) {
            if ($fwProfile.Enabled) {
                $messages += "  - $($fwProfile.Name) Firewall: Enabled"
            } else {
                $messages += "  - $($fwProfile.Name) Firewall: Disabled"
                $allEnabled = $false
            }
        }

        $status = if ($allEnabled) { 'Good' } else { 'Bad' }
        return [PSCustomObject]@{
            CheckName = 'Firewall'
            Status    = $status
            Message   = "Windows Firewall Status:`n" + ($messages -join "`n")
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Firewall'
            Status    = 'Error'
            Message   = "Could not retrieve Firewall status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-UACStatus {
    try {
        $uacValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -ErrorAction Stop).ConsentPromptBehaviorAdmin
        switch ($uacValue) {
            2 {
                $message = "UAC is set to 'Prompt for consent on the secure desktop'."
                $status = 'Good'
            }
            5 {
                $message = "UAC is set to 'Prompt for consent'."
                $status = 'Good'
            }
            0 {
                $message = "UAC is disabled."
                $status = 'Bad'
            }
            default {
                $message = "UAC has an unknown or non-standard setting (Value: $uacValue)."
                $status = 'Warning'
            }
        }
        return [PSCustomObject]@{
            CheckName = 'User Account Control (UAC)'
            Status    = $status
            Message   = $message
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'User Account Control (UAC)'
            Status    = 'Error'
            Message   = "Could not retrieve UAC status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-WindowsUpdateStatus {
    try {
        # Check Windows Update service
        $wuService = Get-Service -Name wuauserv -ErrorAction Stop

        $messages = @()
        $issues = @()

        if ($wuService.Status -eq 'Running') {
            $messages += "Windows Update service: Running"
        } else {
            $issues += "Windows Update service is not running (Status: $($wuService.Status))"
        }

        if ($wuService.StartType -eq 'Automatic' -or $wuService.StartType -eq 'Manual') {
            $messages += "Service start type: $($wuService.StartType)"
        } else {
            $issues += "Windows Update service is disabled"
        }

        # Check for pending updates
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")

            if ($searchResult.Updates.Count -gt 0) {
                $issues += "$($searchResult.Updates.Count) pending update(s) available"
            } else {
                $messages += "No pending updates"
            }
        } catch {
            $messages += "Could not check for pending updates"
        }

        # Check last update time via registry
        try {
            $lastSuccess = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -Name 'LastSuccessTime' -ErrorAction SilentlyContinue
            if ($lastSuccess) {
                $lastUpdateDate = [DateTime]::Parse($lastSuccess.LastSuccessTime)
                $daysSinceUpdate = ((Get-Date) - $lastUpdateDate).Days

                if ($daysSinceUpdate -le 7) {
                    $messages += "Last update: $daysSinceUpdate day(s) ago"
                } elseif ($daysSinceUpdate -le 30) {
                    $issues += "Last successful update was $daysSinceUpdate days ago"
                } else {
                    $issues += "Last successful update was $daysSinceUpdate days ago (critically outdated)"
                }
            }
        } catch {
            # Registry key might not exist, not critical
        }

        $status = if ($issues.Count -eq 0) { 'Good' } elseif ($issues.Count -le 1) { 'Warning' } else { 'Bad' }

        $finalMessage = if ($issues.Count -gt 0) {
            "Issues: " + ($issues -join '; ') + ". " + ($messages -join '; ')
        } else {
            ($messages -join '; ')
        }

        return [PSCustomObject]@{
            CheckName = 'Windows Update'
            Status    = $status
            Message   = $finalMessage + '.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Windows Update'
            Status    = 'Error'
            Message   = "Could not retrieve Windows Update status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-BitLockerStatus {
    try {
        $systemDrive = $env:SystemDrive
        $bitlockerVolume = Get-BitLockerVolume -MountPoint $systemDrive -ErrorAction Stop

        if ($bitlockerVolume.VolumeStatus -eq 'FullyEncrypted') {
            return [PSCustomObject]@{
                CheckName = 'BitLocker'
                Status    = 'Good'
                Message   = "BitLocker is enabled and the system drive ($systemDrive) is fully encrypted."
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'BitLocker'
                Status    = 'Bad'
                Message   = "BitLocker is not fully encrypted on the system drive ($systemDrive). Status: $($bitlockerVolume.VolumeStatus)"
            }
        }
    } catch {
        # Catch errors, including when no BitLocker volume is found for the system drive
        return [PSCustomObject]@{
            CheckName = 'BitLocker'
            Status    = 'Bad'
            Message   = "BitLocker is not enabled or the system drive ($($env:SystemDrive)) is not encrypted. Error: $($_.Exception.Message)"
        }
    }
}

function Get-GuestAccountStatus {
    try {
        $guestAccount = Get-WmiObject -Class Win32_UserAccount -Filter "Name='Guest'" -ErrorAction Stop
        if ($guestAccount.Disabled) {
            return [PSCustomObject]@{
                CheckName = 'Guest Account'
                Status    = 'Good'
                Message   = 'The Guest account is disabled.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Guest Account'
                Status    = 'Bad'
                Message   = 'The Guest account is enabled.'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Guest Account'
            Status    = 'Error'
            Message   = "Could not retrieve Guest Account status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-NetworkSharingStatus {
    try {
        $bindings = Get-NetAdapterBinding | Where-Object { $_.ComponentID -eq 'ms_server' -and $_.Enabled }
        if ($bindings) {
            $adapters = ($bindings | ForEach-Object { $_.DisplayName }) -join ', '
            return [PSCustomObject]@{
                CheckName = 'Network Sharing'
                Status    = 'Bad'
                Message   = "Network sharing (File and Printer Sharing) is enabled on the following adapters: $adapters"
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Network Sharing'
                Status    = 'Good'
                Message   = 'Network sharing (File and Printer Sharing) is disabled on all network adapters.'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Network Sharing'
            Status    = 'Error'
            Message   = "Could not retrieve Network Sharing status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-ExecutionPolicyStatus {
    try {
        $policy = Get-ExecutionPolicy
        if ($policy -in @('Restricted', 'AllSigned', 'RemoteSigned')) {
            return [PSCustomObject]@{
                CheckName = 'PowerShell Execution Policy'
                Status    = 'Good'
                Message   = "PowerShell execution policy is set to '$policy'."
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'PowerShell Execution Policy'
                Status    = 'Bad'
                Message   = "PowerShell execution policy is set to '$policy', which is not secure."
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'PowerShell Execution Policy'
            Status    = 'Error'
            Message   = "Could not retrieve PowerShell Execution Policy. Error: $($_.Exception.Message)"
        }
    }
}

function Get-SecureBootStatus {
    try {
        $isSecureBoot = Confirm-SecureBootUEFI
        if ($isSecureBoot) {
            return [PSCustomObject]@{
                CheckName = 'Secure Boot'
                Status    = 'Good'
                Message   = 'Secure Boot is enabled.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Secure Boot'
                Status    = 'Bad'
                Message   = 'Secure Boot is disabled or not supported.'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Secure Boot'
            Status    = 'Warning' # Changed to Warning as it can throw on non-UEFI systems
            Message   = "Could not determine Secure Boot status. It may not be supported on this system. Error: $($_.Exception.Message)"
        }
    }
}

function Get-SMBv1Status {
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($smb1Feature.State -eq 'Disabled') {
            return [PSCustomObject]@{
                CheckName = 'SMBv1'
                Status    = 'Good'
                Message   = 'SMBv1 is disabled.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'SMBv1'
                Status    = 'Bad'
                Message   = "SMBv1 is enabled (State: $($smb1Feature.State))."
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'SMBv1'
            Status    = 'Error'
            Message   = "Could not retrieve SMBv1 status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-AuditPolicyStatus {
    try {
        $auditPolicy = auditpol.exe /get /category:"Logon/Logoff"
        # Check if both Success and Failure are audited for Logon/Logoff
        if ($auditPolicy -match 'Success and Failure') {
            return [PSCustomObject]@{
                CheckName = 'Audit Policy (Logon/Logoff)'
                Status    = 'Good'
                Message   = 'Audit policy for Logon/Logoff is configured for "Success and Failure".'
            }
        } elseif ($auditPolicy -match 'Success' -or $auditPolicy -match 'Failure') {
            return [PSCustomObject]@{
                CheckName = 'Audit Policy (Logon/Logoff)'
                Status    = 'Warning'
                Message   = 'Audit policy for Logon/Logoff is not configured for both Success and Failure.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Audit Policy (Logon/Logoff)'
                Status    = 'Bad'
                Message   = 'Audit policy for Logon/Logoff is not configured.'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Audit Policy (Logon/Logoff)'
            Status    = 'Error'
            Message   = "Could not retrieve Audit Policy status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-VBSStatus {
    try {
        $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

        if ($null -eq $vbs) {
            return [PSCustomObject]@{
                CheckName = 'Virtualization-Based Security (VBS)'
                Status    = 'Warning'
                Message   = 'VBS information not available. This feature requires Windows 10/11 Enterprise or Pro.'
            }
        }

        $vbsRunning = $vbs.VirtualizationBasedSecurityStatus -eq 2
        $hvciRunning = $vbs.CodeIntegrityPolicyEnforcementStatus -eq 2

        $messages = @()
        $overallStatus = 'Good'

        if ($vbsRunning) {
            $messages += "VBS is enabled and running"
        } else {
            $messages += "VBS is not running"
            $overallStatus = 'Bad'
        }

        if ($hvciRunning) {
            $messages += "Memory Integrity (HVCI) is enabled and running"
        } else {
            $messages += "Memory Integrity (HVCI) is not enabled"
            if ($overallStatus -eq 'Good') { $overallStatus = 'Warning' }
        }

        return [PSCustomObject]@{
            CheckName = 'Virtualization-Based Security (VBS)'
            Status    = $overallStatus
            Message   = ($messages -join '. ') + '.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Virtualization-Based Security (VBS)'
            Status    = 'Warning'
            Message   = "Could not retrieve VBS status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-CredentialGuardStatus {
    try {
        $cg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop

        if ($null -eq $cg) {
            return [PSCustomObject]@{
                CheckName = 'Credential Guard'
                Status    = 'Warning'
                Message   = 'Credential Guard information not available.'
            }
        }

        # SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI
        if ($cg.SecurityServicesRunning -contains 1) {
            return [PSCustomObject]@{
                CheckName = 'Credential Guard'
                Status    = 'Good'
                Message   = 'Credential Guard is enabled and running.'
            }
        } elseif ($cg.SecurityServicesConfigured -contains 1) {
            return [PSCustomObject]@{
                CheckName = 'Credential Guard'
                Status    = 'Warning'
                Message   = 'Credential Guard is configured but not currently running.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Credential Guard'
                Status    = 'Warning'
                Message   = 'Credential Guard is not enabled (default on Windows 11 22H2+).'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Credential Guard'
            Status    = 'Warning'
            Message   = "Could not retrieve Credential Guard status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-TPMStatus {
    try {
        $tpm = Get-Tpm -ErrorAction Stop

        $messages = @()
        $status = 'Good'

        if (-not $tpm.TpmPresent) {
            return [PSCustomObject]@{
                CheckName = 'TPM 2.0'
                Status    = 'Bad'
                Message   = 'TPM is not present on this system. TPM 2.0 is required for Windows 11.'
            }
        }

        if (-not $tpm.TpmReady) {
            $messages += "TPM is present but not ready"
            $status = 'Warning'
        } else {
            $messages += "TPM is present and ready"
        }

        if (-not $tpm.TpmEnabled) {
            $messages += "TPM is not enabled"
            $status = 'Bad'
        }

        # Check TPM version via WMI
        try {
            $tpmVersion = (Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction Stop).SpecVersion
            if ($tpmVersion -like "2.*") {
                $messages += "TPM version 2.0 detected"
            } elseif ($tpmVersion -like "1.*") {
                $messages += "TPM version 1.2 detected (2.0 required for Windows 11)"
                $status = 'Warning'
            } else {
                $messages += "TPM version: $tpmVersion"
            }
        } catch {
            $messages += "TPM version could not be determined"
        }

        return [PSCustomObject]@{
            CheckName = 'TPM 2.0'
            Status    = $status
            Message   = ($messages -join '. ') + '.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'TPM 2.0'
            Status    = 'Bad'
            Message   = "Could not retrieve TPM status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-ASRStatus {
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop

        if ($null -eq $mpPref.AttackSurfaceReductionRules_Ids -or $mpPref.AttackSurfaceReductionRules_Ids.Count -eq 0) {
            return [PSCustomObject]@{
                CheckName = 'Attack Surface Reduction (ASR) Rules'
                Status    = 'Warning'
                Message   = 'No ASR rules are configured. ASR rules help prevent Office exploits, script-based attacks, and credential theft.'
            }
        }

        $enabledCount = ($mpPref.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count
        $auditCount = ($mpPref.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 2 }).Count
        $totalRules = $mpPref.AttackSurfaceReductionRules_Ids.Count

        $message = "$enabledCount ASR rule(s) enabled, $auditCount in audit mode out of $totalRules configured"

        $status = if ($enabledCount -ge 5) { 'Good' } elseif ($enabledCount -gt 0) { 'Warning' } else { 'Bad' }

        return [PSCustomObject]@{
            CheckName = 'Attack Surface Reduction (ASR) Rules'
            Status    = $status
            Message   = $message + '.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Attack Surface Reduction (ASR) Rules'
            Status    = 'Error'
            Message   = "Could not retrieve ASR status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-ControlledFolderAccessStatus {
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop

        # 0 = Disabled, 1 = Enabled, 2 = Audit
        switch ($mpPref.EnableControlledFolderAccess) {
            1 {
                return [PSCustomObject]@{
                    CheckName = 'Controlled Folder Access (Anti-Ransomware)'
                    Status    = 'Good'
                    Message   = 'Controlled Folder Access is enabled, providing ransomware protection.'
                }
            }
            2 {
                return [PSCustomObject]@{
                    CheckName = 'Controlled Folder Access (Anti-Ransomware)'
                    Status    = 'Warning'
                    Message   = 'Controlled Folder Access is in audit mode only.'
                }
            }
            default {
                return [PSCustomObject]@{
                    CheckName = 'Controlled Folder Access (Anti-Ransomware)'
                    Status    = 'Warning'
                    Message   = 'Controlled Folder Access is disabled. This provides ransomware protection for user folders.'
                }
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Controlled Folder Access (Anti-Ransomware)'
            Status    = 'Error'
            Message   = "Could not retrieve Controlled Folder Access status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-EnhancedDefenderStatus {
    try {
        $mpPref = Get-MpPreference -ErrorAction Stop
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop

        $messages = @()
        $issues = @()

        # Real-time protection
        if ($mpStatus.RealTimeProtectionEnabled) {
            $messages += "Real-time protection: Enabled"
        } else {
            $issues += "Real-time protection is disabled"
        }

        # Cloud-delivered protection
        if ($mpPref.MAPSReporting -gt 0) {
            $messages += "Cloud protection: Enabled"
        } else {
            $issues += "Cloud protection is disabled"
        }

        # Network Protection
        if ($mpPref.EnableNetworkProtection -eq 1) {
            $messages += "Network protection: Enabled"
        } elseif ($mpPref.EnableNetworkProtection -eq 2) {
            $messages += "Network protection: Audit mode"
        } else {
            $issues += "Network protection is disabled"
        }

        # Tamper Protection (check via registry as it's not in MpPreference)
        try {
            $tamperProtection = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TamperProtection' -ErrorAction SilentlyContinue).TamperProtection
            if ($tamperProtection -eq 5) {
                $messages += "Tamper protection: Enabled"
            } else {
                $issues += "Tamper protection is not enabled"
            }
        } catch {
            $messages += "Tamper protection: Status unknown"
        }

        # PUA Protection
        if ($mpPref.PUAProtection -eq 1) {
            $messages += "PUA protection: Enabled"
        } else {
            $issues += "PUA (Potentially Unwanted Application) protection is disabled"
        }

        # Signature age
        $sigAge = (Get-Date) - $mpStatus.AntivirusSignatureLastUpdated
        if ($sigAge.Days -eq 0) {
            $messages += "Signatures: Up to date (today)"
        } elseif ($sigAge.Days -le 2) {
            $messages += "Signatures: $($sigAge.Days) day(s) old"
        } else {
            $issues += "Signatures are $($sigAge.Days) days old"
        }

        $status = if ($issues.Count -eq 0) { 'Good' } elseif ($issues.Count -le 2) { 'Warning' } else { 'Bad' }

        $finalMessage = if ($issues.Count -gt 0) {
            "Issues: " + ($issues -join '; ') + ". " + ($messages -join '; ')
        } else {
            ($messages -join '; ')
        }

        return [PSCustomObject]@{
            CheckName = 'Windows Defender (Enhanced)'
            Status    = $status
            Message   = $finalMessage + '.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Windows Defender (Enhanced)'
            Status    = 'Error'
            Message   = "Could not retrieve enhanced Defender status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-WindowsHelloStatus {
    try {
        # Check for Windows Hello PIN or biometrics
        $helloConfigured = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Credential Provider\{8AF662BF-65A0-4D0A-A540-A338A999D36F}"

        if ($helloConfigured) {
            return [PSCustomObject]@{
                CheckName = 'Windows Hello for Business'
                Status    = 'Good'
                Message   = 'Windows Hello appears to be configured on this device.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Windows Hello for Business'
                Status    = 'Warning'
                Message   = 'Windows Hello does not appear to be configured. Windows Hello is required for Personal Data Encryption.'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Windows Hello for Business'
            Status    = 'Warning'
            Message   = "Could not determine Windows Hello status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-ModernLAPSStatus {
    try {
        # Check for Windows LAPS (built-in to Windows 11)
        $modernLaps = Get-Command Get-LapsADPassword -ErrorAction SilentlyContinue

        if ($modernLaps) {
            # Try to check if LAPS is configured
            try {
                $lapsConfig = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config' -ErrorAction SilentlyContinue
                if ($lapsConfig) {
                    return [PSCustomObject]@{
                        CheckName = 'Windows LAPS'
                        Status    = 'Good'
                        Message   = 'Windows LAPS (modern built-in) is configured.'
                    }
                } else {
                    return [PSCustomObject]@{
                        CheckName = 'Windows LAPS'
                        Status    = 'Warning'
                        Message   = 'Windows LAPS cmdlets available but configuration not detected.'
                    }
                }
            } catch {
                return [PSCustomObject]@{
                    CheckName = 'Windows LAPS'
                    Status    = 'Warning'
                    Message   = 'Windows LAPS cmdlets available but status unclear.'
                }
            }
        }

        # Fall back to legacy LAPS check
        if (Get-Module -ListAvailable -Name AdmPwd.PS) {
            return [PSCustomObject]@{
                CheckName = 'Windows LAPS'
                Status    = 'Warning'
                Message   = 'Legacy LAPS (AdmPwd.PS) detected. Consider upgrading to Windows LAPS.'
            }
        }

        return [PSCustomObject]@{
            CheckName = 'Windows LAPS'
            Status    = 'Warning'
            Message   = 'LAPS is not installed. Windows LAPS is built into Windows 11 and Server 2025.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Windows LAPS'
            Status    = 'Warning'
            Message   = "Could not retrieve Windows LAPS status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-EnhancedRDPStatus {
    try {
        $rdpValue = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop).fDenyTSConnections

        if ($rdpValue -eq 1) {
            return [PSCustomObject]@{
                CheckName = 'Remote Desktop (RDP)'
                Status    = 'Good'
                Message   = 'Remote Desktop is disabled.'
            }
        }

        # RDP is enabled, check security settings
        $messages = @("RDP is enabled")
        $issues = @()

        # Check NLA (Network Level Authentication)
        try {
            $nlaEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction Stop).UserAuthentication
            if ($nlaEnabled -eq 1) {
                $messages += "NLA enabled"
            } else {
                $issues += "NLA (Network Level Authentication) is disabled"
            }
        } catch {
            $issues += "Could not determine NLA status"
        }

        # Check Security Layer
        try {
            $secLayer = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -ErrorAction Stop).SecurityLayer
            if ($secLayer -eq 2) {
                $messages += "SSL/TLS encryption"
            } elseif ($secLayer -eq 1) {
                $issues += "Security layer set to 'Negotiate' instead of SSL/TLS"
            } else {
                $issues += "Security layer is set to RDP (weak)"
            }
        } catch {
            $issues += "Could not determine security layer"
        }

        # Check port
        try {
            $port = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -ErrorAction Stop).PortNumber
            if ($port -eq 3389) {
                $issues += "Using default port 3389 (consider changing)"
            } else {
                $messages += "Custom port: $port"
            }
        } catch {
            # Port check failed, not critical
        }

        $status = if ($issues.Count -eq 0) { 'Warning' } else { 'Bad' }
        $finalMessage = ($messages -join ', ') + '. ' + ($issues -join '. ')

        return [PSCustomObject]@{
            CheckName = 'Remote Desktop (RDP)'
            Status    = $status
            Message   = $finalMessage.TrimEnd() + '.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Remote Desktop (RDP)'
            Status    = 'Error'
            Message   = "Could not retrieve RDP status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-SMBSigningStatus {
    try {
        $clientConfig = Get-SmbClientConfiguration -ErrorAction Stop
        $serverConfig = Get-SmbServerConfiguration -ErrorAction Stop

        $messages = @()
        $issues = @()

        # SMB Client signing
        if ($clientConfig.RequireSecuritySignature) {
            $messages += "SMB client signing: Required"
        } elseif ($clientConfig.EnableSecuritySignature) {
            $issues += "SMB client signing is enabled but not required"
        } else {
            $issues += "SMB client signing is disabled"
        }

        # SMB Server signing
        if ($serverConfig.RequireSecuritySignature) {
            $messages += "SMB server signing: Required"
        } elseif ($serverConfig.EnableSecuritySignature) {
            $issues += "SMB server signing is enabled but not required"
        } else {
            $issues += "SMB server signing is disabled"
        }

        # SMB Encryption
        if ($serverConfig.EncryptData) {
            $messages += "SMB encryption: Enabled"
        } else {
            $issues += "SMB encryption is not required"
        }

        $status = if ($issues.Count -eq 0) { 'Good' } elseif ($issues.Count -le 1) { 'Warning' } else { 'Bad' }

        $finalMessage = if ($issues.Count -gt 0) {
            "Issues: " + ($issues -join '; ') + ". " + ($messages -join '; ')
        } else {
            ($messages -join '; ')
        }

        return [PSCustomObject]@{
            CheckName = 'SMB Signing & Encryption'
            Status    = $status
            Message   = $finalMessage + '.'
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'SMB Signing & Encryption'
            Status    = 'Error'
            Message   = "Could not retrieve SMB signing status. Error: $($_.Exception.Message)"
        }
    }
}


# --- Main Script ---

Write-Host "Running Windows Security Checks..." -ForegroundColor Cyan

$results = @()

# Core Windows 11 Security Features (2023-2024)
$results += Get-VBSStatus
$results += Get-CredentialGuardStatus
$results += Get-TPMStatus
$results += Get-SecureBootStatus

# Windows Defender - Enhanced Checks
$results += Get-EnhancedDefenderStatus
$results += Get-ASRStatus
$results += Get-ControlledFolderAccessStatus

# Traditional Security Checks (Updated)
$results += Get-FirewallStatus
$results += Get-UACStatus
$results += Get-WindowsUpdateStatus
$results += Get-BitLockerStatus

# Authentication & Access Control
$results += Get-WindowsHelloStatus
$results += Get-GuestAccountStatus
$results += Get-ModernLAPSStatus

# Network Security
$results += Get-EnhancedRDPStatus
$results += Get-SMBv1Status
$results += Get-SMBSigningStatus
$results += Get-NetworkSharingStatus

# System Configuration
$results += Get-ExecutionPolicyStatus
$results += Get-AuditPolicyStatus

# --- Console Output ---

Write-Host "`n--- Security Check Results ---`n" -ForegroundColor Cyan

foreach ($result in $results) {
    $statusColor = switch ($result.Status) {
        'Good'    { 'Green' }
        'Bad'     { 'Red' }
        'Warning' { 'Yellow' }
        'Error'   { 'Magenta' }
    }
    Write-Host "[$($result.Status.ToUpper())]" -ForegroundColor $statusColor -NoNewline
    Write-Host " $($result.CheckName): $($result.Message)"
}

# --- Report Generation ---

$reportContent = @"
Security Report - $(Get-Date -Format "yyyy/MM/dd HH:mm")
=======================================

"@

foreach ($result in $results) {
    $reportContent += @"
Check:  $($result.CheckName)
Status: $($result.Status)
Info:   $($result.Message)
---------------------------------------
"@
}

$outputFile = "SecurityReport_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
try {
    Set-Content -Path $outputFile -Value $reportContent -ErrorAction Stop
    Write-Host "`nSecurity report saved to '$outputFile'" -ForegroundColor Green
} catch {
    Write-Host "`nFailed to save security report to '$outputFile'. Error: $($_.Exception.Message)" -ForegroundColor Red
}

Read-Host "Press Enter to exit..."
