# Admin check
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator privileges are required for this script. Please run the script as an Administrator." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    exit
}

# --- Function Definitions ---

function Get-DefenderStatus {
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        if ($defenderStatus.AntivirusEnabled) {
            return [PSCustomObject]@{
                CheckName = 'Windows Defender'
                Status    = 'Good'
                Message   = 'Windows Defender is enabled and running.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Windows Defender'
                Status    = 'Bad'
                Message   = 'Windows Defender is not enabled or not running.'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Windows Defender'
            Status    = 'Error'
            Message   = "Could not retrieve Windows Defender status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-FirewallStatus {
    try {
        $firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled
        $messages = @()
        $allEnabled = $true
        foreach ($profile in $firewallProfiles) {
            if ($profile.Enabled) {
                $messages += "  - $($profile.Name) Firewall: Enabled"
            } else {
                $messages += "  - $($profile.Name) Firewall: Disabled"
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

function Get-AutomaticUpdatesStatus {
    try {
        $auValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -ErrorAction Stop).AUOptions
        switch ($auValue) {
            4 {
                $message = 'Automatic updates are set to download and install automatically.'
                $status = 'Good'
            }
            3 {
                $message = 'Automatic updates are set to download and notify for install.'
                $status = 'Good'
            }
            2 {
                $message = 'Automatic updates are set to notify for download and notify for install.'
                $status = 'Good'
            }
            1 {
                $message = 'Automatic updates are disabled.'
                $status = 'Bad'
            }
            default {
                $message = "Unknown automatic updates status (Value: $auValue)."
                $status = 'Warning'
            }
        }
         return [PSCustomObject]@{
            CheckName = 'Automatic Updates'
            Status    = $status
            Message   = $message
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Automatic Updates'
            Status    = 'Error'
            Message   = "Could not retrieve Automatic Updates status. Error: $($_.Exception.Message)"
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

function Get-RDPStatus {
    try {
        $rdpValue = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop).fDenyTSConnections
        if ($rdpValue -eq 1) {
            return [PSCustomObject]@{
                CheckName = 'Remote Desktop (RDP)'
                Status    = 'Good'
                Message   = 'Remote Desktop is disabled.'
            }
        } else {
            return [PSCustomObject]@{
                CheckName = 'Remote Desktop (RDP)'
                Status    = 'Bad'
                Message   = 'Remote Desktop is enabled.'
            }
        }
    } catch {
        return [PSCustomObject]@{
            CheckName = 'Remote Desktop (RDP)'
            Status    = 'Error'
            Message   = "Could not retrieve RDP status. Error: $($_.Exception.Message)"
        }
    }
}

function Get-LAPSStatus {
    if (Get-Module -ListAvailable -Name AdmPwd.PS) {
        try {
            $lapsPass = Get-AdmPwdPassword -ComputerName $env:COMPUTERNAME -ErrorAction Stop
            if ($lapsPass) {
                return [PSCustomObject]@{
                    CheckName = 'LAPS'
                    Status    = 'Good'
                    Message   = 'LAPS is configured and a password is set.'
                }
            } else {
                # This case might be rare, but good to have
                return [PSCustomObject]@{
                    CheckName = 'LAPS'
                    Status    = 'Warning'
                    Message   = 'LAPS is installed, but no password was retrieved.'
                }
            }
        } catch {
            return [PSCustomObject]@{
                CheckName = 'LAPS'
                Status    = 'Bad'
                Message   = 'LAPS is installed, but is not configured correctly on this machine.'
            }
        }
    } else {
        return [PSCustomObject]@{
            CheckName = 'LAPS'
            Status    = 'Warning'
            Message   = 'LAPS PowerShell module (AdmPwd.PS) is not installed.'
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


# --- Main Script ---

Write-Host "Running Windows Security Checks..." -ForegroundColor Cyan

$results = @()
$results += Get-DefenderStatus
$results += Get-FirewallStatus
$results += Get-UACStatus
$results += Get-AutomaticUpdatesStatus
$results += Get-BitLockerStatus
$results += Get-GuestAccountStatus
$results += Get-NetworkSharingStatus
$results += Get-ExecutionPolicyStatus
$results += Get-SecureBootStatus
$results += Get-SMBv1Status
$results += Get-RDPStatus
$results += Get-LAPSStatus
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
