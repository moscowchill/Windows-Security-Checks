# Registry and Startup Enumeration Script
# Location: C:\sharedfolder\PentestScripts\Registry-Startup-Check.ps1

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Registry and Startup Enumeration" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# Stored Credentials
Write-Host "[+] Checking stored credentials..." -ForegroundColor Yellow
Write-Host ""
cmdkey /list
Write-Host ""

# Registry Run Keys
Write-Host "[+] Registry Run Keys (HKLM)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

Write-Host "[+] Registry Run Keys (HKCU)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

# Registry RunOnce Keys
Write-Host "[+] Registry RunOnce Keys (HKLM)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

Write-Host "[+] Registry RunOnce Keys (HKCU)..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

# Startup Folders
Write-Host "[+] Startup Folder Contents (User)..." -ForegroundColor Yellow
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName
Write-Host ""

Write-Host "[+] Startup Folder Contents (All Users)..." -ForegroundColor Yellow
Get-ChildItem "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name, FullName
Write-Host ""

# Scheduled Tasks
Write-Host "[+] Scheduled Tasks (Running as current user or SYSTEM)..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State, @{Name="User";Expression={$_.Principal.UserId}} | Format-Table -AutoSize
Write-Host ""

# Services
Write-Host "[+] Services set to Auto-start..." -ForegroundColor Yellow
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
Write-Host ""

# Winlogon Keys
Write-Host "[+] Winlogon Registry Keys..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Format-List
Write-Host ""

# Boot Execute
Write-Host "[+] Boot Execute..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name BootExecute -ErrorAction SilentlyContinue | Select-Object BootExecute
Write-Host ""

# Additional persistence locations
Write-Host "[+] Image File Execution Options (potential hijacking)..." -ForegroundColor Yellow
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object {
    $debugger = Get-ItemProperty -Path $_.PSPath -Name Debugger -ErrorAction SilentlyContinue
    if ($debugger) {
        Write-Host "$($_.PSChildName): $($debugger.Debugger)" -ForegroundColor Red
    }
}
Write-Host ""

# AppInit_DLLs
Write-Host "[+] AppInit_DLLs..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue | Select-Object AppInit_DLLs
Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -Name AppInit_DLLs -ErrorAction SilentlyContinue | Select-Object AppInit_DLLs
Write-Host ""

# LSA Packages
Write-Host "[+] LSA Authentication Packages..." -ForegroundColor Yellow
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" -ErrorAction SilentlyContinue | Select-Object "Authentication Packages"
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -ErrorAction SilentlyContinue | Select-Object "Security Packages"
Write-Host ""

# Credential Manager entries
Write-Host "[+] Windows Credential Manager entries..." -ForegroundColor Yellow
try {
    $credentials = cmdkey /list | Select-String "Target:" | ForEach-Object { $_.ToString().Trim() }
    $credentials | ForEach-Object { Write-Host $_ }
} catch {
    Write-Host "Unable to enumerate credential manager"
}
Write-Host ""

# PERMISSIONS SUMMARY FOR PENTEST REPORTING
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PERMISSIONS SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test Registry Write Access
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
)

Write-Host "[REGISTRY KEY PERMISSIONS]" -ForegroundColor Yellow
Write-Host ""
foreach ($regPath in $regPaths) {
    $canRead = $false
    $canWrite = $false

    # Test Read
    try {
        $null = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $canRead = $true
    } catch {
        $canRead = $false
    }

    # Test Write
    try {
        $testValueName = "__TEST_WRITE_$(Get-Random)__"
        New-ItemProperty -Path $regPath -Name $testValueName -Value "test" -PropertyType String -ErrorAction Stop | Out-Null
        Remove-ItemProperty -Path $regPath -Name $testValueName -ErrorAction SilentlyContinue
        $canWrite = $true
    } catch {
        $canWrite = $false
    }

    $readStatus = if ($canRead) { "YES" } else { "NO " }
    $writeStatus = if ($canWrite) { "YES" } else { "NO " }
    $readColor = if ($canRead) { "Green" } else { "Red" }
    $writeColor = if ($canWrite) { "Green" } else { "Red" }

    Write-Host "  $regPath" -ForegroundColor White
    Write-Host "    Read:  " -NoNewline
    Write-Host $readStatus -ForegroundColor $readColor -NoNewline
    Write-Host "  |  Write: " -NoNewline
    Write-Host $writeStatus -ForegroundColor $writeColor
    Write-Host ""
}

# Test Startup Folder Permissions
Write-Host "[STARTUP FOLDER PERMISSIONS]" -ForegroundColor Yellow
Write-Host ""
$startupFolders = @(
    @{Path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Name="User Startup"},
    @{Path="$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Startup"; Name="All Users Startup"}
)

foreach ($folder in $startupFolders) {
    $canRead = $false
    $canWrite = $false

    # Test Read
    try {
        $null = Get-ChildItem $folder.Path -ErrorAction Stop
        $canRead = $true
    } catch {
        $canRead = $false
    }

    # Test Write
    try {
        $testFile = Join-Path $folder.Path "__test_write_$(Get-Random).txt"
        New-Item -Path $testFile -ItemType File -ErrorAction Stop | Out-Null
        Remove-Item -Path $testFile -ErrorAction SilentlyContinue
        $canWrite = $true
    } catch {
        $canWrite = $false
    }

    $readStatus = if ($canRead) { "YES" } else { "NO " }
    $writeStatus = if ($canWrite) { "YES" } else { "NO " }
    $readColor = if ($canRead) { "Green" } else { "Red" }
    $writeColor = if ($canWrite) { "Green" } else { "Red" }

    Write-Host "  $($folder.Name): $($folder.Path)" -ForegroundColor White
    Write-Host "    Read:  " -NoNewline
    Write-Host $readStatus -ForegroundColor $readColor -NoNewline
    Write-Host "  |  Write: " -NoNewline
    Write-Host $writeStatus -ForegroundColor $writeColor
    Write-Host ""
}

# Test Scheduled Task Creation
Write-Host "[SCHEDULED TASK PERMISSIONS]" -ForegroundColor Yellow
Write-Host ""
$canCreateTask = $false
try {
    $taskName = "__test_task_$(Get-Random)__"
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo test"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(24)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -ErrorAction Stop | Out-Null
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $canCreateTask = $true
} catch {
    $canCreateTask = $false
}

$taskStatus = if ($canCreateTask) { "YES - Can create scheduled tasks" } else { "NO  - Cannot create scheduled tasks" }
$taskColor = if ($canCreateTask) { "Green" } else { "Red" }
Write-Host "  Create Scheduled Task: " -NoNewline
Write-Host $taskStatus -ForegroundColor $taskColor
Write-Host ""

# User Context
Write-Host "[CURRENT USER CONTEXT]" -ForegroundColor Yellow
Write-Host ""
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "  Username: " -NoNewline
Write-Host "$($currentUser.Name)" -ForegroundColor Cyan
Write-Host "  Admin:    " -NoNewline
if ($isAdmin) {
    Write-Host "YES - Running with Administrator privileges" -ForegroundColor Green
} else {
    Write-Host "NO  - Running with standard user privileges" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Scan Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
