<#
Description : Windows Domain Controller Analysis Report Generator
Name : AD COLLECTOR LIGHT
Tested on : PowerShell 5.1.17763.7131 - Windows Server 2019

GitHub link : https://github.com/michaeldallariva
Version : v3.1
Author : Michael DALLA RIVA, with the help of some AI
Date : 13 April 2025

Purpose:
This script connects to a domain controller in a Windows Active Directory environment
and collects general information about its health and status.

How to use it:
- Run from the C:\temp folder (Or change the variable to change the path)
- Run it on a Windows Domain Controller

License :
Feel free to use for any purpose, personal or commercial.
If you use it within a commercial/consulting scope, it would be nice to receive a donation.

#>


function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    return $isAdmin
}

function Confirm-AdminRights {
    if (-not (Test-Administrator)) {
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor Yellow
        Write-Host "ERROR: This script requires administrative privileges to run correctly." -ForegroundColor Yellow
        Write-Host "Please right-click on PowerShell and select 'Run as Administrator', then" -ForegroundColor Yellow 
        Write-Host "execute the script again." -ForegroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Yellow
        Write-Host ""
        exit
    }
    else {
        Write-Host "Running with administrator privileges. Continuing..." -ForegroundColor Green
    }
}

Confirm-AdminRights

function Import-RequiredModule {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )
    
    try {
        Import-Module $ModuleName -ErrorAction Stop
        Write-Host "Successfully imported $ModuleName module" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "WARNING: Unable to import $ModuleName module." -ForegroundColor Yellow
        Write-Host "Ensure the module is installed and available." -ForegroundColor Yellow
        
        $modulePaths = @(
            "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\$ModuleName\$ModuleName.psd1",
            "C:\Program Files\WindowsPowerShell\Modules\$ModuleName\$ModuleName.psd1"
        )
        
        foreach ($path in $modulePaths) {
            try {
                Import-Module $path -ErrorAction Stop
                Write-Host "Successfully imported $ModuleName module from: $path" -ForegroundColor Green
                return $true
            }
            catch {
            }
        }
        
        Write-Host "NOTICE: $ModuleName module could not be imported from any known location." -ForegroundColor Yellow
        Write-Host "Some functionality may be limited." -ForegroundColor Yellow
        return $false
    }
}

Import-RequiredModule -ModuleName "ActiveDirectory"

function Get-EuropeanDateFormat {
    return Get-Date -Format "dd-MM-yyyy"
}

function Get-FormattedDateTime {
    return Get-Date -Format "dd-MM-yyyy HH:mm:ss"
}

function Set-OutputPaths {
    $basePath = "C:\temp"
    $dateStamp = Get-EuropeanDateFormat
    $timeStamp = Get-Date -Format "HH-mm-ss"
    
    $serverName = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($serverName)) {
        $serverName = [System.Net.Dns]::GetHostName()
    }
    if ([string]::IsNullOrWhiteSpace($serverName)) {
        $serverName = "Unknown"
    }
    
    try {
        $domainName = $env:USERDNSDOMAIN
        if ([string]::IsNullOrWhiteSpace($domainName)) {
            $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
    }
    catch {
        Write-Host "Warning: Unable to retrieve domain name: $_" -ForegroundColor Yellow
        $domainName = "Unknown"
    }
    
    $FolderNameBase = "$serverName.$domainName`_$dateStamp"
    $outputDirectory = "$basePath\$FolderNameBase"
    $jsonPath = "$outputDirectory\$serverName.$domainName`_$timeStamp..json"
    $htmlPath = "$outputDirectory\$serverName.$domainName`_$timeStamp.html"
    $csvPath = "$outputDirectory\$serverName.$domainName`_$timeStamp..csv"

    if (-not (Test-Path -Path $basePath)) {
        try {
            New-Item -ItemType Directory -Path $basePath -Force | Out-Null
            Write-Host "Created directory: $basePath" -ForegroundColor Green
        } catch {
            Write-Host "Warning: Failed to create $basePath. Using current directory instead." -ForegroundColor Yellow
            $basePath = "."
            $outputDirectory = ".\DomainReport_$dateStamp"
            $jsonPath = "$outputDirectory\DomainReport_$timeStamp.json"
            $htmlPath = "$outputDirectory\DomainReport_$timeStamp.html"
            $csvPath = "$outputDirectory\DomainReport_$timeStamp.csv"
        }
    }
    
    return @{
        OutputDirectory = $outputDirectory
        JsonPath = $jsonPath
        HtmlPath = $htmlPath
        CsvPath = $csvPath
    }
}

function Get-DCDiagReplicationInfo {
    Write-Host "Retrieving DCDIAG replication information..." -ForegroundColor Cyan
    
    try {
        $replicationInfo = @()
        
        $dcdiagPath = "$env:SystemRoot\System32\dcdiag.exe"
        if (-not (Test-Path -Path $dcdiagPath)) {
            Write-Host "Warning: dcdiag.exe not found at $dcdiagPath. Unable to check replication status." -ForegroundColor Yellow
            return @{
                ReplicationPartners = @()
                HasReplicationErrors = $false
            }
        }
        
        $currentDC = $env:COMPUTERNAME
        
        $dcdiagOutput = & $dcdiagPath /test:replications /v /s:$currentDC

        Write-Host "DCDIAG output length: $($dcdiagOutput.Length) lines" -ForegroundColor Cyan
        
        $replicationPartners = @()
        $currentPartner = $null
        $hasReplicationErrors = $false
        $errorDetails = ""
        $inErrorSection = $false
        
        foreach ($line in $dcdiagOutput) {
            if ($line -match '^\s*DC=\S+' -or $line -match 'Testing server.*?\\?([A-Za-z0-9\-_]+)') {
                if ($currentPartner -and $inErrorSection) {
                    $currentPartner.ErrorMessage = $errorDetails.Trim()
                    $inErrorSection = $false
                    $errorDetails = ""
                }
                
                $partnerName = ""
                if ($line -match '^\s*DC=(\S+)') {
                    $partnerName = $matches[1]
                } elseif ($line -match 'Testing server.*?\\?([A-Za-z0-9\-_]+)') {
                    $partnerName = $matches[1]
                }
                
                if ($partnerName) {
                    $timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
                    $currentPartner = @{
                        PartnerName = $partnerName
                        LastSuccess = $timestamp
                        LastAttempt = $timestamp
                        Status = "Unknown"
                        ErrorMessage = ""
                    }
                    $replicationPartners += $currentPartner
                }
            }
            
            if (($line -match 'Last Success.*=\s*(.+)' -or $line -match 'Last successful sync.*:\s*(.+)') -and $currentPartner) {
                $lastSuccessStr = $matches[1].Trim()
                if ($lastSuccessStr -ne "0" -and $lastSuccessStr -ne "never" -and $lastSuccessStr -notmatch "^0x") {
                    $currentPartner.LastSuccess = $lastSuccessStr
                }
            }
            elseif (($line -match 'Last Attempt.*=\s*(.+)' -or $line -match 'Last sync attempt.*:\s*(.+)') -and $currentPartner) {
                $lastAttemptStr = $matches[1].Trim()
                if ($lastAttemptStr -ne "0" -and $lastAttemptStr -ne "never" -and $lastAttemptStr -notmatch "^0x") {
                    $currentPartner.LastAttempt = $lastAttemptStr
                }
            }
            elseif (($line -match 'failed with status' -or $line -match 'replication error') -and $currentPartner) {
                $currentPartner.Status = "Failed"
                $hasReplicationErrors = $true
                $inErrorSection = $true
                $errorDetails = $line.Trim() + " "
            }
            elseif ($inErrorSection -and $currentPartner -and $line.Trim() -ne "") {
                $errorDetails += $line.Trim() + " "
            }
            elseif ($line -match 'was successful' -and $currentPartner) {
                $currentPartner.Status = "Success"
                $inErrorSection = $false
                $errorDetails = ""
            }
            elseif ($line -match '(ERROR_|LDAP_|WIN32|ERROR:|error \d+)' -and $currentPartner) {
                $errorDetails += "Error code: " + $line.Trim() + " "
                $inErrorSection = $true
                $currentPartner.Status = "Failed"
                $hasReplicationErrors = $true
            }
        }
        
        if ($currentPartner -and $inErrorSection) {
            $currentPartner.ErrorMessage = $errorDetails.Trim()
        }
        
        Write-Host "Using repadmin command for more reliable replication info..." -ForegroundColor Yellow
        
        $repadminOutput = & repadmin /showrepl $currentDC /csv
        
        if ($repadminOutput) {
            try {
                $csv = ConvertFrom-Csv -InputObject $repadminOutput
                
                foreach ($row in $csv) {
                    if ($row.'Source DSA' -and $row.'Destination DSA') {
                        $destinationDC = $row.'Destination DSA'
                        $sourceDC = $row.'Source DSA'
                        
                        if ($sourceDC -match $currentDC) {
                            $partnerFound = $false
                            $existingPartner = $null
                            
                            foreach ($partner in $replicationPartners) {
                                if ($partner.PartnerName -match $destinationDC) {
                                    $partnerFound = $true
                                    $existingPartner = $partner
                                    break
                                }
                            }
                            
                            if (-not $partnerFound) {
                                $existingPartner = @{
                                    PartnerName = $destinationDC
                                    LastSuccess = "Unknown"
                                    LastAttempt = "Unknown"
                                    Status = "Unknown"
                                    ErrorMessage = ""
                                }
                                $replicationPartners += $existingPartner
                            }
                            
                            if (-not [string]::IsNullOrEmpty($row.'Last Success Time')) {
                                $existingPartner.LastSuccess = $row.'Last Success Time'
                            }
                            
                            if (-not [string]::IsNullOrEmpty($row.'Last Attempt Time')) {
                                $existingPartner.LastAttempt = $row.'Last Attempt Time'
                            }
                            
                            $failureCount = 0
                            if (-not [string]::IsNullOrEmpty($row.'Number of Failures') -and 
                                $row.'Number of Failures' -match '\d+') {
                                $failureCount = [int]$row.'Number of Failures'
                            }
                            
                            if ($failureCount -gt 0) {
                                $existingPartner.Status = "Failed"
                                $hasReplicationErrors = $true
                                
                                $errorMsg = ""
                                if (-not [string]::IsNullOrEmpty($row.'Last Error')) {
                                    $errorMsg = $row.'Last Error'
                                }
                                
                                if (-not [string]::IsNullOrEmpty($errorMsg) -and $errorMsg -ne "0") {
                                    $existingPartner.ErrorMessage = $errorMsg
                                } elseif ([string]::IsNullOrEmpty($existingPartner.ErrorMessage)) {
                                    $existingPartner.ErrorMessage = "Replication failing for $failureCount consecutive attempts."
                                }
                            } elseif ($existingPartner.Status -eq "Unknown") {
                                $existingPartner.Status = "Success"
                            }
                        }
                    }
                }
            } catch {
                Write-Host "Error parsing repadmin CSV output: $_" -ForegroundColor Yellow
            }
        }
        
        foreach ($partner in $replicationPartners) {
            if ($partner.LastSuccess -eq "Unknown" -or $partner.LastAttempt -eq "Unknown") {
                # Try to get more specific replication data for this partner
                $partnerRepl = & repadmin /showrepl $currentDC $partner.PartnerName /verbose
                
                foreach ($line in $partnerRepl) {
                    if ($line -match 'Last successful Synchronization:\s+(.+)' -or 
                        $line -match 'Last Success.*:\s+(.+)') {
                        $partner.LastSuccess = $matches[1].Trim()
                    }
                    
                    # Look for last attempt time
                    if ($line -match 'Last attempt.*:\s+(.+)' -or 
                        $line -match 'Last Attempt.*:\s+(.+)') {
                        $partner.LastAttempt = $matches[1].Trim()
                    }
                }
            }
        }
        
        $currentTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        foreach ($partner in $replicationPartners) {
            if ($partner.LastSuccess -eq "Unknown") {
                $partner.LastSuccess = $currentTimestamp
            }
            if ($partner.LastAttempt -eq "Unknown") {
                $partner.LastAttempt = $currentTimestamp
            }
            
            if ($partner.Status -eq "Failed" -and [string]::IsNullOrEmpty($partner.ErrorMessage)) {
                $partner.ErrorMessage = "Replication failed but no specific error message was captured. Check Event Viewer for more details."
            }
        }
        
        Write-Host "Retrieved information for $($replicationPartners.Count) replication partners" -ForegroundColor Green
        
        return @{
            ReplicationPartners = $replicationPartners
            HasReplicationErrors = $hasReplicationErrors
        }
    }
    catch {
        Write-Host "Error retrieving DCDIAG replication information: $_" -ForegroundColor Red
        return @{
            ReplicationPartners = @()
            HasReplicationErrors = $false
        }
    }
}

function Get-ADDatabaseInfo {
    Write-Host "Retrieving Active Directory database information..." -ForegroundColor Cyan
    
    try {
        $ntdsInfo = @{
            DatabasePath = "Unknown"
            DatabaseSize = 0
            DatabaseSizeUnit = "GB"
            LogPath = "Unknown"
            LogSize = 0
            LogSizeUnit = "MB"
            LastBackupTime = "Never"
            IsBackedUp = $false
        }
        
        $isDC = $false
        try {
            $ntdsService = Get-Service -Name "NTDS" -ErrorAction SilentlyContinue
            if ($null -ne $ntdsService) {
                $isDC = $true
                Write-Host "NTDS service found, this appears to be a domain controller" -ForegroundColor Green
            }
            
            if (-not $isDC) {
                $serverManager = Get-WmiObject -Class Win32_ServerFeature -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -like "*Active Directory Domain Services*" }
                if ($null -ne $serverManager) {
                    $isDC = $true
                    Write-Host "AD DS role found, this appears to be a domain controller" -ForegroundColor Green
                }
            }
            
            if (-not $isDC) {
                $ntdsKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction SilentlyContinue
                if ($null -ne $ntdsKey) {
                    $isDC = $true
                    Write-Host "NTDS registry key found, this appears to be a domain controller" -ForegroundColor Green
                }
            }
        }
        catch {
            Write-Host "Warning: Error checking if server is a domain controller: $_" -ForegroundColor Yellow
        }
        
        if (-not $isDC) {
            Write-Host "This server does not appear to be a domain controller" -ForegroundColor Yellow
            return $ntdsInfo
        }
        
        try {
            $ntdsParams = $null
            
            try {
                $ntdsParams = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -ErrorAction Stop
            }
            catch {
                Write-Host "Warning: Unable to access NTDS Parameters registry key: $_" -ForegroundColor Yellow
            }
            
            if ($ntdsParams) {
                # Get database path
                if ($ntdsParams.PSObject.Properties["DSA Database file"]) {
                    $ntdsInfo.DatabasePath = $ntdsParams."DSA Database file"
                }
                elseif ($ntdsParams.PSObject.Properties["DB"]) {
                    $ntdsInfo.DatabasePath = $ntdsParams.DB
                }
                
                # Get log path
                if ($ntdsParams.PSObject.Properties["Database log files path"]) {
                    $ntdsInfo.LogPath = $ntdsParams."Database log files path"
                }
                elseif ($ntdsParams.PSObject.Properties["Log"]) {
                    $ntdsInfo.LogPath = $ntdsParams.Log
                }
            }
            
            Write-Host "Retrieved database path from registry: $($ntdsInfo.DatabasePath)" -ForegroundColor Green
            Write-Host "Retrieved log path from registry: $($ntdsInfo.LogPath)" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Unable to read NTDS database path from registry: $_" -ForegroundColor Yellow
        }
        
        if ($ntdsInfo.DatabasePath -eq "Unknown") {
            # Default path is usually %SystemRoot%\NTDS\ntds.dit
            $defaultPath = "$env:SystemRoot\NTDS\ntds.dit"
            if (Test-Path -Path $defaultPath) {
                $ntdsInfo.DatabasePath = $defaultPath
                Write-Host "Using default database path: $defaultPath" -ForegroundColor Yellow
            }
        }
        
        if ($ntdsInfo.LogPath -eq "Unknown") {
            $defaultLogPath = "$env:SystemRoot\NTDS"
            if (Test-Path -Path $defaultLogPath) {
                $ntdsInfo.LogPath = $defaultLogPath
                Write-Host "Using default log path: $defaultLogPath" -ForegroundColor Yellow
            }
        }
        
        if ($ntdsInfo.DatabasePath -ne "Unknown" -and (Test-Path -Path $ntdsInfo.DatabasePath)) {
            $dbFile = Get-Item -Path $ntdsInfo.DatabasePath
            
            # Size in GB with two decimal places
            $sizeInGB = [math]::Round($dbFile.Length / 1GB, 2)
            
            if ($sizeInGB -lt 1) {
                # If less than 1GB, show in MB
                $ntdsInfo.DatabaseSize = [math]::Round($dbFile.Length / 1MB, 2)
                $ntdsInfo.DatabaseSizeUnit = "MB"
            } else {
                $ntdsInfo.DatabaseSize = $sizeInGB
                $ntdsInfo.DatabaseSizeUnit = "GB"
            }
            
            Write-Host "Database size: $($ntdsInfo.DatabaseSize) $($ntdsInfo.DatabaseSizeUnit)" -ForegroundColor Green
        } else {
            Write-Host "Warning: Cannot access the database file to determine size" -ForegroundColor Yellow
        }
        
        if ($ntdsInfo.LogPath -ne "Unknown" -and (Test-Path -Path $ntdsInfo.LogPath)) {
            $logFiles = Get-ChildItem -Path $ntdsInfo.LogPath -Filter "*.log" -ErrorAction SilentlyContinue
            $jrsFiles = Get-ChildItem -Path $ntdsInfo.LogPath -Filter "*.jrs" -ErrorAction SilentlyContinue
            $edbFiles = Get-ChildItem -Path $ntdsInfo.LogPath -Filter "edb*.log" -ErrorAction SilentlyContinue
            
            $logFiles = @($logFiles) + @($jrsFiles) + @($edbFiles)
            
            if ($logFiles -and $logFiles.Count -gt 0) {
                $logTotalSize = ($logFiles | Measure-Object -Property Length -Sum).Sum
                
                $sizeInMB = [math]::Round($logTotalSize / 1MB, 2)
                
                if ($sizeInMB -gt 1024) {
                    $ntdsInfo.LogSize = [math]::Round($logTotalSize / 1GB, 2)
                    $ntdsInfo.LogSizeUnit = "GB"
                } else {
                    $ntdsInfo.LogSize = $sizeInMB
                    $ntdsInfo.LogSizeUnit = "MB"
                }
                
                Write-Host "Log size: $($ntdsInfo.LogSize) $($ntdsInfo.LogSizeUnit)" -ForegroundColor Green
            } else {
                Write-Host "Warning: No log files found in log path" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Warning: Cannot access the log directory to determine size" -ForegroundColor Yellow
        }
        

        try {
            $backupEvents = Get-WinEvent -LogName "Microsoft-Windows-Backup" -ErrorAction SilentlyContinue | 
                Where-Object { $_.Id -eq 4 } | # Event ID 4 is successful backup
                Select-Object -First 1
                
            if ($backupEvents) {
                $ntdsInfo.IsBackedUp = $true
                $ntdsInfo.LastBackupTime = $backupEvents.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "Backup information found in Windows Backup event logs" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Warning: Unable to check backup event logs: $_" -ForegroundColor Yellow
        }
        
        if (-not $ntdsInfo.IsBackedUp) {
            try {
                $ntdsBackupEvents = Get-WinEvent -LogName "Microsoft-Windows-ActiveDirectory_DomainService" -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Id -eq 1699 -or $_.Id -eq 1274 } | # Success backup events
                    Select-Object -First 1
                    
                if ($ntdsBackupEvents) {
                    $ntdsInfo.IsBackedUp = $true
                    $ntdsInfo.LastBackupTime = $ntdsBackupEvents.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                    Write-Host "Backup information found in AD DS event logs" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "Warning: Unable to check AD DS event logs: $_" -ForegroundColor Yellow
            }
        }
        
        if (-not $ntdsInfo.IsBackedUp) {
            try {
                # Common backup locations
                $backupLocations = @(
                    "$env:SystemDrive\Windows\Backup",
                    "$env:SystemDrive\WindowsImageBackup"
                )
                
                foreach ($loc in $backupLocations) {
                    if (Test-Path -Path $loc) {
                        $backupFolders = Get-ChildItem -Path $loc -Directory -ErrorAction SilentlyContinue
                        if ($backupFolders -and $backupFolders.Count -gt 0) {
                            $ntdsInfo.IsBackedUp = $true
                            
                            # Get most recent folder modification time as estimate
                            $lastBackupTime = ($backupFolders | 
                                Sort-Object -Property LastWriteTime -Descending | 
                                Select-Object -First 1).LastWriteTime
                                
                            if ($lastBackupTime) {
                                $ntdsInfo.LastBackupTime = $lastBackupTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                            
                            Write-Host "Backup information found in backup directory: $loc" -ForegroundColor Green
                            break
                        }
                    }
                }
            }
            catch {
                Write-Host "Warning: Unable to check backup folders: $_" -ForegroundColor Yellow
            }
        }
        
        if (-not $ntdsInfo.IsBackedUp) {
            try {
                $backupRegKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WindowsServerBackup\Parameters" -ErrorAction SilentlyContinue
                
                if ($backupRegKey -and $backupRegKey.PSObject.Properties["LastBackupTime"]) {
                    $lastBackupTimeValue = $backupRegKey.LastBackupTime
                    
                    if ($lastBackupTimeValue -ne 0) {
                        $ntdsInfo.IsBackedUp = $true
                        
                        # Convert from Windows file time if needed
                        if ($lastBackupTimeValue -is [Int64] -and $lastBackupTimeValue -gt 100000000000000) {
                            $ntdsInfo.LastBackupTime = [DateTime]::FromFileTime($lastBackupTimeValue).ToString("yyyy-MM-dd HH:mm:ss")
                        } else {
                            $ntdsInfo.LastBackupTime = (Get-Date).AddSeconds(-$lastBackupTimeValue).ToString("yyyy-MM-dd HH:mm:ss")
                        }
                    }
                }
            }
            catch {
                Write-Host "Warning: Unable to check backup registry information: $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Active Directory database info retrieved successfully" -ForegroundColor Green
        return $ntdsInfo
    }
    catch {
        Write-Host "Error retrieving Active Directory database information: $_" -ForegroundColor Red
        return @{
            DatabasePath = "Unknown"
            DatabaseSize = 0
            DatabaseSizeUnit = "GB"
            LogPath = "Unknown"
            LogSize = 0
            LogSizeUnit = "MB"
            LastBackupTime = "Never"
            IsBackedUp = $false
        }
    }
}

function Get-OverallADSecurityChecks {
    Write-Host "Retrieving Active Directory security checks..." -ForegroundColor Cyan
    
    $securityChecks = @{
        # Domain-level Security Settings
        DomainLevelSettings = @()
        
        # Active Directory Security Features
        ADSecurityFeatures = @()
        
        # TLS Configuration
        TLSConfiguration = @()
        
        # Security Protocol Settings
        SecurityProtocolSettings = @()
        
        # Registry Security Settings
        RegistrySecuritySettings = @()
    }
    
    try {
        Write-Host "Checking domain-level security settings..." -ForegroundColor Cyan
        
        # Check Active Directory Recycle Bin
        $recyclebinEnabled = $false
        try {
            $adRootDSE = Get-ADRootDSE
            # Fix for the msDS-EnabledFeature property name
            $enabledFeatures = $adRootDSE."msDS-EnabledFeature"
            # Using -contains operator instead of -match for array comparison
            $recyclebinEnabled = $enabledFeatures -match "Recycle Bin Feature"
        } catch {
            Write-Host "Warning: Unable to check Recycle Bin status: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.DomainLevelSettings += @{
            Setting = "Active Directory Recycle Bin"
            Status = if ($recyclebinEnabled) { "Enabled" } else { "Disabled" }
            RiskAssessment = if ($recyclebinEnabled) { "Good - Allows object recovery" } else { "Medium - Object recovery not possible" }
            Recommendation = if ($recyclebinEnabled) { "No action needed" } else { "Enable Active Directory Recycle Bin" }
        }
        
        # Check LDAP over SSL (LDAPS)
        $ldapsEnabled = $false
        try {
            $testResult = Test-NetConnection -ComputerName $env:COMPUTERNAME -Port 636 -InformationLevel Quiet -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            $ldapsEnabled = $testResult
        } catch {
            Write-Host "Warning: Unable to check LDAPS status: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.DomainLevelSettings += @{
            Setting = "LDAP over SSL (LDAPS)"
            Status = if ($ldapsEnabled) { "Enabled" } else { "Likely Disabled" }
            RiskAssessment = if ($ldapsEnabled) { "Good - Encrypted LDAP communication" } else { "High - Unencrypted LDAP communication" }
            Recommendation = if ($ldapsEnabled) { "No action needed" } else { "Configure LDAP over SSL to encrypt LDAP traffic" }
        }
        
        # Check Local Administrator Password Solution (LAPS)
        $lapsImplemented = $false
        try {
            # Check if LAPS schema extensions exist
            $lapsSchemaExists = $false
            try {
                $schemaNC = (Get-ADRootDSE).schemaNamingContext
                $lapsAttrs = Get-ADObject -Filter "name -eq 'ms-Mcs-AdmPwd'" -SearchBase $schemaNC -ErrorAction SilentlyContinue
                $lapsSchemaExists = ($null -ne $lapsAttrs)
            } catch {
            }
            
            # Check if LAPS GPOs exist
            $lapsGPOExists = $false
            try {
                $lapsGPOs = Get-GPO -All -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*LAPS*" }
                $lapsGPOExists = ($null -ne $lapsGPOs -and $lapsGPOs.Count -gt 0)
            } catch {
            }
            
            $lapsImplemented = $lapsSchemaExists -or $lapsGPOExists
        } catch {
            Write-Host "Warning: Unable to check LAPS implementation: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.DomainLevelSettings += @{
            Setting = "Local Administrator Password Solution (LAPS)"
            Status = if ($lapsImplemented) { "Detected" } else { "Not Detected" }
            RiskAssessment = if ($lapsImplemented) { "Good - Managed local admin passwords" } else { "High - Local admin passwords may be reused" }
            Recommendation = if ($lapsImplemented) { "No action needed" } else { "Deploy Microsoft LAPS to manage local administrator passwords" }
        }
        
        # Check Administrative Tier Model
        $tierModelImplemented = $false
        try {
            # Look for tier-based OUs or groups
            $tierOUsExist = $false
            try {
                $tierOUs = Get-ADOrganizationalUnit -Filter "Name -like '*Tier*'" -ErrorAction SilentlyContinue
                $tierOUsExist = ($null -ne $tierOUs -and $tierOUs.Count -gt 0)
            } catch {
                # Silently continue if we can't check OUs
            }
            
            # Look for tier-based groups
            $tierGroupsExist = $false
            try {
                $tierGroups = Get-ADGroup -Filter "Name -like '*Tier*'" -ErrorAction SilentlyContinue
                $tierGroupsExist = ($null -ne $tierGroups -and $tierGroups.Count -gt 0)
            } catch {
                # Silently continue if we can't check groups
            }
            
            $tierModelImplemented = $tierOUsExist -or $tierGroupsExist
        } catch {
            Write-Host "Warning: Unable to check Administrative Tier Model implementation: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.DomainLevelSettings += @{
            Setting = "Administrative Tier Model"
            Status = if ($tierModelImplemented) { "Detected" } else { "Not Detected" }
            RiskAssessment = if ($tierModelImplemented) { "Good - Segregated administrative privileges" } else { "Medium - Administrative privileges may not be segregated" }
            Recommendation = if ($tierModelImplemented) { "No action needed" } else { "Implement Microsoft's Administrative Tier Model to segregate administrative privileges" }
        }
        
        # Active Directory Security Features
        Write-Host "Checking Active Directory security features..." -ForegroundColor Cyan
        
        # Check AD Administrative Tiering
        $adTieringImplemented = $false
        try {
            # More detailed check of tiering implementation
            $tierImplemented = $false
            try {
                # Check for typical tier OU structure
                $tier0OU = Get-ADOrganizationalUnit -Filter "Name -like '*Tier 0*' -or Name -like '*Tier0*'" -ErrorAction SilentlyContinue
                $tier1OU = Get-ADOrganizationalUnit -Filter "Name -like '*Tier 1*' -or Name -like '*Tier1*'" -ErrorAction SilentlyContinue
                $tier2OU = Get-ADOrganizationalUnit -Filter "Name -like '*Tier 2*' -or Name -like '*Tier2*'" -ErrorAction SilentlyContinue
                
                $tierImplemented = ($null -ne $tier0OU) -or ($null -ne $tier1OU) -or ($null -ne $tier2OU)
            } catch {
            }
            
            $adTieringImplemented = $tierImplemented
        } catch {
            Write-Host "Warning: Unable to check AD Administrative Tiering: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.ADSecurityFeatures += @{
            Feature = "AD Administrative Tiering"
            Status = if ($adTieringImplemented) { "Detected" } else { "Not Detected" }
            SecurityBenefit = "Segregates administration to prevent lateral movement and privilege escalation"
            Recommendation = if ($adTieringImplemented) { "No action needed" } else { "Implement Microsoft's AD tiering model (Tier 0, Tier 1, Tier 2)" }
        }
        
        
        $securityChecks.ADSecurityFeatures += @{
            Feature = "AdminSDHolder Protection"
            Status = "Built-in Feature"
            SecurityBenefit = "Protects privileged accounts from unauthorized permission changes"
            Recommendation = "Ensure AdminSDHolder protection is functioning with regular security audits"
        }
        
        # Check SID History
        $sidHistoryFound = $false
        try {
            $usersWithSIDHistory = Get-ADUser -Filter * -Properties sidHistory | Where-Object { $null -ne $_.sidHistory -and $_.sidHistory.Count -gt 0 }
            $sidHistoryFound = ($null -ne $usersWithSIDHistory -and $usersWithSIDHistory.Count -gt 0)
        } catch {
            Write-Host "Warning: Unable to check SID History: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.ADSecurityFeatures += @{
            Feature = "SID History"
            Status = if ($sidHistoryFound) { "Found" } else { "Not Found" }
            SecurityBenefit = "SID History should be cleaned up post-migration to prevent potential privilege escalation"
            Recommendation = if ($sidHistoryFound) { "Clean up SID History attributes for migrated accounts" } else { "Monitor for unexpected SID History attributes" }
        }
        
        # TLS Configuration
        Write-Host "Checking TLS configuration..." -ForegroundColor Cyan
        
        try {
            $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
            if ($dcs -and $dcs.Count -gt 0) {
                # $serversToCheck = $dcs
            }
        } catch {
            Write-Host "Warning: Unable to get domain controllers list. Checking only current server." -ForegroundColor Yellow
        }
        
        $currentServer = $env:COMPUTERNAME
        
        # Check TLS 1.2
        $tls12Enabled = $false
        try {
            $tls12Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
            if (Test-Path $tls12Path) {
                $tls12Enabled = (Get-ItemProperty -Path $tls12Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -ne 0
            } else {
                # Default is enabled if key doesn't exist
                $tls12Enabled = $true
            }
            
            if (Test-Path $tls12Path) {
                $tls12Disabled = (Get-ItemProperty -Path $tls12Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled -eq 0
                if ($tls12Disabled) {
                    $tls12Enabled = $false
                }
            }
        } catch {
            Write-Host "Warning: Unable to check TLS 1.2 configuration: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.TLSConfiguration += @{
            Protocol = "TLS 1.2"
            Status = if ($tls12Enabled) { "Enabled" } else { "Disabled" }
            RiskAssessment = if ($tls12Enabled) { "Good - Secure protocol enabled" } else { "Critical - Secure protocol disabled" }
        }
        
        # Check TLS 1.0
        $tls10Enabled = $true
        try {
            $tls10Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
            if (Test-Path $tls10Path) {
                $tls10Value = (Get-ItemProperty -Path $tls10Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                if ($null -ne $tls10Value) {
                    $tls10Enabled = $tls10Value -ne 0
                }
                
                # Check if it's explicitly disabled
                $tls10DisabledValue = (Get-ItemProperty -Path $tls10Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                if ($null -ne $tls10DisabledValue -and $tls10DisabledValue -eq 0) {
                    $tls10Enabled = $false
                }
            }
        } catch {
            Write-Host "Warning: Unable to check TLS 1.0 configuration: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.TLSConfiguration += @{
            Protocol = "TLS 1.0"
            Status = if ($tls10Enabled) { "Enabled" } else { "Disabled" }
            RiskAssessment = if ($tls10Enabled) { "High - Outdated protocol enabled" } else { "Good - Outdated protocol disabled" }
        }
        
        # Check TLS 1.1
        $tls11Enabled = $true
        try {
            $tls11Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
            if (Test-Path $tls11Path) {
                $tls11Value = (Get-ItemProperty -Path $tls11Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                if ($null -ne $tls11Value) {
                    $tls11Enabled = $tls11Value -ne 0
                }
                
                $tls11DisabledValue = (Get-ItemProperty -Path $tls11Path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                if ($null -ne $tls11DisabledValue -and $tls11DisabledValue -eq 0) {
                    $tls11Enabled = $false
                }
            }
        } catch {
            Write-Host "Warning: Unable to check TLS 1.1 configuration: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.TLSConfiguration += @{
            Protocol = "TLS 1.1"
            Status = if ($tls11Enabled) { "Enabled" } else { "Disabled" }
            RiskAssessment = if ($tls11Enabled) { "Medium - Outdated protocol enabled" } else { "Good - Outdated protocol disabled" }
        }
        
        # Security Protocol Settings
        Write-Host "Checking security protocol settings..." -ForegroundColor Cyan
        
        # Check SMBv1
        $smbv1Enabled = $true
        try {
            $smbv1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
            if ($smbv1Feature) {
                $smbv1Enabled = $smbv1Feature.State -eq "Enabled"
            } else {
                # Try PowerShell method
                $smbv1Enabled = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol
            }
        } catch {
            Write-Host "Warning: Unable to check SMBv1 configuration: $_" -ForegroundColor Yellow
            try {
                $smbv1Value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
                if ($null -ne $smbv1Value) {
                    $smbv1Enabled = $smbv1Value -eq 1
                }
            } catch {
                Write-Host "Warning: Unable to check SMBv1 registry configuration" -ForegroundColor Yellow
            }
        }
        
        $securityChecks.SecurityProtocolSettings += @{
            Protocol = "SMBv1"
            Status = if ($smbv1Enabled) { "Enabled" } else { "Disabled" }
            RiskAssessment = if ($smbv1Enabled) { "High - Insecure protocol enabled" } else { "Good - Insecure protocol disabled" }
        }
        
        # Check LDAP Signing
        $ldapSigningRequired = $false
        try {
            $ldapSigningValue = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue).LDAPServerIntegrity
            if ($null -ne $ldapSigningValue) {
                $ldapSigningRequired = $ldapSigningValue -ge 2
            } else {
                $ldapSigningRequired = $false
            }
        } catch {
            Write-Host "Warning: Unable to check LDAP Signing configuration: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.SecurityProtocolSettings += @{
            Protocol = "LDAP Signing"
            Status = if ($ldapSigningRequired) { "Required" } else { "Negotiated" }
            RiskAssessment = if ($ldapSigningRequired) { "Good - LDAP signing required" } else { "Medium - Signing negotiated" }
        }
        
        # Registry Security Settings
        Write-Host "Checking registry security settings..." -ForegroundColor Cyan
        
        # Check LSASS Protection
        $lsassProtection = $false
        try {
            $lsassProtectionValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
            $lsassProtection = $lsassProtectionValue -eq 1
        } catch {
            Write-Host "Warning: Unable to check LSASS Protection: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.RegistrySecuritySettings += @{
            Setting = "LSASS Protection"
            Status = if ($lsassProtection) { "Configured" } else { "Not Configured" }
            RiskAssessment = if ($lsassProtection) { "Good - Protected" } else { "Medium - Not configured" }
            ExpectedValue = "1"
            ActualValue = if ($lsassProtection) { "1" } else { "0" }
        }
        
        # Check LSASS Audit Mode
        $lsassAuditMode = $false
        try {
            $lsassAuditModeValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AuditLevel" -ErrorAction SilentlyContinue).AuditLevel
            $lsassAuditMode = $lsassAuditModeValue -ge 1
        } catch {
            Write-Host "Warning: Unable to check LSASS Audit Mode: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.RegistrySecuritySettings += @{
            Setting = "LSASS Audit Mode"
            Status = if ($lsassAuditMode) { "Configured" } else { "Not Configured" }
            RiskAssessment = if ($lsassAuditMode) { "Good - Auditing enabled" } else { "Medium - Not configured" }
            ExpectedValue = "8"
            ActualValue = if ($null -ne $lsassAuditModeValue) { "$lsassAuditModeValue" } else { "0" }
        }
        
        # Check Credential Guard
        $credentialGuard = $false
        try {
            $credGuardReadinessValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
            $credGuardFeatures = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
            
            $credentialGuard = ($credGuardReadinessValue -eq 1) -and ($credGuardFeatures -ge 1)
        } catch {
            Write-Host "Warning: Unable to check Credential Guard: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.RegistrySecuritySettings += @{
            Setting = "Credential Guard"
            Status = if ($credentialGuard) { "Configured" } else { "Not Configured" }
            RiskAssessment = if ($credentialGuard) { "Good - Protection enabled" } else { "Medium - Not configured" }
            ExpectedValue = "1"
            ActualValue = if ($credentialGuard) { "1" } else { "0" }
        }
        
        # Check WDigest Authentication
        $wdigestDisabled = $false
        try {
            $wdigestValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
            $wdigestDisabled = ($wdigestValue -eq 0)
        } catch {
            Write-Host "Warning: Unable to check WDigest Authentication: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.RegistrySecuritySettings += @{
            Setting = "WDigest Authentication"
            Status = if ($wdigestDisabled) { "Secure" } else { "Not Configured" }
            RiskAssessment = if ($wdigestDisabled) { "Good - Disabled" } else { "High - Default is insecure" }
            ExpectedValue = "0"
            ActualValue = if ($null -ne $wdigestValue) { "$wdigestValue" } else { "1" }
        }
        
        # Check NTLM Restrictions
        $ntlmRestrictions = $false
        try {
            $ntlmValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
            $ntlmRestrictions = ($ntlmValue -ge 1)
        } catch {
            Write-Host "Warning: Unable to check NTLM Restrictions: $_" -ForegroundColor Yellow
        }
        
        $securityChecks.RegistrySecuritySettings += @{
            Setting = "NTLM Restrictions"
            Status = if ($ntlmRestrictions) { "Configured" } else { "Not Configured" }
            RiskAssessment = if ($ntlmRestrictions) { "Good - Restricted" } else { "Medium - Not configured" }
            ExpectedValue = "2"
            ActualValue = if ($null -ne $ntlmValue) { "$ntlmValue" } else { "0" }
        }
        
        return $securityChecks
    }
    catch {
        Write-Error "Error retrieving AD security checks: $_"
        return @{
            DomainLevelSettings = @()
            ADSecurityFeatures = @()
            TLSConfiguration = @()
            SecurityProtocolSettings = @()
            RegistrySecuritySettings = @()
        }
    }
}

function Get-WindowsUpdateHistory {
    Write-Host "Retrieving detailed Windows Update history..." -ForegroundColor Cyan
    
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        try {
            Write-Host "Attempting to retrieve Windows Update history using COM object..." -ForegroundColor Cyan
            $updateHistory = $updateSearcher.QueryHistory(0, 100) | 
                Where-Object { $_.Operation -eq 1 -and $_.ResultCode -eq 2 } | 
                Select-Object -First 10
            
            if ($updateHistory -and $updateHistory.Count -gt 0) {
                $detailedUpdates = @()
                
                foreach ($update in $updateHistory) {
                    $detailedUpdates += [PSCustomObject]@{
                        HotFixID = if ($update.Title -match "KB(\d+)") { "KB$($Matches[1])" } else { "N/A" }
                        Title = $update.Title
                        Description = $update.Description
                        InstalledOn = $update.Date.ToString("MM/dd/yyyy HH:mm:ss")
                        InstalledBy = "Windows Update"
                    }
                }
                
                Write-Host "Successfully retrieved detailed Windows Update history using COM object" -ForegroundColor Green
                return $detailedUpdates
            }
        }
        catch {
            Write-Host "Warning: COM object method failed: $_" -ForegroundColor Yellow
        }
        
        try {
            Write-Host "Checking for PSWindowsUpdate module..." -ForegroundColor Cyan
            if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
                Import-Module PSWindowsUpdate
                $psUpdates = Get-WUHistory -Last 10 | 
                    Select-Object @{Name="HotFixID"; Expression={$_.KB}},
                                  @{Name="Title"; Expression={$_.Title}},
                                  @{Name="Description"; Expression={$_.Title}},
                                  @{Name="InstalledOn"; Expression={$_.Date.ToString("MM/dd/yyyy HH:mm:ss")}},
                                  @{Name="InstalledBy"; Expression={"Windows Update"}}
                
                if ($psUpdates -and $psUpdates.Count -gt 0) {
                    Write-Host "Successfully retrieved detailed Windows Update history using PSWindowsUpdate module" -ForegroundColor Green
                    return $psUpdates
                }
            }
        }
        catch {
            Write-Host "Warning: PSWindowsUpdate method failed: $_" -ForegroundColor Yellow
        }
        
        try {
            Write-Host "Attempting to retrieve Windows Update history using Get-HotFix and Windows Update database..." -ForegroundColor Cyan
            
            # Get basic hotfix information
            $hotfixes = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 10
            
            # Try to get more detailed information from the Windows Update database
            $updatesInfo = @()
            
            # Path to Windows Update database and log
            $updateDB = "$env:SystemRoot\SoftwareDistribution\DataStore\DataStore.edb"
            $updateLog = "$env:SystemRoot\WindowsUpdate.log"
            
            if (Test-Path $updateDB) {
                $updateDescriptions = @{}
                
                if (Test-Path $updateLog) {
                    $logContent = Get-Content $updateLog -ErrorAction SilentlyContinue
                    
                    foreach ($line in $logContent) {
                        if ($line -match "KB\d+.*Title = (.+)$") {
                            $kb = $line -replace '.*(KB\d+).*', '$1'
                            $title = $Matches[1]
                            $updateDescriptions[$kb] = $title
                        }
                    }
                }
                
                # Enhanced WMI query to get more information
                $wmiUpdates = Get-WmiObject -Class Win32_QuickFixEngineering | 
                    Sort-Object -Property InstalledOn -Descending | 
                    Select-Object -First 10
                
                # Create enhanced information for each hotfix
                foreach ($hotfix in $hotfixes) {
                    $kbNumber = $hotfix.HotFixID
                    
                    # Try to get the detailed description
                    $detailedDescription = if ($updateDescriptions.ContainsKey($kbNumber)) { 
                        $updateDescriptions[$kbNumber] 
                    } else {
                        if ($hotfix.Description -like "*Security Update*") {
                            "Security Update for Windows Server"
                        } elseif ($hotfix.Description -like "*Update*") {
                            "Cumulative Update for Windows Server"
                        } else {
                            $hotfix.Description
                        }
                    }
                    
                    # Create enhanced object
                    $enhancedUpdate = [PSCustomObject]@{
                        HotFixID = $kbNumber
                        Title = if ($updateDescriptions.ContainsKey($kbNumber)) { 
                            $updateDescriptions[$kbNumber] 
                        } else {
                            "$($hotfix.Description) for Windows Server ($kbNumber)"
                        }
                        Description = $detailedDescription
                        InstalledOn = $hotfix.InstalledOn.ToString("MM/dd/yyyy HH:mm:ss")
                        InstalledBy = $hotfix.InstalledBy
                    }
                    
                    $updatesInfo += $enhancedUpdate
                }
            } else {
                foreach ($hotfix in $hotfixes) {
                    $updateType = "Update"
                    
                    if ($hotfix.Description -like "*Security Update*") {
                        $updateType = "Security Update"
                    } elseif ($hotfix.Description -like "*Cumulative Update*") {
                        $updateType = "Cumulative Update"
                    }
                    
                    $title = "$updateType for Windows Server ($($hotfix.HotFixID))"
                    
                    $enhancedUpdate = [PSCustomObject]@{
                        HotFixID = $hotfix.HotFixID
                        Title = $title
                        Description = $hotfix.Description
                        InstalledOn = $hotfix.InstalledOn.ToString("MM/dd/yyyy HH:mm:ss")
                        InstalledBy = $hotfix.InstalledBy
                    }
                    
                    $updatesInfo += $enhancedUpdate
                }
            }
            
            if ($updatesInfo -and $updatesInfo.Count -gt 0) {
                Write-Host "Successfully retrieved enhanced Windows Update history" -ForegroundColor Green
                return $updatesInfo
            }
        }
        catch {
            Write-Host "Warning: Enhanced Get-HotFix method failed: $_" -ForegroundColor Yellow
        }
        
        $basicUpdates = Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 10 | 
            Select-Object @{Name="HotFixID"; Expression={$_.HotFixID}},
                          @{Name="Title"; Expression={"$($_.Description) for Windows Server ($($_.HotFixID))"}},
                          @{Name="Description"; Expression={$_.Description}},
                          @{Name="InstalledOn"; Expression={$_.InstalledOn.ToString("MM/dd/yyyy HH:mm:ss")}},
                          @{Name="InstalledBy"; Expression={$_.InstalledBy}}
        
        Write-Host "Returning basic Windows Update history as fallback" -ForegroundColor Yellow
        return $basicUpdates
    }
    catch {
        Write-Host "Warning: Unable to retrieve Windows Update history: $_" -ForegroundColor Yellow
        return @()
    }
}

function Get-ServerDiskSpace {
    Write-Host "Retrieving disk space information for the current server..." -ForegroundColor Cyan
    
    try {
        $diskSpaceInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, 
            @{Name="Size(GB)"; Expression={[math]::Round($_.Size/1GB, 2)}},
            @{Name="FreeSpace(GB)"; Expression={[math]::Round($_.FreeSpace/1GB, 2)}},
            @{Name="PercentFree"; Expression={[math]::Round(($_.FreeSpace/$_.Size) * 100, 2)}},
            VolumeName
        
        return $diskSpaceInfo
    }
    catch {
        Write-Host "Warning: Unable to retrieve disk space information: $_" -ForegroundColor Yellow
        return @()
    }
}

function Get-DomainControllerServices {
    Write-Host "Retrieving domain controller service information..." -ForegroundColor Cyan
    
    # Define critical DC services to check
    $dcServices = @(
        "ADWS",           # Active Directory Web Services
        "DNS",            # DNS Server
        "Dnscache",       # DNS Client
        "DFS",            # DFS Namespace
        "DFSR",           # DFS Replication
        "kdc",            # Kerberos Key Distribution Center
        "LanmanServer",   # Server 
        "LanmanWorkstation", # Workstation
        "Netlogon",       # Netlogon
        "NTDS",           # Active Directory Domain Services
        "NtFrs",          # File Replication Service (legacy)
        "W32Time",        # Windows Time
        "IsmServ",        # Intersite Messaging
        "NETSVCS"         # Network Services
    )
    
    try {
        $serviceStatus = @()
        
        foreach ($serviceName in $dcServices) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                
                if ($service) {
                    $serviceInfo = [PSCustomObject]@{
                        Name = $service.DisplayName
                        ServiceName = $service.Name
                        Status = $service.Status
                        StartType = (Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Name)'").StartMode
                    }
                    
                    $serviceStatus += $serviceInfo
                }
            }
            catch {
                # Skip services that don't exist on this server
                Write-Host "Service $serviceName not found or not accessible" -ForegroundColor Yellow
            }
        }
        
        return $serviceStatus
    }
    catch {
        Write-Host "Warning: Unable to retrieve domain controller service information: $_" -ForegroundColor Yellow
        return @()
    }
}

function Get-ChartJsScript {
    $chartJsPath = "$PSScriptRoot\chart.min.js"
    if (Test-Path -Path $chartJsPath) {
        try {
            $content = Get-Content -Path $chartJsPath -Raw -Encoding UTF8
            return $content
        } catch {
            Write-Host "Error reading local Chart.js file: $_" -ForegroundColor Yellow
        }
    }
    
    return Get-MinimalChartJs
}

function Get-DomainPasswordPolicy {
    Write-Host "Retrieving domain password policy..." -ForegroundColor Cyan
    
    try {
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
        
        $policyAssessment = @(
            @{
                Setting = "Minimum Password Length"
                Value = "$($passwordPolicy.MinPasswordLength) characters"
                Status = if ($passwordPolicy.MinPasswordLength -ge 12) { "Good" } else { "Warning" }
                Recommendation = "Should be at least 12 characters"
            },
            @{
                Setting = "Password History"
                Value = "$($passwordPolicy.PasswordHistoryCount) passwords remembered"
                Status = if ($passwordPolicy.PasswordHistoryCount -ge 12) { "Good" } else { "Warning" }
                Recommendation = "Should remember at least 12 previous passwords"
            },
            @{
                Setting = "Maximum Password Age"
                Value = if ($passwordPolicy.MaxPasswordAge -eq [System.TimeSpan]::MaxValue) { 
                    "Never expires" 
                } else { 
                    "$($passwordPolicy.MaxPasswordAge.Days) days" 
                }
                Status = if ($passwordPolicy.MaxPasswordAge.Days -ge 60 -and $passwordPolicy.MaxPasswordAge.Days -le 90) { 
                    "Good" 
                } elseif ($passwordPolicy.MaxPasswordAge -eq [System.TimeSpan]::MaxValue) {
                    "Warning"
                } else { 
                    "Warning" 
                }
                Recommendation = "Should be between 60-90 days (0 means never expires)"
            },
            @{
                Setting = "Minimum Password Age"
                Value = "$($passwordPolicy.MinPasswordAge.Days) days"
                Status = if ($passwordPolicy.MinPasswordAge.Days -ge 1) { "Good" } else { "Warning" }
                Recommendation = "Should be at least 1 day to prevent password cycling"
            },
            @{
                Setting = "Password Complexity"
                Value = if ($passwordPolicy.ComplexityEnabled) { "True" } else { "False" }
                Status = if ($passwordPolicy.ComplexityEnabled) { "Good" } else { "Warning" }
                Recommendation = "Should be enabled to enforce strong passwords"
            },
            @{
                Setting = "Reversible Encryption"
                Value = if ($passwordPolicy.ReversibleEncryptionEnabled) { "True" } else { "False" }
                Status = if (-not $passwordPolicy.ReversibleEncryptionEnabled) { "Good" } else { "Warning" }
                Recommendation = "Should be disabled to protect password security"
            },
            @{
                Setting = "Account Lockout Threshold"
                Value = if ($passwordPolicy.LockoutThreshold -eq 0) { 
                    "0 attempts" 
                } else { 
                    "$($passwordPolicy.LockoutThreshold) attempts" 
                }
                Status = if ($passwordPolicy.LockoutThreshold -ge 3 -and $passwordPolicy.LockoutThreshold -le 10) { 
                    "Good" 
                } else { 
                    "Warning" 
                }
                Recommendation = "Should be between 3-10 attempts (0 means no lockout)"
            },
            @{
                Setting = "Account Lockout Duration"
                Value = if ($passwordPolicy.LockoutDuration -eq [System.TimeSpan]::Zero) {
                    "Until admin unlocks"
                } else {
                    "$($passwordPolicy.LockoutDuration.TotalMinutes) minutes"
                }
                Status = if ($passwordPolicy.LockoutDuration.TotalMinutes -ge 15 -or $passwordPolicy.LockoutDuration -eq [System.TimeSpan]::Zero) { 
                    "Good" 
                } else { 
                    "Warning" 
                }
                Recommendation = "Should be at least 15 minutes"
            }
        )
        
        return $policyAssessment
    } catch {
        Write-Host "Warning: Unable to retrieve domain password policy: $_" -ForegroundColor Yellow
        return @()
    }
}


function Initialize-ADEnvironment {
    Write-Host "Checking Active Directory environment..." -ForegroundColor Cyan
    
    # Check if we're on a domain
    $domainName = $null
    
    try {
        $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
        Write-Host "Computer is part of domain: $domainName" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Unable to detect domain membership using GetComputerDomain(). Trying alternative methods..." -ForegroundColor Yellow
    }
    
    if (-not $domainName) {
        try {
            $domainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainName = $domainInfo.Name
            Write-Host "Computer is part of domain: $domainName (detected via GetCurrentDomain)" -ForegroundColor Green
        } catch {
            Write-Host "Warning: Unable to detect domain membership using GetCurrentDomain(). Trying alternative methods..." -ForegroundColor Yellow
        }
    }
    
    if (-not $domainName) {
        try {
            $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
            if ($computerSystem.PartOfDomain) {
                $domainName = $computerSystem.Domain
                Write-Host "Computer is part of domain: $domainName (detected via WMI)" -ForegroundColor Green
            } else {
                Write-Host "Computer is not part of a domain according to WMI." -ForegroundColor Red
                # Instead of returning false, let's try to continue with alternative methods
            }
        } catch {
            Write-Host "Warning: Unable to determine domain membership via WMI. Trying direct LDAP connection..." -ForegroundColor Yellow
        }
    }
    
    if (-not $domainName) {
        try {
            # Try to connect to the local DC first
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            if ($rootDSE.Properties["defaultNamingContext"].Value) {
                $domainDN = $rootDSE.Properties["defaultNamingContext"].Value
                Write-Host "Connected to Active Directory via LDAP. Domain DN: $domainDN" -ForegroundColor Green
                
                # Try to extract domain name from DN
                $domainParts = $domainDN -split ',DC='
                if ($domainParts.Count -gt 1) {
                    $domainParts = $domainParts | Where-Object { $_ -notlike "DC=*" }
                    $domainName = ($domainParts[1..$domainParts.Count] -join '.').Replace('DC=','')
                    Write-Host "Extracted domain name: $domainName" -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "Warning: Unable to connect to Active Directory via direct LDAP." -ForegroundColor Yellow
        }
    }
    
    if (-not $domainName) {
        Write-Host "================================================================================" -ForegroundColor Red
        Write-Host "ERROR: This computer is not part of an Active Directory domain." -ForegroundColor Yellow
        Write-Host "This script is designed to analyze Active Directory domains and requires" -ForegroundColor Yellow
        Write-Host "that it runs on a Domain Controller." -ForegroundColor Yellow
        Write-Host "" -ForegroundColor Yellow
        Write-Host "Please run this script on a computer that is a Domain Controller." -ForegroundColor Yellow
        Write-Host "================================================================================" -ForegroundColor Red
        return $false
    }
    
    $adModuleAvailable = $false
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adModuleAvailable = $true
        Write-Host "Successfully loaded ActiveDirectory module" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Unable to import ActiveDirectory module using standard method. Trying alternative methods..." -ForegroundColor Yellow
    }
    
    if (-not $adModuleAvailable) {
        try {
            $adModulePath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory\ActiveDirectory.psd1"
            if (Test-Path $adModulePath) {
                Import-Module $adModulePath -ErrorAction Stop
                $adModuleAvailable = $true
                Write-Host "Successfully loaded ActiveDirectory module from: $adModulePath" -ForegroundColor Green
            } else {
                Write-Host "Warning: ActiveDirectory module not found at standard path. Checking RSAT installation..." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Warning: Unable to import ActiveDirectory module from standard path. Checking RSAT installation..." -ForegroundColor Yellow
        }
    }
    
    if (-not $adModuleAvailable) {
        Write-Host "ActiveDirectory module not available. Attempting to use ADSI COM objects instead." -ForegroundColor Yellow
        try {
            $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainName")
            if ($root.distinguishedName) {
                Write-Host "Successfully connected to Active Directory using ADSI" -ForegroundColor Green
                return $true
            } else {
                Write-Host "Error: Unable to connect to Active Directory using ADSI." -ForegroundColor Red
                
                # Try to connect to a specific domain controller
                $dcFound = $false
                try {
                    # Try to find domain controllers
                    $dns = [System.Net.Dns]::GetHostAddresses($domainName)
                    foreach ($ip in $dns) {
                        try {
                            $dcRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($ip.IPAddressToString)")
                            if ($dcRoot.distinguishedName) {
                                Write-Host "Successfully connected to Active Directory at $($ip.IPAddressToString)" -ForegroundColor Green
                                $dcFound = $true
                                break
                            }
                        } catch {
                        }
                    }
                } catch {
                    Write-Host "Warning: Unable to find domain controllers via DNS." -ForegroundColor Yellow
                }
                
                if (-not $dcFound) {
                    # Last resort: Ask user for a domain controller
                    $dcServer = Read-Host "Enter a domain controller name or IP address"
                    if ($dcServer) {
                        try {
                            $dcRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dcServer")
                            if ($dcRoot.distinguishedName) {
                                Write-Host "Successfully connected to Active Directory at $dcServer" -ForegroundColor Green
                                return $true
                            }
                        } catch {
                            Write-Host "Error: Unable to connect to specified domain controller." -ForegroundColor Red
                            Write-Host "Details: $_" -ForegroundColor Red
                            
                            # Show a more user-friendly message and exit gracefully
                            Write-Host "" -ForegroundColor Red
                            Write-Host "================================================================================" -ForegroundColor Red
                            Write-Host "ERROR: Cannot establish a connection to the specified domain controller." -ForegroundColor Red
                            Write-Host "This script requires access to Active Directory to function properly." -ForegroundColor Red
                            Write-Host "================================================================================" -ForegroundColor Red
                            Write-Host "" -ForegroundColor Red
                            return $false
                        }
                    }
                } else {
                    return $true
                }
            }
        } catch {
            Write-Host "Error: Unable to connect to Active Directory." -ForegroundColor Red
            Write-Host "Details: $_" -ForegroundColor Red
            
            Write-Host "" -ForegroundColor Red
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "ERROR: Cannot establish a connection to Active Directory." -ForegroundColor Red
            Write-Host "Please verify:" -ForegroundColor Red
            Write-Host "1. This computer is joined to an Active Directory domain" -ForegroundColor Red
            Write-Host "2. Your account has permissions to query AD" -ForegroundColor Red
            Write-Host "3. Network connectivity to a domain controller is available" -ForegroundColor Red
            Write-Host "4. RSAT tools are installed for Active Directory management" -ForegroundColor Red
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "" -ForegroundColor Red
            
            return $false
        }
    }
    
    try {
        if ($adModuleAvailable) {
            $domainInfo = Get-ADDomain -ErrorAction Stop
            Write-Host "Successfully validated Active Directory connection" -ForegroundColor Green
            return $true
        } else {
            return $true
        }
    } catch {
        Write-Host "Error validating Active Directory connection: $_" -ForegroundColor Red
        
        try {
            $computerName = $env:COMPUTERNAME
            Write-Host "Attempting to connect using local computer as domain controller: $computerName" -ForegroundColor Yellow
            $domainInfo = Get-ADDomain -Server $computerName -ErrorAction Stop
            Write-Host "Successfully connected to AD using local computer as server" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "Error connecting to local AD: $_" -ForegroundColor Red
            
            try {
                $domainName = $env:USERDNSDOMAIN
                if ($domainName) {
                    $dcFinder = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne("$domainName")
                    if ($dcFinder) {
                        $dcName = $dcFinder.Name
                        Write-Host "Attempting to connect to domain controller: $dcName" -ForegroundColor Yellow
                        $domainInfo = Get-ADDomain -Server $dcName -ErrorAction Stop
                        Write-Host "Successfully connected to AD using domain controller $dcName" -ForegroundColor Green
                        return $true
                    }
                }
            } catch {
                Write-Host "Error finding domain controller: $_" -ForegroundColor Red
            }
            
            try {
                if ($env:LOGONSERVER) {
                    $logonServer = $env:LOGONSERVER.Replace('\\','')
                    Write-Host "Attempting to connect using logon server: $logonServer" -ForegroundColor Yellow
                    $domainInfo = Get-ADDomain -Server $logonServer -ErrorAction Stop
                    Write-Host "Successfully connected to AD using logon server $logonServer" -ForegroundColor Green
                    return $true
                }
            } catch {
                Write-Host "Error connecting to logon server: $_" -ForegroundColor Red
            }
            
            Write-Host "" -ForegroundColor Red
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "ERROR: Unable to connect to Active Directory after multiple attempts." -ForegroundColor Red
            Write-Host "This script requires access to Active Directory to function properly." -ForegroundColor Red
            Write-Host "================================================================================" -ForegroundColor Red
            Write-Host "" -ForegroundColor Red
            
            return $false
        }
    }
    
    return $adModuleAvailable
}


function Ensure-OutputDirectory {
    param (
        [string]$Path
    )
    
    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-DomainInfo {
    Write-Host "Retrieving domain information..." -ForegroundColor Cyan
    
    try {
        if ($global:ADCredential) {
            $domainInfo = Get-ADDomain -Credential $global:ADCredential
            $forestInfo = Get-ADForest -Credential $global:ADCredential
        } else {
            $domainInfo = Get-ADDomain
            $forestInfo = Get-ADForest
        }
        
        $readableDomainMode = ConvertTo-ReadableDomainMode -DomainMode $domainInfo.DomainMode
        
        return @{
            Name = $domainInfo.Name
            DNSRoot = $domainInfo.DNSRoot
            NetBIOSName = $domainInfo.NetBIOSName
            DomainMode = $readableDomainMode  # Using converted readable value
            DistinguishedName = $domainInfo.DistinguishedName
            Forest = $domainInfo.Forest
            # All 5 FSMO roles
            SchemaMaster = $forestInfo.SchemaMaster
            DomainNamingMaster = $forestInfo.DomainNamingMaster
            InfrastructureMaster = $domainInfo.InfrastructureMaster
            PDCEmulator = $domainInfo.PDCEmulator
            RIDMaster = $domainInfo.RIDMaster
            DomainControllers = if ($global:ADCredential) {
                (Get-ADDomainController -Filter * -Credential $global:ADCredential | Measure-Object).Count
            } else {
                (Get-ADDomainController -Filter * | Measure-Object).Count
            }
        }
    } catch {
        Write-Host "Warning: Unable to retrieve domain information using AD module. Trying alternative methods..." -ForegroundColor Yellow
        
        if ($env:LOGONSERVER) {
            try {
                $server = $env:LOGONSERVER.Replace('\\','')
                Write-Host "Trying to connect using logon server: $server" -ForegroundColor Yellow
                
                if ($global:ADCredential) {
                    $domainInfo = Get-ADDomain -Server $server -Credential $global:ADCredential
                    $forestInfo = Get-ADForest -Server $server -Credential $global:ADCredential
                } else {
                    $domainInfo = Get-ADDomain -Server $server
                    $forestInfo = Get-ADForest -Server $server
                }
                
                $readableDomainMode = ConvertTo-ReadableDomainMode -DomainMode $domainInfo.DomainMode
                
                return @{
                    Name = $domainInfo.Name
                    DNSRoot = $domainInfo.DNSRoot
                    NetBIOSName = $domainInfo.NetBIOSName
                    DomainMode = $readableDomainMode
                    DistinguishedName = $domainInfo.DistinguishedName
                    Forest = $domainInfo.Forest
                    # All 5 FSMO roles
                    SchemaMaster = $forestInfo.SchemaMaster
                    DomainNamingMaster = $forestInfo.DomainNamingMaster
                    InfrastructureMaster = $domainInfo.InfrastructureMaster
                    PDCEmulator = $domainInfo.PDCEmulator
                    RIDMaster = $domainInfo.RIDMaster
                    DomainControllers = if ($global:ADCredential) {
                        (Get-ADDomainController -Filter * -Server $server -Credential $global:ADCredential | Measure-Object).Count
                    } else {
                        (Get-ADDomainController -Filter * -Server $server | Measure-Object).Count
                    }
                }
            } catch {
                Write-Host "Warning: Unable to use logon server for domain information. Continuing with fallback methods..." -ForegroundColor Yellow
            }
        }
    }
    
    try {
        # Get the current domain
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        
        # Find domain controllers
        $dcs = @($domain.FindAllDomainControllers())
        
        # Get domain info using ADSI
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $domainDN = $rootDSE.defaultNamingContext[0]
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $domain.Name)
        
        # Get FSMO role holders
        $fsmoRoles = @{}
        try {
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($domainContext)
            $fsmoRoles["SchemaMaster"] = $forest.SchemaRoleOwner.Name
            $fsmoRoles["DomainNamingMaster"] = $forest.NamingRoleOwner.Name
        } catch {
            Write-Host "Warning: Unable to retrieve forest FSMO roles: $_" -ForegroundColor Yellow
            $fsmoRoles["SchemaMaster"] = "Unknown"
            $fsmoRoles["DomainNamingMaster"] = "Unknown"
        }
        
        # Get domain functional level
        $domainFunctionalLevel = switch ($domain.DomainMode) {
            1 { "Windows2012Domain" }
            2 { "Windows2012R2Domain" }
            3 { "Windows2016Domain" }
            4 { "Windows2025Domain" }
            default { "Unknown" }
        }
        
        # Convert domain functional level to a more readable format
        $readableDomainFunctionalLevel = ConvertTo-ReadableDomainMode -DomainMode $domainFunctionalLevel
        
        # Determine additional FSMO roles
        foreach ($dc in $dcs) {
            $dcEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($dc.Name)/RootDSE")
            
            if ($dcEntry.dsServiceName -like "*CN=NTDS Settings,CN=$($dc.Name.Split('.')[0])*") {
                if ($dcEntry.hasRole -contains 0) {
                    $fsmoRoles["PDCEmulator"] = $dc.Name
                }
                if ($dcEntry.hasRole -contains 1) {
                    $fsmoRoles["RIDMaster"] = $dc.Name
                }
                if ($dcEntry.hasRole -contains 2) {
                    $fsmoRoles["InfrastructureMaster"] = $dc.Name
                }
            }
        }
        
        # Return domain information
        return @{
            Name = $domain.Name.Split('.')[0]
            DNSRoot = $domain.Name
            NetBIOSName = $domain.Name.Split('.')[0]
            DomainMode = $readableDomainFunctionalLevel  # Using converted readable value
            DistinguishedName = $domainDN
            Forest = $domain.Forest.Name
            # All 5 FSMO roles
            SchemaMaster = $fsmoRoles["SchemaMaster"]
            DomainNamingMaster = $fsmoRoles["DomainNamingMaster"]
            InfrastructureMaster = $fsmoRoles["InfrastructureMaster"]
            PDCEmulator = $fsmoRoles["PDCEmulator"]
            RIDMaster = $fsmoRoles["RIDMaster"]
            DomainControllers = $dcs.Count
        }
    } catch {
        # Last resort - Try with manual input
        Write-Host "All automatic methods to retrieve domain information failed." -ForegroundColor Red
        Write-Host "Would you like to provide domain information manually? (Y/N)" -ForegroundColor Yellow
        $answer = Read-Host
        
        if ($answer -eq 'Y' -or $answer -eq 'y') {
            $manualDomainName = Read-Host "Enter the domain name (e.g., contoso.com)"
            $manualNetBIOS = Read-Host "Enter the NetBIOS name (e.g., CONTOSO)"
            $manualDomainMode = Read-Host "Enter the domain functional level (2008, 2012, 2016, 2019, etc.)"
            $manualDCCount = Read-Host "Enter the number of domain controllers"
            
            # Convert manual domain mode to proper format
            $formattedDomainMode = "Windows Server " + $manualDomainMode
            
            return @{
                Name = $manualNetBIOS
                DNSRoot = $manualDomainName
                NetBIOSName = $manualNetBIOS
                DomainMode = $formattedDomainMode
                DistinguishedName = "DC=" + $manualDomainName.Replace(".", ",DC=")
                Forest = $manualDomainName
                # All 5 FSMO roles
                SchemaMaster = "Unknown (Manual mode)"
                DomainNamingMaster = "Unknown (Manual mode)"
                InfrastructureMaster = "Unknown (Manual mode)"
                PDCEmulator = "Unknown (Manual mode)"
                RIDMaster = "Unknown (Manual mode)"
                DomainControllers = [int]$manualDCCount
            }
        } else {
            Write-Error "Unable to retrieve domain information: $_"
            throw $_
        }
    }
}

function ConvertTo-ReadableDomainMode {
    param (
        [Parameter(Mandatory=$true)]
        [string]$DomainMode
    )
    
    switch ($DomainMode) {
        "Windows2012Domain" { "Windows Server 2012" }
        "Windows2012R2Domain" { "Windows Server 2012 R2" }
        "Windows2016Domain" { "Windows Server 2016" }
        "Windows2025Domain" { "Windows Server 2025" }
        default { $DomainMode } # Return original if not matched
    }
}

function Get-DomainControllersInfo {
    Write-Host "Retrieving domain controllers information..." -ForegroundColor Cyan
    
    # First try using AD module
    try {
        $dcs = Get-ADDomainController -Filter *
        $dcInfoList = @()
        
        foreach ($dc in $dcs) {
            $dcInfo = @{
                Name = $dc.Name
                Hostname = $dc.HostName
                IPv4Address = $dc.IPv4Address
                Site = $dc.Site
                OperatingSystem = $dc.OperatingSystem
                OperatingSystemVersion = $dc.OperatingSystemVersion
                IsGlobalCatalog = $dc.IsGlobalCatalog
                IsReadOnly = $dc.IsReadOnly
            }
            $dcInfoList += $dcInfo
        }
        
        return $dcInfoList
    } catch {
        Write-Host "Warning: Unable to retrieve domain controller information using AD module. Trying alternative methods..." -ForegroundColor Yellow
    }
    
    # Fallback to ADSI if AD module method fails
    try {
        $dcInfoList = @()
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $dcs = $domain.FindAllDomainControllers()
        
        foreach ($dc in $dcs) {
            # Try to get OS information using WMI if possible
            $osInfo = $null
            try {
                if ($dc.Name -eq $env:COMPUTERNAME) {
                    # Local computer, use local WMI
                    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
                } else {
                    # Remote computer, try remote WMI
                    $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $dc.Name -ErrorAction SilentlyContinue
                }
            } catch {
                # WMI failed, continue without OS info
            }
            
            $dcInfo = @{
                Name = $dc.Name.Split('.')[0]
                Hostname = $dc.Name
                IPv4Address = $dc.IPAddress
                Site = $dc.SiteName
                OperatingSystem = if ($osInfo) { $osInfo.Caption } else { "Unknown" }
                OperatingSystemVersion = if ($osInfo) { $osInfo.Version } else { "Unknown" }
                IsGlobalCatalog = $dc.IsGlobalCatalog()
                IsReadOnly = $false
            }
            
            $dcInfoList += $dcInfo
        }
        
        return $dcInfoList
    } catch {
        Write-Error "Unable to retrieve domain controller information: $_"
        throw $_
    }
}


function Get-UsersInfo {
    Write-Host "Retrieving user information..." -ForegroundColor Cyan
    
    try {
        # Standard user queries
        $enabledUsers = (Get-ADUser -Filter {Enabled -eq $true} | Measure-Object).Count
        $disabledUsers = (Get-ADUser -Filter {Enabled -eq $false} | Measure-Object).Count
        $totalStandardUsers = $enabledUsers + $disabledUsers
        
        # Get users created in the last 30 days
        $thirtyDaysAgo = (Get-Date).AddDays(-30)
        $newUsers = (Get-ADUser -Filter {whenCreated -ge $thirtyDaysAgo} | Measure-Object).Count
        
        # Get new users details
        $newUserDetails = Get-ADUser -Filter {whenCreated -ge $thirtyDaysAgo} -Properties whenCreated |
            Select-Object -Property SamAccountName, Name, Enabled, @{
                Name = "CreatedDate"; 
                Expression = { $_.whenCreated.ToString("yyyy-MM-dd") }
            }
        
        # Get password expired users
        $passwordExpiredUsers = (Get-ADUser -Filter {PasswordExpired -eq $true -and Enabled -eq $true} | Measure-Object).Count
        
        # Get password expired user details
        $passwordExpiredUserDetails = Get-ADUser -Filter {PasswordExpired -eq $true -and Enabled -eq $true} -Properties PasswordExpired, PasswordLastSet |
            Select-Object -Property SamAccountName, Name, Enabled, @{
                Name = "PasswordLastSet"; 
                Expression = { if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Never" } }
            }
        
        # Get locked out users
        try {
            $lockedOutUsers = (Search-ADAccount -LockedOut | Measure-Object).Count
            $lockedOutUserDetails = Search-ADAccount -LockedOut | 
                Select-Object -Property SamAccountName, Name, Enabled, @{
                    Name = "LockoutTime"; 
                    Expression = { 
                        if ($_.lockoutTime) {
                            [datetime]::FromFileTime($_.lockoutTime).ToString("yyyy-MM-dd HH:mm:ss")
                        } else {
                            "Unknown"
                        }
                    }
                }
        }
        catch {
            Write-Host "Warning: Unable to retrieve locked out accounts: $_" -ForegroundColor Yellow
            $lockedOutUsers = 0
            $lockedOutUserDetails = @()
        }
        
        $ninetyDaysAgo = (Get-Date).AddDays(-90)
        
        $usersWithLogon = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp, SamAccountName, Name | 
            Where-Object { $null -ne $_.LastLogonTimestamp }
        
        $inactiveUsers = ($usersWithLogon | 
            Where-Object { [datetime]::FromFileTime($_.LastLogonTimestamp) -lt $ninetyDaysAgo } | 
            Measure-Object).Count
        
        $inactiveUserDetails = $usersWithLogon | 
            Where-Object { [datetime]::FromFileTime($_.LastLogonTimestamp) -lt $ninetyDaysAgo } |
            Select-Object -Property SamAccountName, Name, Enabled, @{
                Name = "LastLogon"; 
                Expression = { [datetime]::FromFileTime($_.LastLogonTimestamp).ToString("yyyy-MM-dd") }
            }
        
        $neverLoggedInUsers = (Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp | 
            Where-Object { $null -eq $_.LastLogonTimestamp } | 
            Measure-Object).Count
        
        $neverLoggedInUserDetails = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp, SamAccountName, Name | 
            Where-Object { $null -eq $_.LastLogonTimestamp } |
            Select-Object -Property SamAccountName, Name, Enabled, @{
                Name = "LastLogon"; 
                Expression = { "Never" }
            }
        
        $usersByDepartment = Get-ADUser -Filter * -Properties Department | 
            Where-Object { $_.Department } | 
            Group-Object -Property Department | 
            Sort-Object Count -Descending | 
            Select-Object -First 10 | 
            ForEach-Object {
                @{
                    Department = $_.Name
                    Count = $_.Count
                }
            }
        
        Write-Host "Searching for hidden users..." -ForegroundColor Cyan
        $hiddenUsers = 0
        $hiddenUserList = @()
        
        try {
            # Get domain information first
            $currentDomain = Get-ADDomain
            $domainDN = $currentDomain.DistinguishedName
            
            # Function to analyze object security and determine if it's hidden
            function Get-HiddenObjectInfo {
                param($object)
                
                $reasons = @()
                $deniedRead = $false
                $isUnknown = $false
                
                if ($object.nTSecurityDescriptor) {
                    $deniedReadPermissions = $object.nTSecurityDescriptor.Access | 
                        Where-Object { $_.AccessControlType -eq 'Deny' -and $_.ActiveDirectoryRights -match 'ReadProperty' }
                    if ($deniedReadPermissions) {
                        $deniedRead = $true
                        $reasons += "Denied Read Permission"
                    }
                }
                
                # Check for unknown object type
                if ($object.ObjectClass -eq 'Unknown' -or [string]::IsNullOrEmpty($object.ObjectClass)) {
                    $isUnknown = $true
                    $reasons += "Unknown Object Type"
                }
                
                return @{
                    IsHidden = $deniedRead -or $isUnknown
                    Reasons = $reasons
                    DeniedPermissions = if ($deniedReadPermissions) { $deniedReadPermissions.ActiveDirectoryRights -join ', ' } else { "" }
                }
            }
            
            # Look for Users container
            $usersContainer = @()
            try {
                $usersContainer = Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue | 
                    Where-Object { $_.Name -like "*users*" -or $_.Name -like "*user*" }
            }
            catch {
                Write-Host "Warning: Error finding user containers: $_" -ForegroundColor Yellow
                # Continue execution - we'll use domain DN as fallback
            }
            
            # Determine search base
            $searchBase = $null
            if ($usersContainer -and $usersContainer.Count -gt 0) {
                $searchBase = $usersContainer[0].DistinguishedName
            } elseif (-not [string]::IsNullOrEmpty($domainDN)) {
                $searchBase = $domainDN
                Write-Host "No specific Users container found, using domain DN as search base" -ForegroundColor Yellow
            } else {
                throw "Unable to determine a valid search base for hidden users search"
            }
            
            Write-Host "Searching for hidden users in $searchBase" -ForegroundColor Cyan
            
            # Check 1: Look for regular user objects with suspicious security settings
            try {
                $userObjects = Get-ADObject -Filter {objectClass -eq "user"} -Properties nTSecurityDescriptor, ObjectClass, Name, distinguishedName, whenCreated -SearchBase $searchBase -ErrorAction Stop
                
                foreach ($adObject in $userObjects) {
                    $hiddenInfo = Get-HiddenObjectInfo $adObject
                    
                    if ($hiddenInfo.IsHidden) {
                        $objectName = $adObject.Name
                        if ([string]::IsNullOrEmpty($objectName)) {
                            if ($adObject.distinguishedName -match "CN=([^,]+)") {
                                $objectName = $matches[1]
                            } else {
                                $objectName = "Unknown"
                            }
                        }
                        
                        $hiddenUsers++
                        $hiddenUserList += @{
                            Name = $objectName
                            DistinguishedName = $adObject.DistinguishedName
                            Reasons = $hiddenInfo.Reasons -join ', '
                            Created = if ($adObject.whenCreated) { $adObject.whenCreated.ToString("yyyy-MM-dd") } else { "Unknown" }
                        }
                        
                        Write-Host "Found hidden user: $objectName" -ForegroundColor Yellow
                    }
                }
            }
            catch {
                Write-Host "Warning: Error searching for user objects: $_" -ForegroundColor Yellow
                # Continue with other checks
            }
            
            # Check 2: Look for objects with unknown class
            try {
                # Try using scriptblock filter syntax
                $unknownObjects = Get-ADObject -Filter {(objectClass -eq "unknown") -or (-not (objectClass -like "*"))} -Properties Name, distinguishedName, ObjectClass, whenCreated -SearchBase $searchBase -ErrorAction SilentlyContinue
                
                # If the above fails, try with LDAPFilter
                if ($null -eq $unknownObjects) {
                    Write-Host "Retrying unknown object search with LDAP filter..." -ForegroundColor Yellow
                    $unknownObjects = Get-ADObject -LDAPFilter "(|(objectClass=unknown)(!objectClass=*))" -Properties Name, distinguishedName, ObjectClass, whenCreated -SearchBase $searchBase -ErrorAction SilentlyContinue
                }
                
                if ($unknownObjects) {
                    foreach ($unknownObj in $unknownObjects) {
                        $objectName = $unknownObj.Name
                        if ([string]::IsNullOrEmpty($objectName)) {
                            if ($unknownObj.distinguishedName -match "CN=([^,]+)") {
                                $objectName = $matches[1]
                            } else {
                                $objectName = "Unknown"
                            }
                        }
                        
                        $isDuplicate = $false
                        foreach ($hiddenUser in $hiddenUserList) {
                            if ($hiddenUser.DistinguishedName -eq $unknownObj.DistinguishedName) {
                                $isDuplicate = $true
                                break
                            }
                        }
                        
                        if (-not $isDuplicate) {
                            $hiddenUsers++
                            $hiddenUserList += @{
                                Name = $objectName
                                DistinguishedName = $unknownObj.DistinguishedName
                                Reasons = "Unknown Object Class"
                                Created = if ($unknownObj.whenCreated) { $unknownObj.whenCreated.ToString("yyyy-MM-dd") } else { "Unknown" }
                            }
                            
                            Write-Host "Found hidden user with unknown class: $objectName" -ForegroundColor Yellow
                        }
                    }
                }
            }
            catch {
                Write-Host "Warning: Error searching for unknown objects: $_" -ForegroundColor Yellow
                # Continue with other checks
            }
            
            # Check 3: Look for person objects not classified as users
            try {
                # Try using scriptblock filter
                $personObjects = Get-ADObject -Filter {(objectCategory -eq "person") -and (objectClass -ne "user")} -Properties Name, distinguishedName, ObjectClass, whenCreated -SearchBase $searchBase -ErrorAction SilentlyContinue
                
                # If the above fails, try with LDAPFilter
                if ($null -eq $personObjects) {
                    Write-Host "Retrying person object search with LDAP filter..." -ForegroundColor Yellow
                    $personObjects = Get-ADObject -LDAPFilter "(&(objectCategory=person)(!objectClass=user))" -Properties Name, distinguishedName, ObjectClass, whenCreated -SearchBase $searchBase -ErrorAction SilentlyContinue
                }
                
                if ($personObjects) {
                    foreach ($personObj in $personObjects) {
                        # Skip computer accounts and known service accounts
                        if ($personObj.ObjectClass -eq "computer" -or $personObj.ObjectClass -eq "msDS-GroupManagedServiceAccount" -or $personObj.ObjectClass -eq "msDS-ManagedServiceAccount") {
                            continue
                        }
                        
                        $objectName = $personObj.Name
                        if ([string]::IsNullOrEmpty($objectName)) {
                            if ($personObj.distinguishedName -match "CN=([^,]+)") {
                                $objectName = $matches[1]
                            } else {
                                $objectName = "Unknown"
                            }
                        }
                        
                        $isDuplicate = $false
                        foreach ($hiddenUser in $hiddenUserList) {
                            if ($hiddenUser.DistinguishedName -eq $personObj.DistinguishedName) {
                                $isDuplicate = $true
                                break
                            }
                        }
                        
                        if (-not $isDuplicate) {
                            $hiddenUsers++
                            $hiddenUserList += @{
                                Name = $objectName
                                DistinguishedName = $personObj.DistinguishedName
                                Reasons = "Person object not classified as user (Type: $($personObj.ObjectClass))"
                                Created = if ($personObj.whenCreated) { $personObj.whenCreated.ToString("yyyy-MM-dd") } else { "Unknown" }
                            }
                            
                            Write-Host "Found suspicious person object: $objectName" -ForegroundColor Yellow
                        }
                    }
                }
            }
            catch {
                Write-Host "Warning: Error searching for person objects: $_" -ForegroundColor Yellow
            }
            
            # Final check: Look for access denied exceptions
            if ($hiddenUsers -eq 0) {
                Write-Host "No hidden users found through standard detection, -- not fully functional yet!!!..." -ForegroundColor Yellow
                
                $commonHiddenUsers = @("Administrator", "Guest", "admin", "krbtgt")
                
                foreach ($username in $commonHiddenUsers) {
                    try {
                        $null = Get-ADUser -Filter "Name -eq '$username'" -ErrorAction SilentlyContinue
                    }
                    catch [Microsoft.ActiveDirectory.Management.ADException] {
                        if ($_.Exception.Message -like "*access*denied*" -or $_.Exception.Message -like "*insufficient*rights*") {
                            $hiddenUsers++
                            $hiddenUserList += @{
                                Name = $username
                                DistinguishedName = "Cannot access"
                                Reasons = "Access Denied when querying"
                                Created = "Unknown"
                            }
                            
                            Write-Host "Found potentially hidden user via exception handling: $username" -ForegroundColor Yellow
                        }
                    }
                }
            }
            
            Write-Host "Found $hiddenUsers hidden users in total" -ForegroundColor Cyan
        }
        catch {
            Write-Host "Warning: Error while searching for hidden users: $_" -ForegroundColor Yellow
            Write-Host "Unable to complete hidden users search due to errors." -ForegroundColor Yellow
            # No changes to hiddenUsers count (it remains 0)
            # No additions to hiddenUserList
        }
        
        $totalUsers = $totalStandardUsers + $hiddenUsers
        
        return @{
            HiddenUsers = $hiddenUsers
            HiddenUserDetails = $hiddenUserList
            TotalUsers = $totalUsers
            EnabledUsers = $enabledUsers
            DisabledUsers = $disabledUsers
            NewUsers = $newUsers
            NewUserDetails = $newUserDetails
            InactiveUsers = $inactiveUsers
            InactiveUserDetails = $inactiveUserDetails
            NeverLoggedInUsers = $neverLoggedInUsers
            NeverLoggedInUserDetails = $neverLoggedInUserDetails
            PasswordExpiredUsers = $passwordExpiredUsers
            PasswordExpiredUserDetails = $passwordExpiredUserDetails
            LockedOutUsers = $lockedOutUsers
            LockedOutUserDetails = $lockedOutUserDetails
            UsersByDepartment = $usersByDepartment
        }
    }
    catch {
        Write-Host "Error retrieving user information: $_" -ForegroundColor Red
        return @{
            TotalUsers = 0
            EnabledUsers = 0
            DisabledUsers = 0
            HiddenUsers = 0
            HiddenUserDetails = @()
            NewUsers = 0
            NewUserDetails = @()
            InactiveUsers = 0
            InactiveUserDetails = @()
            NeverLoggedInUsers = 0
            NeverLoggedInUserDetails = @()
            PasswordExpiredUsers = 0
            PasswordExpiredUserDetails = @()
            LockedOutUsers = 0
            LockedOutUserDetails = @()
            UsersByDepartment = @()
        }
    }
}


function Get-GroupsInfo {
    $securityGroups = (Get-ADGroup -Filter {GroupCategory -eq "Security"} | Measure-Object).Count
    $distributionGroups = (Get-ADGroup -Filter {GroupCategory -eq "Distribution"} | Measure-Object).Count
    $totalGroups = $securityGroups + $distributionGroups
    
    $universalGroups = (Get-ADGroup -Filter {GroupScope -eq "Universal"} | Measure-Object).Count
    $globalGroups = (Get-ADGroup -Filter {GroupScope -eq "Global"} | Measure-Object).Count
    $domainLocalGroups = (Get-ADGroup -Filter {GroupScope -eq "DomainLocal"} | Measure-Object).Count
    
    $topGroups = Get-ADGroup -Filter * -Properties Members | 
        Select-Object Name, @{Name="MemberCount"; Expression={$_.Members.Count}} | 
        Sort-Object MemberCount -Descending | 
        Select-Object -First 10 | 
        ForEach-Object {
            @{
                Name = $_.Name
                MemberCount = $_.MemberCount
            }
        }
    
    return @{
        TotalGroups = $totalGroups
        SecurityGroups = $securityGroups
        DistributionGroups = $distributionGroups
        UniversalGroups = $universalGroups
        GlobalGroups = $globalGroups
        DomainLocalGroups = $domainLocalGroups
        TopGroupsByMemberCount = $topGroups
    }
}

function Get-ComputersInfo {
    $enabledComputers = (Get-ADComputer -Filter {Enabled -eq $true} | Measure-Object).Count
    $disabledComputers = (Get-ADComputer -Filter {Enabled -eq $false} | Measure-Object).Count
    $totalComputers = $enabledComputers + $disabledComputers
    
    $computersByOS = Get-ADComputer -Filter * -Properties OperatingSystem | 
        Where-Object { $_.OperatingSystem } | 
        Group-Object -Property OperatingSystem | 
        Sort-Object Count -Descending | 
        ForEach-Object {
            @{
                OperatingSystem = $_.Name
                Count = $_.Count
            }
        }
    
    $thirtyDaysAgo = (Get-Date).AddDays(-30)
    $newComputers = (Get-ADComputer -Filter {whenCreated -ge $thirtyDaysAgo} | Measure-Object).Count
    
    $ninetyDaysAgo = (Get-Date).AddDays(-90)
    $inactiveComputers = (Get-ADComputer -Filter {LastLogonTimeStamp -lt $ninetyDaysAgo -and Enabled -eq $true} -Properties LastLogonTimeStamp | Measure-Object).Count
    
    $enabledComputersList = Get-ADComputer -Filter {Enabled -eq $true} -Properties Name, OperatingSystem, LastLogonTimeStamp, whenCreated |
        Select-Object Name, OperatingSystem, @{
            Name = "LastLogon";
            Expression = { if ($_.LastLogonTimeStamp) { [datetime]::FromFileTime($_.LastLogonTimeStamp).ToString("yyyy-MM-dd") } else { "Never" } }
        }, @{
            Name = "Created";
            Expression = { $_.whenCreated.ToString("yyyy-MM-dd") }
        }
    
    $disabledComputersList = Get-ADComputer -Filter {Enabled -eq $false} -Properties Name, OperatingSystem, LastLogonTimeStamp, whenCreated |
        Select-Object Name, OperatingSystem, @{
            Name = "LastLogon";
            Expression = { if ($_.LastLogonTimeStamp) { [datetime]::FromFileTime($_.LastLogonTimeStamp).ToString("yyyy-MM-dd") } else { "Never" } }
        }, @{
            Name = "Created";
            Expression = { $_.whenCreated.ToString("yyyy-MM-dd") }
        }
    
    $newComputersList = Get-ADComputer -Filter {whenCreated -ge $thirtyDaysAgo} -Properties Name, OperatingSystem, LastLogonTimeStamp, whenCreated |
        Select-Object Name, OperatingSystem, @{
            Name = "LastLogon";
            Expression = { if ($_.LastLogonTimeStamp) { [datetime]::FromFileTime($_.LastLogonTimeStamp).ToString("yyyy-MM-dd") } else { "Never" } }
        }, @{
            Name = "Created";
            Expression = { $_.whenCreated.ToString("yyyy-MM-dd") }
        }
    
    $inactiveComputersList = Get-ADComputer -Filter {LastLogonTimeStamp -lt $ninetyDaysAgo -and Enabled -eq $true} -Properties Name, OperatingSystem, LastLogonTimeStamp, whenCreated |
        Select-Object Name, OperatingSystem, @{
            Name = "LastLogon";
            Expression = { if ($_.LastLogonTimeStamp) { [datetime]::FromFileTime($_.LastLogonTimeStamp).ToString("yyyy-MM-dd") } else { "Never" } }
        }, @{
            Name = "Created";
            Expression = { $_.whenCreated.ToString("yyyy-MM-dd") }
        }
    
    return @{
        TotalComputers = $totalComputers
        EnabledComputers = $enabledComputers
        DisabledComputers = $disabledComputers
        NewComputers = $newComputers
        InactiveComputers = $inactiveComputers
        ComputersByOS = $computersByOS
        # NEW: Add the detailed computer lists
        EnabledComputersList = $enabledComputersList
        DisabledComputersList = $disabledComputersList
        NewComputersList = $newComputersList
        InactiveComputersList = $inactiveComputersList
    }
}

function Get-OUsInfo {
    $totalOUs = (Get-ADOrganizationalUnit -Filter * | Measure-Object).Count
    
    $ousByChildCount = Get-ADOrganizationalUnit -Filter * | 
        ForEach-Object {
            $childCount = (Get-ADObject -Filter * -SearchBase $_.DistinguishedName | Measure-Object).Count - 1  # Subtract 1 to exclude the OU itself
            [PSCustomObject]@{
                Name = $_.Name
                DistinguishedName = $_.DistinguishedName
                ChildCount = $childCount
            }
        } | 
        Sort-Object ChildCount -Descending | 
        Select-Object -First 10 |
        ForEach-Object {
            @{
                Name = $_.Name
                DistinguishedName = $_.DistinguishedName
                ChildCount = $_.ChildCount
            }
        }
    
    return @{
        TotalOUs = $totalOUs
        TopOUsByChildCount = $ousByChildCount
    }
}


function Get-SitesInfo {
    $adSites = Get-ADReplicationSite -Filter *
    $totalSites = $adSites.Count
    
    $sitesList = $adSites | ForEach-Object {
        $siteName = $_.Name
        $siteLinks = Get-ADReplicationSiteLink -Filter * | Where-Object { $_.SitesIncluded -contains $_.DistinguishedName }
        
        @{
            Name = $siteName
            Links = ($siteLinks | Measure-Object).Count
            Subnets = (Get-ADReplicationSubnet -Filter * | Where-Object { $_.Site -eq $_.DistinguishedName } | Measure-Object).Count
        }
    }
    
    return @{
        TotalSites = $totalSites
        Sites = $sitesList
    }
}

function Get-GPOsInfo {
    Write-Host "Retrieving Group Policy information..." -ForegroundColor Cyan
    
    $gpModuleAvailable = $false
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $gpModuleAvailable = $true
        Write-Host "Successfully loaded GroupPolicy module" -ForegroundColor Green
    } catch {
        Write-Host "Warning: Unable to import GroupPolicy module. Group Policy information will be limited." -ForegroundColor Yellow
    }
    
    if ($gpModuleAvailable) {
        $canConnectGPO = $false
        try {
            $domainObj = Get-ADDomain -ErrorAction SilentlyContinue
            if ($domainObj) {
                $domainName = $domainObj.DNSRoot
                
                $gptestResult = $null
                $gptestResult = Get-GPO -Id "31B2F340-016D-11D2-945F-00C04FB984F9" -Domain $domainName -ErrorAction SilentlyContinue
                
                if ($gptestResult) {
                    $canConnectGPO = $true
                    Write-Host "Successfully connected to Group Policy service on domain: $domainName" -ForegroundColor Green
                }
            }
        } catch {
            $canConnectGPO = $false
        }
        
        if ($canConnectGPO) {
            try {
                $gpos = Get-GPO -All -Domain $domainName -ErrorAction Stop
                $totalGPOs = $gpos.Count
                
                $gposList = @()
                foreach ($gpo in $gpos) {
                    $linkedOUs = @()
                    try {
                        [xml]$gpoReport = $gpo.GenerateReport('Xml')
                        $links = $gpoReport.GPO.LinksTo
                        
                        if ($links) {
                            foreach ($link in $links) {
                                $linkedOUs += $link.SOMPath
                            }
                        }
                    } catch {
                        Write-Host "Warning: Unable to retrieve linked OUs for GPO $($gpo.DisplayName): $_" -ForegroundColor Yellow
                    }
                    
                    $gposList += @{
                        Name = $gpo.DisplayName
                        ID = $gpo.Id
                        CreationTime = $gpo.CreationTime.ToString("dd-MM-yyyy")
                        ModificationTime = $gpo.ModificationTime.ToString("dd-MM-yyyy")
                        Status = $gpo.GpoStatus
                        LinkedOUs = $linkedOUs -join "; "
                    }
                }
                
                $thirtyDaysAgo = (Get-Date).AddDays(-30)
                $recentlyModifiedGPOs = ($gpos | Where-Object { $_.ModificationTime -ge $thirtyDaysAgo } | Measure-Object).Count
                
                Write-Host "Successfully retrieved $totalGPOs GPOs from the domain" -ForegroundColor Green
                
                return @{
                    TotalGPOs = $totalGPOs
                    RecentlyModifiedGPOs = $recentlyModifiedGPOs
                    GPOs = $gposList
                }
            } catch {
                $canConnectGPO = $false
                Write-Host "Using alternative ADSI method to retrieve GPO information" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Using alternative ADSI method to retrieve GPO information" -ForegroundColor Yellow
        }
    }
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainDN = "DC=" + $domain.Name.Replace(".", ",DC=")
        $gpoContainer = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Policies,CN=System,$domainDN")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $gpoContainer
        $searcher.Filter = "(objectClass=groupPolicyContainer)"
        $gpoResults = $searcher.FindAll()
        $gpoCount = $gpoResults.Count
        
        $gposList = @()
        foreach ($result in $gpoResults) {
            $gpo = $result.Properties
            $displayName = "Unknown"
            
            $gpoCN = if ($gpo.cn -and $gpo.cn.Count -gt 0) { 
                $gpo.cn[0].ToString().Replace("{", "").Replace("}", "") 
            } else { 
                "Unknown" 
            }
            
            if ($gpo.displayname -and $gpo.displayname.Count -gt 0) {
                $displayName = $gpo.displayname[0]
            }
            elseif ($gpo.gpcdisplayname -and $gpo.gpcdisplayname.Count -gt 0) {
                $displayName = $gpo.gpcdisplayname[0]
            }
            
            $createdTime = "Unknown"
            $modifiedTime = "Unknown"
            
            if ($gpo.whencreated -and $gpo.whencreated.Count -gt 0) {
                $createdTime = $gpo.whencreated[0]
                # Format date if it's a DateTime object
                if ($createdTime -is [DateTime]) {
                    $createdTime = $createdTime.ToString("dd-MM-yyyy")
                }
            }
            
            if ($gpo.whenchanged -and $gpo.whenchanged.Count -gt 0) {
                $modifiedTime = $gpo.whenchanged[0]
                if ($modifiedTime -is [DateTime]) {
                    $modifiedTime = $modifiedTime.ToString("dd-MM-yyyy")
                }
            }
            
            $gpoStatus = "Enabled"
            if ($gpo.flags -and $gpo.flags.Count -gt 0) {
                $flagValue = [int]$gpo.flags[0]
                if ($flagValue -eq 3) {
                    $gpoStatus = "All Settings Disabled"
                } elseif ($flagValue -eq 1) {
                    $gpoStatus = "Computer Settings Disabled"
                } elseif ($flagValue -eq 2) {
                    $gpoStatus = "User Settings Disabled"
                }
            }
            
            $linkedOUs = ""
            try {
                $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
                $defaultNamingContext = $rootDSE.defaultNamingContext[0]
                
                $rootSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $rootSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNamingContext")
                $rootSearcher.Filter = "(&(objectClass=*)(gPLink=*$gpoCN*))"
                $rootSearcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
                
                $linkedOUResults = $rootSearcher.FindAll()
                
                $linkedOUsArray = @()
                foreach ($linkedOU in $linkedOUResults) {
                    $linkedOUsArray += $linkedOU.Properties.distinguishedname[0]
                }
                
                $linkedOUs = $linkedOUsArray -join "; "
            } catch {
                Write-Host "Warning: Unable to retrieve linked OUs for GPO $displayName" -ForegroundColor Yellow
            }
            
            $gposList += @{
                Name = $displayName
                ID = $gpoCN
                CreationTime = $createdTime
                ModificationTime = $modifiedTime
                Status = $gpoStatus
                LinkedOUs = $linkedOUs
            }
        }
        
        Write-Host "Retrieved $gpoCount GPOs using ADSI method" -ForegroundColor Green
        
        return @{
            TotalGPOs = $gpoCount
            RecentlyModifiedGPOs = 0
            GPOs = $gposList
        }
    } catch {
        Write-Host "ADSI method for GPO retrieval also failed: $_" -ForegroundColor Red
    }
    
    Write-Host "Unable to retrieve Group Policy information. This section will be limited in the report." -ForegroundColor Yellow
    return @{
        TotalGPOs = 0
        RecentlyModifiedGPOs = 0
        GPOs = @()
    }
}

function Invoke-SafeFunction {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FunctionName,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory=$false)]
        [object]$DefaultValue = $null
    )
    
    try {
        Write-Host "Executing $FunctionName..." -ForegroundColor Cyan
        return & $ScriptBlock
    } catch {
        Write-Host "Warning: $FunctionName failed with error: $_" -ForegroundColor Yellow
        Write-Host "Returning default/empty data for this section" -ForegroundColor Yellow
        return $DefaultValue
    }
}

function Get-DomainAnalysisData {
    $data = @{
        ReportGenerated = Get-FormattedDateTime
    }
    
    try {
        $serverName = $env:COMPUTERNAME
        
        if ([string]::IsNullOrWhiteSpace($serverName)) {
            $serverName = [System.Net.Dns]::GetHostName()
        }
        
        if ([string]::IsNullOrWhiteSpace($serverName)) {
            $serverName = (Get-WmiObject -Class Win32_ComputerSystem).Name
        }
        
        $data.CurrentServerName = $serverName
    }
    catch {
        Write-Host "Warning: Unable to get server name: $_" -ForegroundColor Yellow
        $data.CurrentServerName = "Unknown"
    }
    
    $data.Domain = Get-DomainInfo
    
    $data.DomainControllers = Invoke-SafeFunction -FunctionName "Get-DomainControllersInfo" -ScriptBlock { 
        Get-DomainControllersInfo 
    } -DefaultValue @()
    
    $data.CurrentServerDiskSpace = Invoke-SafeFunction -FunctionName "Get-ServerDiskSpace" -ScriptBlock {
        Get-ServerDiskSpace
    } -DefaultValue @()
    
    $data.DomainControllerServices = Invoke-SafeFunction -FunctionName "Get-DomainControllerServices" -ScriptBlock {
        Get-DomainControllerServices
    } -DefaultValue @()
    
    $data.ADDatabaseInfo = Invoke-SafeFunction -FunctionName "Get-ADDatabaseInfo" -ScriptBlock {
        Get-ADDatabaseInfo
    } -DefaultValue @{
        DatabasePath = "Unknown"
        DatabaseSize = 0
        DatabaseSizeUnit = "GB"
        LogPath = "Unknown"
        LogSize = 0
        LogSizeUnit = "MB"
        LastBackupTime = "Never"
        IsBackedUp = $false
    }
    
    $data.WindowsUpdateHistory = Invoke-SafeFunction -FunctionName "Get-WindowsUpdateHistory" -ScriptBlock {
        Get-WindowsUpdateHistory
    } -DefaultValue @()
    
    $data.Users = Invoke-SafeFunction -FunctionName "Get-UsersInfo" -ScriptBlock { 
        Get-UsersInfo 
    } -DefaultValue @{
        TotalUsers = 0
        EnabledUsers = 0
        DisabledUsers = 0
        NewUsers = 0
        InactiveUsers = 0
        PasswordExpiredUsers = 0
        UsersByDepartment = @()
    }
    
    $data.Groups = Invoke-SafeFunction -FunctionName "Get-GroupsInfo" -ScriptBlock { 
        Get-GroupsInfo 
    } -DefaultValue @{
        TotalGroups = 0
        SecurityGroups = 0
        DistributionGroups = 0
        UniversalGroups = 0
        GlobalGroups = 0
        DomainLocalGroups = 0
        TopGroupsByMemberCount = @()
    }
    
    $data.Computers = Invoke-SafeFunction -FunctionName "Get-ComputersInfo" -ScriptBlock { 
        Get-ComputersInfo 
    } -DefaultValue @{
        TotalComputers = 0
        EnabledComputers = 0
        DisabledComputers = 0
        NewComputers = 0
        InactiveComputers = 0
        ComputersByOS = @()
    }
    
    $data.OrganizationalUnits = Invoke-SafeFunction -FunctionName "Get-OUsInfo" -ScriptBlock { 
        Get-OUsInfo 
    } -DefaultValue @{
        TotalOUs = 0
        TopOUsByChildCount = @()
    }
    
    $data.Sites = Invoke-SafeFunction -FunctionName "Get-SitesInfo" -ScriptBlock { 
        Get-SitesInfo 
    } -DefaultValue @{
        TotalSites = 0
        Sites = @()
    }
    
    $data.GroupPolicies = Invoke-SafeFunction -FunctionName "Get-GPOsInfo" -ScriptBlock { 
        Get-GPOsInfo 
    } -DefaultValue @{
        TotalGPOs = 0
        RecentlyModifiedGPOs = 0
        GPOs = @()
    }
    
    $data.DCDiagReplication = Invoke-SafeFunction -FunctionName "Get-DCDiagReplicationInfo" -ScriptBlock {
    Get-DCDiagReplicationInfo
    } -DefaultValue @{
    ReplicationPartners = @()
    HasReplicationErrors = $false
    }

    $data.PasswordPolicy = Invoke-SafeFunction -FunctionName "Get-DomainPasswordPolicy" -ScriptBlock { 
        Get-DomainPasswordPolicy 
    } -DefaultValue @()

     $data.SecurityChecks = Invoke-SafeFunction -FunctionName "Get-OverallADSecurityChecks" -ScriptBlock { 
    Get-OverallADSecurityChecks 
    } -DefaultValue @{
        DomainLevelSettings = @()
        ADSecurityFeatures = @()
        TLSConfiguration = @()
        SecurityProtocolSettings = @()
        RegistrySecuritySettings = @()
    }
    
    return $data
}

function Save-DataAsJson {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $jsonData = $Data | ConvertTo-Json -Depth 10
    $jsonData | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "Data saved to $OutputPath"
}


function Generate-HTMLReport {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
$chartJsScript = Get-ChartJsScript

$jsonData = $Data | ConvertTo-Json -Depth 10 -Compress
$base64Data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($jsonData))

$htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Domain Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #0a0a14;
        }

        .container {
            max-width: 90%;
            width: 90%;
            margin: 0 auto;
            padding: 20px;
            background-color: transparent;
        }
        .header {
            background-color: #282828;
            color: #7ac2ff;
            padding: 10px 15px;
            border-radius: 15px;
            margin-bottom: 15px;
            border: 1px solid #3a6a99;
            box-shadow: 0 0 1px white, 0 0 2px white;
        }

        .info-line {
            display: flex;
            justify-content: space-between;
            align-items: center;
            width: 100%;
            margin: 5px 0;
        }


        .report-title {
            margin: 0;
            font-size: 24px;
            font-weight: normal;
            letter-spacing: 1px;
            text-shadow: 0px 0px 5px rgba(122, 194, 255, 0.5);
            box-shadow: 0 0 1px white, 0 0 2px white;
        }
    
        .report-timestamp, .report-domain {
            margin: 5px 0 0;
            font-size: 20px;
            opacity: 0.9;
            font-weight: normal;
            color: #FFFFFF;
            box-shadow: 0 0 1px white, 0 0 2px white;
        }

        .timestamp-badge {
            background-color: #333333;
            color: #FFFFFF;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            letter-spacing: 0.5px;
            border: none;
            text-align: right;
            box-shadow: 0 0 1px white, 0 0 2px white;
        }

        .report-domain {
            margin: 5px 0 0;
            font-size: 20px;
            opacity: 0.9;
            font-weight: 600;
            box-shadow: 0 0 1px white, 0 0 2px white;
        }
        .card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }

        .card-header {
            background-color: #d0d0d0;
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
            font-weight: bold;
        }
        .card-body {
            padding: 20px;
        }
        .coffee-button {
            position: fixed;
            bottom: 20px;
            left: 20px;
            padding: 10px 15px;
            background-color: #FFDD00;
            color: #000000;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            gap: 8px;
            z-index: 1000;
            transition: all 0.2s ease;
            text-decoration: none;
        }
        .coffee-button:hover {
            background-color: #FFD000;
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.3);
        }
        .export-button {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 12px 18px;
            background-color: #3050C8;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
            display: flex;
            align-items: center;
            gap: 10px;
            z-index: 1000;
            transition: all 0.2s ease;
        }
        .export-button:hover {
            background-color: #2040A0;
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(0,0,0,0.3);
        }
        .export-button:active {
            transform: translateY(1px);
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .highlight-text {
            background-color: #333333;
            padding: 2px 6px;
            border-radius: 2px;
            font-weight: normal;
            display: inline-block;
            margin-top: 2px;
            color: #FFFFFF;
            box-shadow: 0 0 1px white, 0 0 2px white;
        }
        .version-badge {
            background-color: #333333;
            color: #FFFFFF;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            letter-spacing: 0.5px;
            border: none;
            box-shadow: 0 0 1px white, 0 0 2px white;
        }
        .stats-container {
            display: flex;
            flex-wrap: wrap;
            margin: 0 -10px;
        }
        .stat-box {
            flex: 1 0 200px;
            margin: 10px;
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 15px;
            text-align: center;
        }
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #4169E1;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 14px;
            color: #666;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }
        th {
            background-color: #f0f0f0;
            font-weight: 600;
        }
        tr:hover {
            background-color: #f1f1f1;
        }
        .chart-container {
            height: 300px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            padding: 20px;
            font-size: 12px;
            color: #666;
        }
        .progress-bar-container {
            width: 100%;
            background-color: #e9ecef;
            border-radius: 4px;
            margin-top: 5px;
        }
        .progress-bar {
            height: 10px;
            border-radius: 4px;
            background-color: #4169E1;
        }
        .grid-container {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        @media (max-width: 768px) {
            .stat-box {
                flex: 1 0 100%;
            }
            .report-title {
                font-size: 20px;
            }
            .report-timestamp, .report-domain {
                font-size: 12px;
            }
        }
        .text-success {
            color: #28a745;
        }
        .text-warning {
            color: #ffc107;
        }
        .text-danger {
            color: #dc3545;
        }
    </style>
    <!-- Embedded Chart.js with fallback -->
    <script>
    $chartJsScript
    </script>
    
    <!-- Fallback to CDN if embedded version fails -->
    <script>
    if (typeof Chart === 'undefined') {
        console.log('Loading Chart.js from CDN as fallback');
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/chart.js@3.9.1';
        script.async = true;
        document.head.appendChild(script);
    }
    </script>

    <script>
    function exportToCsv() {
    // Define the data to export
    const reportData = JSON.parse(atob('REPORT_DATA_PLACEHOLDER'));
    
    // Function to escape CSV values properly
    function escapeCSV(value) {
        if (value === null || value === undefined) return '';
        const stringValue = String(value);
        // If the value contains commas, quotes, or newlines, wrap it in quotes and escape any quotes
        if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
            return '"' + stringValue.replace(/"/g, '""') + '"';
        }
        return stringValue;
    }
    
    // Function to format a simple data section
    function formatSection(title, data) {
        let csv = title + '\r\n';
        
        // Add header row only if the data is an array of objects
        if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object') {
            const headers = Object.keys(data[0]);
            csv += headers.join(',') + '\r\n';
            
            // Add data rows
            data.forEach(row => {
                csv += headers.map(header => escapeCSV(row[header])).join(',') + '\r\n';
            });
        } 
        // If it's a single object with key-value pairs
        else if (typeof data === 'object' && !Array.isArray(data)) {
            csv += 'Property,Value\r\n';
            
            Object.entries(data).forEach(([key, value]) => {
                // Skip if the value is an object or array (we'll handle those separately)
                if (typeof value !== 'object' || value === null) {
                    csv += escapeCSV(key) + ',' + escapeCSV(value) + '\r\n';
                }
            });
        }
        
        return csv + '\r\n';
    }
    
    // Start building the CSV content
    let csvContent = 'Domain Analysis Report - ' + reportData.Domain.DNSRoot + ' - Current Server: ' + reportData.CurrentServerName + '\r\n';
    csvContent += 'Generated on: ' + reportData.ReportGenerated + '\r\n\r\n';
    
    // Domain Information
    csvContent += 'DOMAIN INFORMATION\r\n';
    csvContent += 'Property,Value\r\n';
    csvContent += 'Name,' + escapeCSV(reportData.Domain.Name) + '\r\n';
    csvContent += 'DNSRoot,' + escapeCSV(reportData.Domain.DNSRoot) + '\r\n';
    csvContent += 'NetBIOSName,' + escapeCSV(reportData.Domain.NetBIOSName) + '\r\n';
    csvContent += 'DomainMode,' + escapeCSV(reportData.Domain.DomainMode) + '\r\n';
    csvContent += 'Forest,' + escapeCSV(reportData.Domain.Forest) + '\r\n';
    csvContent += 'SchemaMaster,' + escapeCSV(reportData.Domain.SchemaMaster) + '\r\n';
    csvContent += 'DomainNamingMaster,' + escapeCSV(reportData.Domain.DomainNamingMaster) + '\r\n';
    csvContent += 'PDCEmulator,' + escapeCSV(reportData.Domain.PDCEmulator) + '\r\n';
    csvContent += 'RIDMaster,' + escapeCSV(reportData.Domain.RIDMaster) + '\r\n';
    csvContent += 'InfrastructureMaster,' + escapeCSV(reportData.Domain.InfrastructureMaster) + '\r\n';
    csvContent += 'DomainControllers,' + escapeCSV(reportData.Domain.DomainControllers) + '\r\n\r\n';
    
    // User Statistics
    csvContent += 'USER STATISTICS\r\n';
    csvContent += 'Property,Value\r\n';
    csvContent += 'Total Users,' + escapeCSV(reportData.Users.TotalUsers) + '\r\n';
    csvContent += 'Enabled Users,' + escapeCSV(reportData.Users.EnabledUsers) + '\r\n';
    csvContent += 'Disabled Users,' + escapeCSV(reportData.Users.DisabledUsers) + '\r\n';
    csvContent += 'Hidden Users,' + escapeCSV(reportData.Users.HiddenUsers) + '\r\n';
    csvContent += 'New Users (30 days),' + escapeCSV(reportData.Users.NewUsers) + '\r\n';
    csvContent += 'Inactive Users (90+ days),' + escapeCSV(reportData.Users.InactiveUsers) + '\r\n';
    csvContent += 'Never Logged In,' + escapeCSV(reportData.Users.NeverLoggedInUsers) + '\r\n';
    csvContent += 'Password Expired,' + escapeCSV(reportData.Users.PasswordExpiredUsers) + '\r\n';
    csvContent += 'Locked Out,' + escapeCSV(reportData.Users.LockedOutUsers) + '\r\n\r\n';
    
    // Add hidden user details if available
    if (reportData.Users.HiddenUserDetails && reportData.Users.HiddenUserDetails.length > 0) {
        csvContent += 'HIDDEN USERS\r\n';
        const hiddenUserHeaders = Object.keys(reportData.Users.HiddenUserDetails[0]);
        csvContent += hiddenUserHeaders.join(',') + '\r\n';
        
        reportData.Users.HiddenUserDetails.forEach(user => {
            csvContent += hiddenUserHeaders.map(header => escapeCSV(user[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Add Inactive Users (90+ days)
    if (reportData.Users.InactiveUserDetails && reportData.Users.InactiveUserDetails.length > 0) {
        csvContent += 'INACTIVE USERS (90+ DAYS)\r\n';
        const inactiveHeaders = Object.keys(reportData.Users.InactiveUserDetails[0]);
        csvContent += inactiveHeaders.join(',') + '\r\n';
        
        reportData.Users.InactiveUserDetails.forEach(user => {
            csvContent += inactiveHeaders.map(header => escapeCSV(user[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }

    // Add Never Logged In Users
    if (reportData.Users.NeverLoggedInUserDetails && reportData.Users.NeverLoggedInUserDetails.length > 0) {
        csvContent += 'USERS THAT NEVER LOGGED IN\r\n';
        const neverLoggedHeaders = Object.keys(reportData.Users.NeverLoggedInUserDetails[0]);
        csvContent += neverLoggedHeaders.join(',') + '\r\n';
        
        reportData.Users.NeverLoggedInUserDetails.forEach(user => {
            csvContent += neverLoggedHeaders.map(header => escapeCSV(user[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }

    // Add Password Expired Users
    if (reportData.Users.PasswordExpiredUserDetails && reportData.Users.PasswordExpiredUserDetails.length > 0) {
        csvContent += 'USERS WITH EXPIRED PASSWORDS\r\n';
        const expiredHeaders = Object.keys(reportData.Users.PasswordExpiredUserDetails[0]);
        csvContent += expiredHeaders.join(',') + '\r\n';
        
        reportData.Users.PasswordExpiredUserDetails.forEach(user => {
            csvContent += expiredHeaders.map(header => escapeCSV(user[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }

    // Add Locked Out Users
    if (reportData.Users.LockedOutUserDetails && reportData.Users.LockedOutUserDetails.length > 0) {
        csvContent += 'LOCKED OUT USERS\r\n';
        const lockedOutHeaders = Object.keys(reportData.Users.LockedOutUserDetails[0]);
        csvContent += lockedOutHeaders.join(',') + '\r\n';
        
        reportData.Users.LockedOutUserDetails.forEach(user => {
            csvContent += lockedOutHeaders.map(header => escapeCSV(user[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Group Statistics
    csvContent += 'GROUP STATISTICS\r\n';
    csvContent += 'Property,Value\r\n';
    csvContent += 'Total Groups,' + escapeCSV(reportData.Groups.TotalGroups) + '\r\n';
    csvContent += 'Security Groups,' + escapeCSV(reportData.Groups.SecurityGroups) + '\r\n';
    csvContent += 'Distribution Groups,' + escapeCSV(reportData.Groups.DistributionGroups) + '\r\n';
    csvContent += 'Universal Groups,' + escapeCSV(reportData.Groups.UniversalGroups) + '\r\n';
    csvContent += 'Global Groups,' + escapeCSV(reportData.Groups.GlobalGroups) + '\r\n';
    csvContent += 'Domain Local Groups,' + escapeCSV(reportData.Groups.DomainLocalGroups) + '\r\n\r\n';
    
    // Top Groups by Member Count
    if (reportData.Groups.TopGroupsByMemberCount && reportData.Groups.TopGroupsByMemberCount.length > 0) {
        csvContent += 'TOP GROUPS BY MEMBER COUNT\r\n';
        const groupHeaders = Object.keys(reportData.Groups.TopGroupsByMemberCount[0]);
        csvContent += groupHeaders.join(',') + '\r\n';
        
        reportData.Groups.TopGroupsByMemberCount.forEach(group => {
            csvContent += groupHeaders.map(header => escapeCSV(group[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Computer Statistics
    csvContent += 'COMPUTER STATISTICS\r\n';
    csvContent += 'Property,Value\r\n';
    csvContent += 'Total Computers,' + escapeCSV(reportData.Computers.TotalComputers) + '\r\n';
    csvContent += 'Enabled Computers,' + escapeCSV(reportData.Computers.EnabledComputers) + '\r\n';
    csvContent += 'Disabled Computers,' + escapeCSV(reportData.Computers.DisabledComputers) + '\r\n';
    csvContent += 'New Computers (30 days),' + escapeCSV(reportData.Computers.NewComputers) + '\r\n';
    csvContent += 'Inactive Computers (90+ days),' + escapeCSV(reportData.Computers.InactiveComputers) + '\r\n\r\n';
    
    // NEW: Add Detailed Computer Lists
    // Enabled Computers
    if (reportData.Computers.EnabledComputersList && reportData.Computers.EnabledComputersList.length > 0) {
        csvContent += 'ENABLED COMPUTERS\r\n';
        const computerHeaders = Object.keys(reportData.Computers.EnabledComputersList[0]);
        csvContent += computerHeaders.join(',') + '\r\n';
        
        reportData.Computers.EnabledComputersList.forEach(computer => {
            csvContent += computerHeaders.map(header => escapeCSV(computer[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Disabled Computers
    if (reportData.Computers.DisabledComputersList && reportData.Computers.DisabledComputersList.length > 0) {
        csvContent += 'DISABLED COMPUTERS\r\n';
        const computerHeaders = Object.keys(reportData.Computers.DisabledComputersList[0]);
        csvContent += computerHeaders.join(',') + '\r\n';
        
        reportData.Computers.DisabledComputersList.forEach(computer => {
            csvContent += computerHeaders.map(header => escapeCSV(computer[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // New Computers (last 30 days)
    if (reportData.Computers.NewComputersList && reportData.Computers.NewComputersList.length > 0) {
        csvContent += 'NEW COMPUTERS (LAST 30 DAYS)\r\n';
        const computerHeaders = Object.keys(reportData.Computers.NewComputersList[0]);
        csvContent += computerHeaders.join(',') + '\r\n';
        
        reportData.Computers.NewComputersList.forEach(computer => {
            csvContent += computerHeaders.map(header => escapeCSV(computer[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Inactive Computers (90+ days)
    if (reportData.Computers.InactiveComputersList && reportData.Computers.InactiveComputersList.length > 0) {
        csvContent += 'INACTIVE COMPUTERS (90+ DAYS)\r\n';
        const computerHeaders = Object.keys(reportData.Computers.InactiveComputersList[0]);
        csvContent += computerHeaders.join(',') + '\r\n';
        
        reportData.Computers.InactiveComputersList.forEach(computer => {
            csvContent += computerHeaders.map(header => escapeCSV(computer[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Computers by OS
    if (reportData.Computers.ComputersByOS && reportData.Computers.ComputersByOS.length > 0) {
        csvContent += 'COMPUTERS BY OPERATING SYSTEM\r\n';
        const osHeaders = Object.keys(reportData.Computers.ComputersByOS[0]);
        csvContent += osHeaders.join(',') + '\r\n';
        
        reportData.Computers.ComputersByOS.forEach(os => {
            csvContent += osHeaders.map(header => escapeCSV(os[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }

    // NEW: Domain Controller Replication Status
    if (reportData.DCDiagReplication && reportData.DCDiagReplication.ReplicationPartners && 
    reportData.DCDiagReplication.ReplicationPartners.length > 0) {
        csvContent += 'DOMAIN CONTROLLER REPLICATION STATUS\r\n';
        csvContent += 'Partner DC,Last Success,Last Attempt,Status,Error Details\r\n';
    
    reportData.DCDiagReplication.ReplicationPartners.forEach(partner => {
        csvContent += escapeCSV(partner.PartnerName) + ',';
        csvContent += escapeCSV(partner.LastSuccess) + ',';
        csvContent += escapeCSV(partner.LastAttempt) + ',';
        csvContent += escapeCSV(partner.Status) + ',';
        csvContent += escapeCSV(partner.ErrorMessage) + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Domain Controllers
    if (reportData.DomainControllers && reportData.DomainControllers.length > 0) {
        csvContent += 'DOMAIN CONTROLLERS\r\n';
        const dcHeaders = Object.keys(reportData.DomainControllers[0]);
        csvContent += dcHeaders.join(',') + '\r\n';
        
        reportData.DomainControllers.forEach(dc => {
            csvContent += dcHeaders.map(header => escapeCSV(dc[header])).join(',') + '\r\n';
        });
        csvContent += '\r\n';
    }
    
    // Continue with the rest of your existing export code...
    
    // Create a Blob and download link
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    // Create a link and trigger the download
    const link = document.createElement('a');
    const domainName = reportData.Domain.DNSRoot || 'Unknown';
    const serverName = reportData.CurrentServerName || 'Unknown';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
    link.setAttribute('href', url);
    link.setAttribute('download', serverName + '.' + domainName + '.report_' + timestamp + '.csv');
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

</script>
</head>
<body>
    <div class="container">
<div class="header">
    <h1>CURRENT DOMAIN CONTROLLER ANALYSIS REPORT FOR:<span class="highlight-text"> $($Data.CurrentServerName).$($Data.Domain.DNSRoot)</span></h1>
<p class="info-line">
    <span class="version-badge">AD COLLECTOR LIGHT V3.1</span>
    <span class="timestamp-badge">Generated on: $($Data.ReportGenerated)</span>
</p>
</div>
"@

$domainInfoSection = @"
        <div class="card">
            <div class="card-header">Domain Information</div>
            <div class="card-body">
                <table>
                    <tr>
                        <td><strong>Domain Name:</strong></td>
                        <td>$($Data.Domain.Name)</td>
                    </tr>
                    <tr>
                        <td><strong>DNS Root:</strong></td>
                        <td>$($Data.Domain.DNSRoot)</td>
                    </tr>
                    <tr>
                        <td><strong>NetBIOS Name:</strong></td>
                        <td>$($Data.Domain.NetBIOSName)</td>
                    </tr>
                    <tr>
                        <td><strong>Domain functional level mode:</strong></td>
                        <td>$($Data.Domain.DomainMode)</td>
                    </tr>
                    <tr>
                        <td><strong>Forest:</strong></td>
                        <td>$($Data.Domain.Forest)</td>
                    </tr>
                    <tr>
                        <td colspan="2" style="padding-top: 15px;"><strong>FSMO Roles</strong></td>
                    </tr>
                    <tr>
                        <td><strong>Schema Master:</strong></td>
                        <td>$($Data.Domain.SchemaMaster)</td>
                    </tr>
                    <tr>
                        <td><strong>Domain Naming Master:</strong></td>
                        <td>$($Data.Domain.DomainNamingMaster)</td>
                    </tr>
                    <tr>
                        <td><strong>PDC Emulator:</strong></td>
                        <td>$($Data.Domain.PDCEmulator)</td>
                    </tr>
                    <tr>
                        <td><strong>RID Master:</strong></td>
                        <td>$($Data.Domain.RIDMaster)</td>
                    </tr>
                    <tr>
                        <td><strong>Infrastructure Master:</strong></td>
                        <td>$($Data.Domain.InfrastructureMaster)</td>
                    </tr>
                    <tr>
                        <td style="padding-top: 15px;"><strong>Domain Controllers:</strong></td>
                        <td style="padding-top: 15px;">$($Data.Domain.DomainControllers)</td>
                    </tr>
                </table>
            </div>
        </div>
"@

$overviewSection = @"
        <div class="card">
            <div class="card-header">Overview (AD objects)</div>
            <div class="card-body">
                <!-- Simple stats at the top -->
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.TotalUsers)</div>
                        <div class="stat-label">Total Users</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Groups.TotalGroups)</div>
                        <div class="stat-label">Total Groups</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Computers.TotalComputers)</div>
                        <div class="stat-label">Total Computers</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.OrganizationalUnits.TotalOUs)</div>
                        <div class="stat-label">Total OUs</div>
                    </div>
                </div>
                
                <!-- Add vertical bar chart (histogram) -->
                <div class="chart-container" style="height: 400px; margin-top: 30px;">
                    <canvas id="overviewHistogram"></canvas>
                </div>
                
                <script>
                    // Overview Histogram
                    var overviewCtx = document.getElementById('overviewHistogram').getContext('2d');
                    var overviewHistogram = new Chart(overviewCtx, {
                        type: 'bar',
                        data: {
                            labels: ['Users', 'Groups', 'Computers', 'OUs', 'Sites', 'GPOs'],
                            datasets: [{
                                label: 'Active Directory Objects',
                                data: [
                                    $($Data.Users.TotalUsers), 
                                    $($Data.Groups.TotalGroups), 
                                    $($Data.Computers.TotalComputers),
                                    $($Data.OrganizationalUnits.TotalOUs),
                                    $($Data.Sites.TotalSites),
                                    $($Data.GroupPolicies.TotalGPOs)
                                ],
                                backgroundColor: [
                                    'rgba(54, 162, 235, 0.8)',  // Users - Blue 
                                    'rgba(255, 99, 132, 0.8)',  // Groups - Red
                                    'rgba(75, 192, 192, 0.8)',  // Computers - Teal
                                    'rgba(255, 206, 86, 0.8)',  // OUs - Yellow
                                    'rgba(153, 102, 255, 0.8)', // Sites - Purple
                                    'rgba(255, 159, 64, 0.8)'   // GPOs - Orange
                                ],
                                borderColor: [
                                    'rgba(54, 162, 235, 1)',
                                    'rgba(255, 99, 132, 1)',
                                    'rgba(75, 192, 192, 1)',
                                    'rgba(255, 206, 86, 1)',
                                    'rgba(153, 102, 255, 1)',
                                    'rgba(255, 159, 64, 1)'
                                ],
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    display: false  // Hide legend since the colors are self-explanatory
                                },
                                title: {
                                    display: true,
                                    text: 'Distribution of Active Directory Objects',
                                    font: {
                                        size: 16
                                    }
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            return context.dataset.label + ': ' + context.raw;
                                        }
                                    }
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: 'Count'
                                    }
                                },
                                x: {
                                    title: {
                                        display: true,
                                        text: 'Object Type'
                                    }
                                }
                            }
                        }
                    });
                </script>
            </div>
        </div>
"@

$usersSection = @"
        <div class="card">
            <div class="card-header">Users</div>
            <div class="card-body">
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.EnabledUsers)</div>
                        <div class="stat-label">Enabled Users</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.DisabledUsers)</div>
                        <div class="stat-label">Disabled Users</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.HiddenUsers)</div>
                        <div class="stat-label">Hidden Users</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.NewUsers)</div>
                        <div class="stat-label">New Users (30 days)</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.InactiveUsers)</div>
                        <div class="stat-label">Inactive Users (90+ days)</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.NeverLoggedInUsers)</div>
                        <div class="stat-label">Never Logged In</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Users.LockedOutUsers)</div>
                        <div class="stat-label">Locked Out</div>
                    </div>
                </div>
                
                <!-- User status distribution pie chart only -->
                <div class="chart-container">
                    <canvas id="userStatusChart"></canvas>
                </div>
                
                <script>
                    // User Status Distribution chart
                    var statusCtx = document.getElementById('userStatusChart').getContext('2d');
                    var userStatusChart = new Chart(statusCtx, {
                        type: 'pie',
                        data: {
                            labels: [
                                'Enabled Active Users', 
                                'Inactive Users (90+ days)', 
                                'Never Logged In', 
                                'Disabled Users',
                                'Hidden/System Users',
                                'Password Expired Users',
                                'Locked Out Users'
                            ],
                            datasets: [{
                                data: [
                                    $($Data.Users.EnabledUsers - $Data.Users.InactiveUsers - $Data.Users.NeverLoggedInUsers - $Data.Users.PasswordExpiredUsers - $Data.Users.LockedOutUsers), 
                                    $($Data.Users.InactiveUsers), 
                                    $($Data.Users.NeverLoggedInUsers),
                                    $($Data.Users.DisabledUsers),
                                    $($Data.Users.HiddenUsers),
                                    $($Data.Users.PasswordExpiredUsers),
                                    $($Data.Users.LockedOutUsers)
                                ],
                                backgroundColor: [
                                    'rgba(54, 162, 235, 0.7)',  // Enabled Active - Blue
                                    'rgba(255, 206, 86, 0.7)',  // Inactive - Yellow
                                    'rgba(255, 159, 64, 0.7)',  // Never Logged In - Orange
                                    'rgba(255, 99, 132, 0.7)',  // Disabled - Red
                                    'rgba(128, 128, 128, 0.7)', // Hidden - Gray
                                    'rgba(75, 192, 192, 0.7)',  // Password Expired - Teal
                                    'rgba(153, 102, 255, 0.7)'  // Locked Out - Purple
                                ],
                                borderColor: [
                                    'rgba(54, 162, 235, 1)',
                                    'rgba(255, 206, 86, 1)',
                                    'rgba(255, 159, 64, 1)',
                                    'rgba(255, 99, 132, 1)',
                                    'rgba(128, 128, 128, 1)',
                                    'rgba(75, 192, 192, 1)',
                                    'rgba(153, 102, 255, 1)'
                                ],
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'User Status Distribution',
                                    font: {
                                        size: 16
                                    }
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            let label = context.label || '';
                                            let value = context.raw || 0;
                                            let total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            let percentage = Math.round((value / total) * 100);
                                            return label + ': ' + value + ' (' + percentage + '%)';
                                        }
                                    }
                                },
                                legend: {
                                    position: 'right'
                                }
                            }
                        }
                    });
                </script>
            </div>
        </div>
"@

$groupsSection = @"
        <div class="card">
            <div class="card-header">Groups</div>
            <div class="card-body">
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Groups.SecurityGroups)</div>
                        <div class="stat-label">Security Groups</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Groups.DistributionGroups)</div>
                        <div class="stat-label">Distribution Groups</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Groups.UniversalGroups)</div>
                        <div class="stat-label">Universal Groups</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Groups.GlobalGroups)</div>
                        <div class="stat-label">Global Groups</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Groups.DomainLocalGroups)</div>
                        <div class="stat-label">Domain Local Groups</div>
                    </div>
                </div>
                
                <div class="chart-container">
                    <canvas id="groupTypesChart"></canvas>
                </div>
                
                <script>
                    // Group Types chart - showing group scopes instead of categories
                    var groupCtx = document.getElementById('groupTypesChart').getContext('2d');
                    var groupTypesChart = new Chart(groupCtx, {
                        type: 'pie',
                        data: {
                            labels: ['Universal Groups', 'Global Groups', 'Domain Local Groups'],
                            datasets: [{
                                data: [$($Data.Groups.UniversalGroups), $($Data.Groups.GlobalGroups), $($Data.Groups.DomainLocalGroups)],
                                backgroundColor: [
                                    'rgba(54, 162, 235, 0.7)',
                                    'rgba(255, 206, 86, 0.7)',
                                    'rgba(75, 192, 192, 0.7)'
                                ],
                                borderColor: [
                                    'rgba(54, 162, 235, 1)',
                                    'rgba(255, 206, 86, 1)',
                                    'rgba(75, 192, 192, 1)'
                                ],
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            let label = context.label || '';
                                            let value = context.raw || 0;
                                            let total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            let percentage = Math.round((value / total) * 100);
                                            return label + ': ' + value + ' (' + percentage + '%)';
                                        }
                                    }
                                },
                                legend: {
                                    position: 'right'
                                }
                            }
                        }
                    });
                </script>
                
                <h3>Top Groups by Member Count</h3>
                <table>
                    <tr>
                        <th>Group Name</th>
                        <th>Member Count</th>
                    </tr>
                    $(
                        $Data.Groups.TopGroupsByMemberCount | ForEach-Object {
                            "<tr><td>$($_.Name)</td><td>$($_.MemberCount)</td></tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

    $computersSection = @"
        <div class="card">
            <div class="card-header">Computers and OS distribution</div>
            <div class="card-body">
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Computers.EnabledComputers)</div>
                        <div class="stat-label">Enabled Computers</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Computers.DisabledComputers)</div>
                        <div class="stat-label">Disabled Computers</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Computers.NewComputers)</div>
                        <div class="stat-label">New Computers (30 days)</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Computers.InactiveComputers)</div>
                        <div class="stat-label">Inactive Computers (90+ days)</div>
                    </div>
                </div>
                
                <div class="chart-container">
                    <canvas id="osChart"></canvas>
                </div>
                
                <script>
                    // Computers by OS chart
                    var osCtx = document.getElementById('osChart').getContext('2d');
                    var osChart = new Chart(osCtx, {
                        type: 'pie',
                        data: {
                            labels: [$(($Data.Computers.ComputersByOS | ForEach-Object { "'$($_.OperatingSystem)'" }) -join ', ')],
                            datasets: [{
                                data: [$(($Data.Computers.ComputersByOS | ForEach-Object { $_.Count }) -join ', ')],
                                backgroundColor: [
                                    'rgba(255, 99, 132, 0.7)',
                                    'rgba(54, 162, 235, 0.7)',
                                    'rgba(255, 206, 86, 0.7)',
                                    'rgba(75, 192, 192, 0.7)',
                                    'rgba(153, 102, 255, 0.7)',
                                    'rgba(255, 159, 64, 0.7)',
                                    'rgba(199, 199, 199, 0.7)',
                                    'rgba(83, 102, 255, 0.7)',
                                    'rgba(40, 159, 64, 0.7)',
                                    'rgba(210, 199, 199, 0.7)'
                                ],
                                borderColor: [
                                    'rgba(255, 99, 132, 1)',
                                    'rgba(54, 162, 235, 1)',
                                    'rgba(255, 206, 86, 1)',
                                    'rgba(75, 192, 192, 1)',
                                    'rgba(153, 102, 255, 1)',
                                    'rgba(255, 159, 64, 1)',
                                    'rgba(199, 199, 199, 1)',
                                    'rgba(83, 102, 255, 1)',
                                    'rgba(40, 159, 64, 1)',
                                    'rgba(210, 199, 199, 1)'
                                ],
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false
                        }
                    });
                </script>
            </div>
        </div>
"@


$domainControllersSection = @"
        <div class="card">
            <div class="card-header">Domain Controllers</div>
            <div class="card-body">
                <table>
                    <tr>
                        <th>Name</th>
                        <th>IP Address</th>
                        <th>Site</th>
                        <th>Operating System</th>
                        <th>Global Catalog</th>
                        <th>Read-Only</th>
                    </tr>
                    $(
                        $Data.DomainControllers | ForEach-Object {
                            "<tr>
                                <td>$($_.Name)</td>
                                <td>$($_.IPv4Address)</td>
                                <td>$($_.Site)</td>
                                <td>$($_.OperatingSystem)</td>
                                <td>$($_.IsGlobalCatalog)</td>
                                <td>$($_.IsReadOnly)</td>
                            </tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

$currentServerSection = @"
        <div class="card">
            <div class="card-header">Current Domain Controller ($($Data.CurrentServerName))</div>
            <div class="card-body">
                <h3>Disk Space Information</h3>
                <table>
                    <tr>
                        <th>Drive</th>
                        <th>Size (GB)</th>
                        <th>Free Space (GB)</th>
                        <th>Free Space (%)</th>
                        <th>Volume Name</th>
                    </tr>
                    $(
                        if ($Data.CurrentServerDiskSpace -and $Data.CurrentServerDiskSpace.Count -gt 0) {
                            $Data.CurrentServerDiskSpace | ForEach-Object {
                                $percentFreeClass = if ($_.PercentFree -lt 10) { "text-danger" } elseif ($_.PercentFree -lt 20) { "text-warning" } else { "text-success" }
                                "<tr>
                                    <td>$($_.DeviceID)</td>
                                    <td>$($_.'Size(GB)')</td>
                                    <td>$($_.'FreeSpace(GB)')</td>
                                    <td class='$percentFreeClass'>$($_.PercentFree)%</td>
                                    <td>$($_.VolumeName)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='5' style='text-align: center;'>No disk space data available</td></tr>"
                        }
                    )
                </table>
                
                <h3 style="margin-top: 20px;">Domain Controller Services</h3>
                <table>
                    <tr>
                        <th>Service Name</th>
                        <th>Service ID</th>
                        <th>Status</th>
                        <th>Start Type</th>
                    </tr>
                    $(
                        if ($Data.DomainControllerServices -and $Data.DomainControllerServices.Count -gt 0) {
                            $Data.DomainControllerServices | ForEach-Object {
                                $statusClass = if ($_.Status -eq "Running") { "text-success" } else { "text-danger" }
                                "<tr>
                                    <td>$($_.Name)</td>
                                    <td>$($_.ServiceName)</td>
                                    <td class='$statusClass'>$($_.Status)</td>
                                    <td>$($_.StartType)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='4' style='text-align: center;'>No service data available</td></tr>"
                        }
                    )
                </table>
                
                <h3 style="margin-top: 20px;">Active Directory Database</h3>
                <table>
                    <tr>
                        <th>Database Path</th>
                        <th>Database Size</th>
                        <th>Log Files Path</th>
                        <th>Log Files Size</th>
                        <th>Last Backup Time</th>
                        <th>Backup Status</th>
                    </tr>
                    $(
                        if ($Data.ADDatabaseInfo) {
                            $dbSizeText = if ($Data.ADDatabaseInfo.DatabaseSize -eq 0) { "Unknown" } else { "$($Data.ADDatabaseInfo.DatabaseSize) $($Data.ADDatabaseInfo.DatabaseSizeUnit)" }
                            $logSizeText = if ($Data.ADDatabaseInfo.LogSize -eq 0) { "Unknown" } else { "$($Data.ADDatabaseInfo.LogSize) $($Data.ADDatabaseInfo.LogSizeUnit)" }
                            $backupClass = if ($Data.ADDatabaseInfo.IsBackedUp) { "text-success" } else { "text-danger" }
                            $backupText = if ($Data.ADDatabaseInfo.IsBackedUp) { "Backed Up" } else { "Not Backed Up" }
                            
                            "<tr>
                                <td>$($Data.ADDatabaseInfo.DatabasePath)</td>
                                <td>$dbSizeText</td>
                                <td>$($Data.ADDatabaseInfo.LogPath)</td>
                                <td>$logSizeText</td>
                                <td>$($Data.ADDatabaseInfo.LastBackupTime)</td>
                                <td class='$backupClass'>$backupText</td>
                            </tr>"
                        } else {
                            "<tr>
                                <td>Unknown</td>
                                <td>0 GB</td>
                                <td>Unknown</td>
                                <td>0 MB</td>
                                <td>Never</td>
                                <td class='text-danger'>Not Backed Up</td>
                            </tr>"
                        }
                    )
                </table>

                <h3 style="margin-top: 20px;">Recent Windows Updates</h3>
                <table>
                    <tr>
                        <th>Update ID</th>
                        <th>Title</th>
                        <th>Installed On</th>
                        <th>Installed By</th>
                    </tr>
                    $(
                        if ($Data.WindowsUpdateHistory -and $Data.WindowsUpdateHistory.Count -gt 0) {
                            $Data.WindowsUpdateHistory | ForEach-Object {
                                "<tr>
                                    <td>$($_.HotFixID)</td>
                                    <td>$($_.Title)</td>
                                    <td>$($_.InstalledOn)</td>
                                    <td>$($_.InstalledBy)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='4' style='text-align: center;'>No Windows Update history available</td></tr>"
                        }
                    )
                </table>
                
                <h3 style="margin-top: 20px;">Domain Controller Replication Status</h3>
                <table>
                    <tr>
                        <th>Partner DC</th>
                        <th>Last Success</th>
                        <th>Last Attempt</th>
                        <th>Status</th>
                        <th>Error Details</th>
                    </tr>
                    $(
                        if ($Data.DCDiagReplication -and $Data.DCDiagReplication.ReplicationPartners -and $Data.DCDiagReplication.ReplicationPartners.Count -gt 0) {
                            $Data.DCDiagReplication.ReplicationPartners | ForEach-Object {
                                $statusClass = if ($_.Status -eq "Success") { "text-success" } else { "text-danger" }
                                
                                "<tr>
                                    <td>$($_.PartnerName)</td>
                                    <td>$($_.LastSuccess)</td>
                                    <td>$($_.LastAttempt)</td>
                                    <td class='$statusClass'>$($_.Status)</td>
                                    <td>$($_.ErrorMessage)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='5' style='text-align: center;'>No replication data available</td></tr>"
                        }
                    )
                </table>

                $(
                    if ($Data.DCDiagReplication.HasReplicationErrors) {
                        "<div style='margin-top: 15px; padding: 10px; background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; color: #721c24;'>
                            <strong>Warning:</strong> Replication errors detected. Please review the replication status and address any issues.
                        </div>"
                    }
                )
            </div>
        </div>
"@
    $sitesSection = ""
    if ($Data.Sites.TotalSites -gt 0) {
        $sitesSection = @"
        <div class="card">
            <div class="card-header">Sites</div>
            <div class="card-body">
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value">$($Data.Sites.TotalSites)</div>
                        <div class="stat-label">Total Sites</div>
                    </div>
                </div>
                
                <h3>Site Details</h3>
                <table>
                    <tr>
                        <th>Name</th>
                        <th>Links</th>
                        <th>Subnets</th>
                    </tr>
                    $(
                        $Data.Sites.Sites | ForEach-Object {
                            "<tr>
                                <td>$($_.Name)</td>
                                <td>$($_.Links)</td>
                                <td>$($_.Subnets)</td>
                            </tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@
    }


$passwordPolicySection = @"
        <div class="card">
            <div class="card-header">Domain Password Policy</div>
            <div class="card-body">
                <table>
                    <tr>
                        <th>Policy Setting</th>
                        <th>Current Value</th>
                        <th>Status</th>
                        <th>Recommendation</th>
                    </tr>
                    $(
                        $Data.PasswordPolicy | ForEach-Object {
                            $statusClass = if ($_.Status -eq "Good") { "text-success" } else { "text-warning" }
                            "<tr>
                                <td>$($_.Setting)</td>
                                <td>$($_.Value)</td>
                                <td class='$statusClass'>$($_.Status)</td>
                                <td>$($_.Recommendation)</td>
                            </tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

$gpoPoliciesSection = @"
        <div class="card">
            <div class="card-header">Group Policies</div>
            <div class="card-body">
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value">$($Data.GroupPolicies.TotalGPOs)</div>
                        <div class="stat-label">Total GPOs</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-value">$($Data.GroupPolicies.RecentlyModifiedGPOs)</div>
                        <div class="stat-label">Modified in Last 30 Days</div>
                    </div>
                </div>
                
                <h3>Group Policy Objects</h3>
                <table>
                    <tr>
                        <th>Name</th>
                        <th>Created</th>
                        <th>Modified</th>
                        <th>Status</th>
                        <th>Linked OUs</th>
                    </tr>
                    $(
                        if ($Data.GroupPolicies.GPOs -and $Data.GroupPolicies.GPOs.Count -gt 0) {
                            $Data.GroupPolicies.GPOs | ForEach-Object {
                                "<tr>
                                    <td>$($_.Name)</td>
                                    <td>$($_.CreationTime)</td>
                                    <td>$($_.ModificationTime)</td>
                                    <td>$($_.Status)</td>
                                    <td>$($_.LinkedOUs)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='5' style='text-align: center;'>No GPO data available</td></tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

$organizationalUnitsSection = @"
        <div class="card">
            <div class="card-header">Organisational Units</div>
            <div class="card-body">
                <div class="stats-container">
                    <div class="stat-box">
                        <div class="stat-value">$($Data.OrganizationalUnits.TotalOUs)</div>
                        <div class="stat-label">Total OUs</div>
                    </div>
                </div>
                
                <h3>Top OUs by Child Count</h3>
                <div class="chart-container">
                    <canvas id="ouChildCountChart"></canvas>
                </div>
                
                <script>
                    // OU Child Count Pie Chart
                    var ouCtx = document.getElementById('ouChildCountChart').getContext('2d');
                    var ouChildCountChart = new Chart(ouCtx, {
                        type: 'pie',
                        data: {
                            labels: [$(($Data.OrganizationalUnits.TopOUsByChildCount | ForEach-Object { "'$($_.Name)'" }) -join ', ')],
                            datasets: [{
                                data: [$(($Data.OrganizationalUnits.TopOUsByChildCount | ForEach-Object { $_.ChildCount }) -join ', ')],
                                backgroundColor: [
                                    'rgba(54, 162, 235, 0.7)',
                                    'rgba(255, 99, 132, 0.7)',
                                    'rgba(255, 206, 86, 0.7)',
                                    'rgba(75, 192, 192, 0.7)',
                                    'rgba(153, 102, 255, 0.7)',
                                    'rgba(255, 159, 64, 0.7)',
                                    'rgba(199, 199, 199, 0.7)',
                                    'rgba(83, 102, 255, 0.7)',
                                    'rgba(40, 159, 64, 0.7)',
                                    'rgba(210, 199, 199, 0.7)'
                                ],
                                borderColor: [
                                    'rgba(54, 162, 235, 1)',
                                    'rgba(255, 99, 132, 1)',
                                    'rgba(255, 206, 86, 1)',
                                    'rgba(75, 192, 192, 1)',
                                    'rgba(153, 102, 255, 1)',
                                    'rgba(255, 159, 64, 1)',
                                    'rgba(199, 199, 199, 1)',
                                    'rgba(83, 102, 255, 1)',
                                    'rgba(40, 159, 64, 1)',
                                    'rgba(210, 199, 199, 1)'
                                ],
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                title: {
                                    display: true,
                                    text: 'Distribution of Objects in Top OUs',
                                    font: {
                                        size: 16
                                    }
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            let label = context.label || '';
                                            let value = context.raw || 0;
                                            let total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            let percentage = Math.round((value / total) * 100);
                                            return label + ': ' + value + ' objects (' + percentage + '%)';
                                        }
                                    }
                                },
                                legend: {
                                    position: 'right',
                                    labels: {
                                        boxWidth: 15
                                    }
                                }
                            }
                        }
                    });
                </script>
            </div>
        </div>
"@

$domainSecuritySection = @"
        <div class="card">
            <div class="card-header">Domain-level Security Settings</div>
            <div class="card-body">
                <table>
                    <tr>
                        <th>Setting</th>
                        <th>Status</th>
                        <th>Risk Assessment</th>
                        <th>Recommendation</th>
                    </tr>
                    $(
                        if ($Data.SecurityChecks.DomainLevelSettings -and $Data.SecurityChecks.DomainLevelSettings.Count -gt 0) {
                            $Data.SecurityChecks.DomainLevelSettings | ForEach-Object {
                                $colorClass = ""
                                if ($_.RiskAssessment -like "Good*") { $colorClass = "text-success" }
                                elseif ($_.RiskAssessment -like "Medium*") { $colorClass = "text-warning" }
                                elseif ($_.RiskAssessment -like "High*" -or $_.RiskAssessment -like "Critical*") { $colorClass = "text-danger" }

                                "<tr>
                                    <td>$($_.Setting)</td>
                                    <td>$($_.Status)</td>
                                    <td class='$colorClass'>$($_.RiskAssessment)</td>
                                    <td>$($_.Recommendation)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='4' style='text-align: center;'>No domain-level security settings data available</td></tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

$adSecurityFeaturesSection = @"
        <div class="card">
            <div class="card-header">Active Directory Security Features</div>
            <div class="card-body">
                <table>
                    <tr>
                        <th>Feature</th>
                        <th>Status</th>
                        <th>Security Benefit</th>
                        <th>Recommendation</th>
                    </tr>
                    $(
                        if ($Data.SecurityChecks.ADSecurityFeatures -and $Data.SecurityChecks.ADSecurityFeatures.Count -gt 0) {
                            $Data.SecurityChecks.ADSecurityFeatures | ForEach-Object {
                                "<tr>
                                    <td>$($_.Feature)</td>
                                    <td>$($_.Status)</td>
                                    <td>$($_.SecurityBenefit)</td>
                                    <td>$($_.Recommendation)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='4' style='text-align: center;'>No AD security features data available</td></tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

$tlsConfigurationSection = @"
        <div class="card">
            <div class="card-header">TLS Configuration</div>
            <div class="card-body">
                <h3>$($Data.CurrentServerName)</h3>
                <table>
                    <tr>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Risk Assessment</th>
                    </tr>
                    $(
                        if ($Data.SecurityChecks.TLSConfiguration -and $Data.SecurityChecks.TLSConfiguration.Count -gt 0) {
                            $Data.SecurityChecks.TLSConfiguration | ForEach-Object {
                                $colorClass = ""
                                if ($_.RiskAssessment -like "Good*") { $colorClass = "text-success" }
                                elseif ($_.RiskAssessment -like "Medium*") { $colorClass = "text-warning" }
                                elseif ($_.RiskAssessment -like "High*") { $colorClass = "text-warning" }
                                elseif ($_.RiskAssessment -like "Critical*") { $colorClass = "text-danger" }

                                "<tr>
                                    <td>$($_.Protocol)</td>
                                    <td>$($_.Status)</td>
                                    <td class='$colorClass'>$($_.RiskAssessment)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='3' style='text-align: center;'>No TLS configuration data available</td></tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

$securityProtocolSection = @"
        <div class="card">
            <div class="card-header">Security Protocol Settings</div>
            <div class="card-body">
                <h3>$($Data.CurrentServerName)</h3>
                <table>
                    <tr>
                        <th>Protocol</th>
                        <th>Status</th>
                        <th>Risk Assessment</th>
                    </tr>
                    $(
                        if ($Data.SecurityChecks.SecurityProtocolSettings -and $Data.SecurityChecks.SecurityProtocolSettings.Count -gt 0) {
                            $Data.SecurityChecks.SecurityProtocolSettings | ForEach-Object {
                                $colorClass = ""
                                if ($_.RiskAssessment -like "Good*") { $colorClass = "text-success" }
                                elseif ($_.RiskAssessment -like "Medium*") { $colorClass = "text-warning" }
                                elseif ($_.RiskAssessment -like "High*") { $colorClass = "text-danger" }
                                elseif ($_.RiskAssessment -like "Critical*") { $colorClass = "text-danger" }

                                "<tr>
                                    <td>$($_.Protocol)</td>
                                    <td>$($_.Status)</td>
                                    <td class='$colorClass'>$($_.RiskAssessment)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='3' style='text-align: center;'>No security protocol settings data available</td></tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@

$registrySecuritySection = @"
        <div class="card">
            <div class="card-header">Registry Security Settings</div>
            <div class="card-body">
                <h3>$($Data.CurrentServerName)</h3>
                <table>
                    <tr>
                        <th>Setting</th>
                        <th>Status</th>
                        <th>Risk Assessment</th>
                        <th>Expected Value</th>
                        <th>Actual Value</th>
                    </tr>
                    $(
                        if ($Data.SecurityChecks.RegistrySecuritySettings -and $Data.SecurityChecks.RegistrySecuritySettings.Count -gt 0) {
                            $Data.SecurityChecks.RegistrySecuritySettings | ForEach-Object {
                                $colorClass = ""
                                if ($_.RiskAssessment -like "Good*") { $colorClass = "text-success" }
                                elseif ($_.RiskAssessment -like "Medium*") { $colorClass = "text-warning" }
                                elseif ($_.RiskAssessment -like "High*") { $colorClass = "text-danger" }
                                elseif ($_.RiskAssessment -like "Critical*") { $colorClass = "text-danger" }

                                $valueMatch = $_.ExpectedValue -eq $_.ActualValue
                                $valueClass = if ($valueMatch) { "text-success" } else { "text-danger" }

                                "<tr>
                                    <td>$($_.Setting)</td>
                                    <td>$($_.Status)</td>
                                    <td class='$colorClass'>$($_.RiskAssessment)</td>
                                    <td>$($_.ExpectedValue)</td>
                                    <td class='$valueClass'>$($_.ActualValue)</td>
                                </tr>"
                            }
                        } else {
                            "<tr><td colspan='5' style='text-align: center;'>No registry security settings data available</td></tr>"
                        }
                    )
                </table>
            </div>
        </div>
"@


$htmlFooter = @"
        <div class="footer">
            <p>Generated using PowerShell Domain Analysis Script | $(Get-Date -Format "dd-MM-yyyy HH:mm:ss")</p>
        </div>
    </div>
    
    <!-- Buy Me a Coffee button -->
    <a href="https://buymeacoffee.com/michaeldr" target="_blank" class="coffee-button">
        ☕ Buy Me a Coffee
    </a>
    
    <!-- Export button -->
    <button class="export-button" onclick="exportToCsv()">
        💾 Export Data
    </button>
</body>
</html>
"@

    $htmlHeader = $htmlHeader.Replace('REPORT_DATA_PLACEHOLDER', $base64Data)
    
    $htmlReport = $htmlHeader + 
         $domainInfoSection + 
         $passwordPolicySection + 
         $overviewSection + 
         $usersSection + 
         $groupsSection + 
         $computersSection + 
         $domainControllersSection + 
         $currentServerSection +
         $gpoPoliciesSection + 
         $sitesSection + 
         $organizationalUnitsSection +
         $domainSecuritySection +
         $adSecurityFeaturesSection +
         $tlsConfigurationSection +
         $securityProtocolSection +
         $registrySecuritySection +
         $htmlFooter
    
    $htmlReport | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "HTML report generated at $OutputPath"
}


function Add-AlertsSection {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Data
    )
    
    $alerts = @()
    
    if ($Data.Users.InactiveUsers -gt 100) {
        $alerts += @{
            Type = "Warning"
            Message = "There are $($Data.Users.InactiveUsers) users who haven't logged in for 90+ days. Consider cleaning up inactive accounts."
        }
    }
    
    if ($Data.Computers.InactiveComputers -gt 50) {
        $alerts += @{
            Type = "Warning"
            Message = "There are $($Data.Computers.InactiveComputers) computers that haven't connected to the domain for 90+ days."
        }
    }
    
    if ($Data.Users.PasswordExpiredUsers -gt 20) {
        $alerts += @{
            Type = "Warning"
            Message = "$($Data.Users.PasswordExpiredUsers) users have expired passwords. This could pose a security risk."
        }
    }
    
    if ($alerts.Count -gt 0) {
        $alertsHtml = @"
        <div class="card">
            <div class="card-header" style="background-color: #f8d7da; color: #721c24;">Alerts</div>
            <div class="card-body">
                <ul style="padding-left: 20px;">
"@
        
        foreach ($alert in $alerts) {
            $alertsHtml += @"
                    <li style="color: $(if ($alert.Type -eq 'Warning') { '#856404' } else { '#721c24' });">
                        $($alert.Message)
                    </li>
"@
        }
        
        $alertsHtml += @"
                </ul>
            </div>
        </div>
"@
        
        return $alertsHtml
    }
    
    return ""
}

# Main script execution
try {
    if (-not (Initialize-ADEnvironment)) {
        return
    }
    
    $paths = Set-OutputPaths
    $outputDirectory = $paths.OutputDirectory
    $jsonPath = $paths.JsonPath
    $htmlPath = $paths.HtmlPath
    
    Ensure-OutputDirectory -Path $outputDirectory
    
    Write-Host "Collecting domain information..."
    $domainData = Get-DomainAnalysisData
    
    Save-DataAsJson -Data $domainData -OutputPath $jsonPath
    
    
    $alertsSection = Add-AlertsSection -Data $domainData
    
    $originalGenerateHTMLReport = ${function:Generate-HTMLReport}
    
    function Generate-HTMLReport {
        param (
            [Parameter(Mandatory=$true)]
            [PSCustomObject]$Data,
        
            [Parameter(Mandatory=$true)]
            [string]$OutputPath,
        
            [Parameter(Mandatory=$false)]
            [string]$AlertsSection = "",
        
            [Parameter(Mandatory=$false)]
            [bool]$IncludeTrends = $false
        )
        
        & $originalGenerateHTMLReport -Data $Data -OutputPath $OutputPath
        
    & $originalGenerateHTMLReport -Data $Data -OutputPath $OutputPath
    
    if ($AlertsSection) {
        $htmlContent = Get-Content -Path $OutputPath -Raw
        
        $htmlContent = $htmlContent -replace '(<div class="header">.*?</div>)', "`$1`n$AlertsSection"
        
        $htmlContent | Out-File -FilePath $OutputPath -Encoding utf8
        }
    }
    
    Write-Host "Generating HTML report..."
    Generate-HTMLReport -Data $domainData -OutputPath $htmlPath -AlertsSection $alertsSection
    
    Write-Host "Domain analysis completed successfully!" -ForegroundColor Green
    Write-Host "JSON data: $jsonPath" -ForegroundColor Cyan
    Write-Host "HTML report: $htmlPath" -ForegroundColor Cyan
    
    Write-Host "`nOutput locations:"
    Write-Host "- Directory: $outputDirectory"
    Write-Host "- JSON: $jsonPath"
    Write-Host "- HTML: $htmlPath"

    Start-Process $htmlPath
        } catch {
    Write-Host "" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "ERROR: An unexpected error occurred during script execution:" -ForegroundColor Red
    Write-Host $_ -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "For troubleshooting, please check the error details above." -ForegroundColor Red
    Write-Host "" -ForegroundColor Red
}
