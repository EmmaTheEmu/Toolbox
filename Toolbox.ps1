# Selection screen
function main {
    $selection = 0
    Write-Host "Select what function you wish to use:"
    Write-Host "1. Network"
    Write-Host "2. Apps"
    Write-Host "3. Performance"
    Write-Host "4. Checks info"
    $selection = Read-Host
    Switch ($selection) {
        0: {
            Write-Host "Please select an option."
            main
        }
        1 { network_select }
        2 { application_select }
        3 { performance_select }
        4 { check_select }
    }
    main
}

# Network functions

function network_select {
    Clear-Host
    Write-Host "0. Back to selection"
    Write-Host "1. Network information"
    Write-Host "2. Reset DNS"
    $selection = Read-Host
    switch ($selection) {
        0 { main }
        1 { ip_info }
        2 { reset_dns }
    }
    main
}

function ip_info {
    Get-NetIPConfiguration
    Get-NetAdapter | format-table
    netsh wlan show wlanreport
}

function reset_dns {
    # Added exception for VPNs to avoid resetting the wrong one.
    $adapters = get-netadapter | where-object { $_.status -eq "Up" -and (($_.ifName -notlike "*VPN*")) } 
    Set-DnsClientServerAddress -ResetServerAddresses -InterfaceIndex $adapters.ifIndex
    Write-Host "DNS of $($adapters.interfacedescription) has been reset."
}

# Apps
function application_select {
    Clear-Host
    Write-Host "0. Back to selection"
    Write-Host "1. Install applications"
    Write-Host "2. List all installed applications."
    $selection = Read-Host
    switch ($selection) {
        0 { main }
        1 { install_application }
        2 { app_list }
    }
    main
}

function install_application {
    try {
        Invoke-RestMethod "https://raw.githubusercontent.com/EmmaTheEmu/EasierWinget/main/WingetCLI.ps1" | Invoke-Expression
        
    }
    catch {
        Invoke-RestMethod "https://raw.githubusercontent.com/EmmaTheEmu/EasierWinget/main/WingetCLI.ps1" -UseBasicParsing | Invoke-Expression
    }
    finally {
        write-host "Cannot run Winget."
    }
}

function app_list {
    $32bit = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $64bit = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $total = $32bit + $64bit
    $total
}

# Performance

function performance_select {
    Write-Host "0. Back to selection"
    Write-Host "1. Performance analyzer"
    Write-Host "2. WU Installer"
    Write-Host "3. Export System and Application event logs"
    Write-Host "4. Install Lenovo Vantage recommended updates"
    $selection = Read-Host

    switch ($selection) {
        0 { main }
        1 { performance_analyzer }
        2 { install_wu }
        3 { event_logs }
        4 { lenovo_update }
    }
    main
}

function performance_analyzer {
    Clear-Host
    Write-Host "Running General profile test for 60s."
    wpr -start GeneralProfile
    Start-Sleep 60
    Write-Host "Saving data to c:\windows\temp\perf.etl"
    wpr -stop "c:\windows\temp\perf.etl"
    Write-Host "Done!"
}

function install_wu {
install-module -Name PSWindowsUpdate -force
    import-module PSWindowsUpdate
    Write-Host "Update list: `n"
    Get-WindowsUpdate
    install-windowsupdate
}

function event_logs {
    Clear-Host
    if ((Test-Path -path "c:\windows\temp\eventlogs") -is $False) {
        New-Item -ItemType Directory -path "C:\Windows\Temp\Eventlogs"
    }
    wevtutil epl System C:\windows\temp\eventlogs\system_logs.evtx
    wevtutil epl Application C:\windows\temp\eventlogs\application_logs.evtx
    Write-Host "Event logs have been exported to c:\windows\temp\eventlogs"
}

function lenovo_update{
    # https://jantari.github.io/LSUClient-docs/docs/topics/best-practices/
    Install-Module -Name LSUClient -Force
    Import-Module LSUClient
    Get-LSUpdate | Install-LSUpdate | format-table -Property Title, Type, Success
}

# Checks info

function check_select {
    Clear-Host
    Write-Host "0. Back to selection"
    Write-Host "1. Failed logins"
    Write-Host "2. Antivirus list"
    $selection = Read-Host
    switch ($selection) {
        0 { main }
        1 { failed_logins }
        2 { Get-AntiVirusProduct }
    }
    main
}

function failed_logins {
    $shareprinters = 0
    Clear-Host
    Write-Host "Shared folders:"
    Get-CimInstance -ClassName Win32_Share

    $Printers = Get-Printer
    foreach ($printer in $printers) {
        if ($($printer.Shared) -eq $True) {
            $shareprinters++
        }
    }
    Write-Host "There are: $shareprinters currently shared printers"
    if ($shareprinters -ne 0) {
        $printers | Where-Object { $_.Shared -eq $True }
    }

    Write-Host "Currently active firewall rules: "
    Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Format-Table -Property Name, DisplayName, Protocol, LocalPort, Enabled, Direction, Action | Where-Object { $_.Enabled -eq $true }
}

function Get-AntiVirusProduct {
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('name')]
        $computername = $env:computername


    )
    $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $computername

    $ret = @()
    foreach ($AntiVirusProduct in $AntiVirusProducts) {
        #Switch to determine the status of antivirus definitions and real-time protection.
        #The values in this switch-statement are retrieved from the following website: http://community.kaseya.com/resources/m/knowexch/1020.aspx
        switch ($AntiVirusProduct.productState) {
            "262144" { $defstatus = "Up to date" ; $rtstatus = "Disabled" }
            "262160" { $defstatus = "Out of date" ; $rtstatus = "Disabled" }
            "266240" { $defstatus = "Up to date" ; $rtstatus = "Enabled" }
            "266256" { $defstatus = "Out of date" ; $rtstatus = "Enabled" }
            "393216" { $defstatus = "Up to date" ; $rtstatus = "Disabled" }
            "393232" { $defstatus = "Out of date" ; $rtstatus = "Disabled" }
            "393488" { $defstatus = "Out of date" ; $rtstatus = "Disabled" }
            "397312" { $defstatus = "Up to date" ; $rtstatus = "Enabled" }
            "397328" { $defstatus = "Out of date" ; $rtstatus = "Enabled" }
            "397584" { $defstatus = "Out of date" ; $rtstatus = "Enabled" }
            default { $defstatus = "Unknown" ; $rtstatus = "Unknown" }
        }

        #Create hash-table for each computer
        $ht = @{}
        $ht.Computername = $computername
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
        $ht.'Definition Status' = $defstatus
        $ht.'Real-time Protection Status' = $rtstatus


        #Create a new object for each computer
        $ret += New-Object -TypeName PSObject -Property $ht 
    }
    Return $ret
} 



main