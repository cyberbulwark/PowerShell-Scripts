#requires -Version 5.1
#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Scans enabled Windows Server computers in Active Directory and creates a
    searchable OS and activation/license inventory report.

.DESCRIPTION
    Reads operating-system, hardware, registry and Windows Software Protection
    Platform information from each server by using PowerShell remoting.

    The report identifies activation state and the installed key channel when
    Windows exposes it (KMS, MAK, Retail, OEM, AVMA or Evaluation). It records
    only the partial product key. It does not retrieve or disclose complete
    product keys.

    Activation is not proof of license entitlement. Compare the results with
    Microsoft agreements, subscriptions, purchase records and assigned rights.

.EXAMPLE
    .\AD-Windows-Server-OS-License-Inventory.ps1

.EXAMPLE
    .\AD-Windows-Server-OS-License-Inventory.ps1 -SearchBase "OU=Servers,DC=corp,DC=root,DC=heywood,DC=org"

.EXAMPLE
    .\AD-Windows-Server-OS-License-Inventory.ps1 -ComputerName SERVER01,SERVER02

.EXAMPLE
    .\AD-Windows-Server-OS-License-Inventory.ps1 -OutputFormat HTML,CSV
#>

[CmdletBinding()]
param(
    [string]$SearchBase,

    [string[]]$ComputerName,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 24,

    [ValidateSet('All','HTML','CSV','JSON')]
    [string[]]$OutputFormat = @('HTML','CSV'),

    [string]$OutputFolder = (Join-Path $env:SystemDrive ("Temp\Windows-Server-License-Inventory-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'

function Convert-LicenseStatus {
    param([AllowNull()][object]$Status)

    switch ([int]$Status) {
        0 { 'Unlicensed' }
        1 { 'Licensed' }
        2 { 'Out-of-box grace period' }
        3 { 'Out-of-tolerance grace period' }
        4 { 'Non-genuine grace period' }
        5 { 'Notification mode' }
        6 { 'Extended grace period' }
        default { 'Unknown' }
    }
}

function Get-LicenseChannel {
    param(
        [AllowNull()][string]$ProductKeyChannel,
        [AllowNull()][string]$Description
    )

    $source = "$ProductKeyChannel $Description"
    switch -Regex ($source) {
        'VOLUME_KMSCLIENT|KMSCLIENT' { return 'Volume - KMS client' }
        'VOLUME_MAK|MAK'             { return 'Volume - MAK' }
        'VOLUME_KMS|KMS host'        { return 'Volume - KMS host' }
        'OEM_DM|OEM'                 { return 'OEM' }
        'RETAIL'                     { return 'Retail' }
        'AVMA'                       { return 'Automatic Virtual Machine Activation (AVMA)' }
        'TIMEBASED_EVAL|EVAL'        { return 'Evaluation' }
        default {
            if ([string]::IsNullOrWhiteSpace($ProductKeyChannel)) { return 'Unknown/not exposed' }
            return $ProductKeyChannel
        }
    }
}

Write-Host 'Building the Active Directory Windows Server target list...' -ForegroundColor Cyan

if ($ComputerName) {
    $targets = @($ComputerName | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    $adLookup = @{}
}
else {
    $adParameters = @{
        Filter     = 'Enabled -eq $true -and OperatingSystem -like "*Windows Server*"'
        Properties = @('DNSHostName','OperatingSystem','OperatingSystemVersion','LastLogonDate','Created','IPv4Address')
    }
    if ($SearchBase) { $adParameters.SearchBase = $SearchBase }

    $adComputers = @(Get-ADComputer @adParameters)
    $targets = @($adComputers |
        ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } } |
        Sort-Object -Unique)
    $adLookup = @{}
    foreach ($computer in $adComputers) {
        $key = if ($computer.DNSHostName) { $computer.DNSHostName.ToLowerInvariant() } else { $computer.Name.ToLowerInvariant() }
        $adLookup[$key] = $computer
        $adLookup[$computer.Name.ToLowerInvariant()] = $computer
    }
}

if ($targets.Count -eq 0) {
    throw 'No enabled Windows Server computers were found in the specified AD scope.'
}

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
Write-Host ("Scanning {0} server(s) with PowerShell remoting..." -f $targets.Count) -ForegroundColor Cyan

$remoteCollector = {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $processors = @(Get-CimInstance -ClassName Win32_Processor)

    $currentVersion = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    $windowsApplicationId = '55c92734-d682-4d71-983e-d6ec3f16059f'
    $license = $null
    $licenseService = $null
    $licensingQueryError = $null
    try {
        $licenseProducts = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='$windowsApplicationId'" |
            Where-Object { $_.PartialProductKey } |
            Sort-Object @{ Expression = { if ($_.LicenseStatus -eq 1) { 0 } else { 1 } } },
                        @{ Expression = { if ($_.Name -like 'Windows*') { 0 } else { 1 } } })
        $license = $licenseProducts | Select-Object -First 1
        $licenseService = Get-CimInstance -ClassName SoftwareLicensingService | Select-Object -First 1
    }
    catch {
        $licensingQueryError = $_.Exception.Message
    }

    $physicalCores = ($processors | Measure-Object -Property NumberOfCores -Sum).Sum
    $logicalProcessors = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $socketCount = @($processors | Select-Object -ExpandProperty SocketDesignation -Unique).Count
    if (-not $socketCount) { $socketCount = $computerSystem.NumberOfProcessors }

    $vmPattern = 'Virtual|VMware|KVM|Hyper-V|Xen|HVM|VirtualBox|Amazon EC2|Google Compute'
    $isVirtual = ($computerSystem.Model -match $vmPattern -or
                  $computerSystem.Manufacturer -match $vmPattern -or
                  $computerSystem.HypervisorPresent -eq $true)

    $displayVersion = $currentVersion.DisplayVersion
    if (-not $displayVersion) { $displayVersion = $currentVersion.ReleaseId }

    [pscustomobject][ordered]@{
        ComputerName                            = $env:COMPUTERNAME
        DNSHostName                             = $computerSystem.DNSHostName
        ScanTimestampUTC                        = (Get-Date).ToUniversalTime().ToString('o')
        AvailabilityStatus                      = 'Available - inventory completed'
        LicensingQueryStatus                    = if ($licensingQueryError) { 'Failed' } elseif ($license) { 'Completed' } else { 'No installed Windows license record found' }
        LicensingQueryError                     = $licensingQueryError
        OSCaption                               = $os.Caption
        OSEditionId                             = $currentVersion.EditionID
        OSDisplayVersion                        = $displayVersion
        OSVersion                               = $os.Version
        OSBuild                                 = if ($currentVersion.UBR -ne $null) { "$($os.BuildNumber).$($currentVersion.UBR)" } else { [string]$os.BuildNumber }
        OSArchitecture                          = $os.OSArchitecture
        InstallationType                        = $currentVersion.InstallationType
        WindowsProductName                      = if ($license) { $license.Name } else { $currentVersion.ProductName }
        WindowsProductDescription               = if ($license) { $license.Description } else { $null }
        ProductId                               = $currentVersion.ProductId
        LicenseStatusCode                       = if ($license) { $license.LicenseStatus } else { $null }
        LicenseStatusReason                     = if ($license) { ('0x{0:X8}' -f [uint32]$license.LicenseStatusReason) } else { $null }
        ProductKeyChannel                       = if ($license) { $license.ProductKeyChannel } else { $null }
        PartialProductKey                       = if ($license) { $license.PartialProductKey } else { $null }
        LicenseFamily                           = if ($license) { $license.LicenseFamily } else { $null }
        SkuId                                   = if ($license) { $license.ID } else { $null }
        GracePeriodRemainingMinutes             = if ($license) { $license.GracePeriodRemaining } else { $null }
        EvaluationEndDate                       = if ($license -and $license.EvaluationEndDate) { $license.EvaluationEndDate } else { $null }
        DiscoveredKmsServer                     = if ($license) { $license.DiscoveredKeyManagementServiceMachineName } else { $null }
        DiscoveredKmsPort                       = if ($license) { $license.DiscoveredKeyManagementServiceMachinePort } else { $null }
        ConfiguredKmsServer                     = if ($licenseService) { $licenseService.KeyManagementServiceMachine } else { $null }
        ConfiguredKmsPort                       = if ($licenseService) { $licenseService.KeyManagementServicePort } else { $null }
        KmsClientMachineId                      = if ($licenseService) { $licenseService.ClientMachineID } else { $null }
        VolumeActivationIntervalMinutes         = if ($licenseService) { $licenseService.VLActivationInterval } else { $null }
        VolumeRenewalIntervalMinutes            = if ($licenseService) { $licenseService.VLRenewalInterval } else { $null }
        RemainingWindowsRearmCount              = if ($licenseService) { $licenseService.RemainingWindowsReArmCount } else { $null }
        FirmwareEmbeddedKeyDescription          = if ($licenseService) { $licenseService.OA3xOriginalProductKeyDescription } else { $null }
        InstallDate                             = $os.InstallDate
        LastBootUpTime                          = $os.LastBootUpTime
        UptimeDays                              = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2)
        Manufacturer                            = $computerSystem.Manufacturer
        Model                                   = $computerSystem.Model
        IsVirtualMachine                        = [bool]$isVirtual
        SocketCount                             = $socketCount
        PhysicalCoreCount                       = $physicalCores
        LogicalProcessorCount                   = $logicalProcessors
        MemoryGB                                = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
    }
}

$invokeParameters = @{
    ComputerName  = $targets
    ScriptBlock   = $remoteCollector
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = 'SilentlyContinue'
    ErrorVariable = 'remotingErrors'
}
if ($Credential) { $invokeParameters.Credential = $Credential }

$rawResults = @(Invoke-Command @invokeParameters)
$responded = @($rawResults | Select-Object -ExpandProperty PSComputerName -Unique)
$inventory = New-Object System.Collections.Generic.List[object]

foreach ($item in $rawResults) {
    $adComputer = $null
    $lookupCandidates = @($item.DNSHostName, $item.ComputerName, $item.PSComputerName) |
        Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() }
    foreach ($candidate in $lookupCandidates) {
        if ($adLookup.ContainsKey($candidate)) {
            $adComputer = $adLookup[$candidate]
            break
        }
    }

    $status = Convert-LicenseStatus -Status $item.LicenseStatusCode
    $channel = Get-LicenseChannel -ProductKeyChannel $item.ProductKeyChannel -Description $item.WindowsProductDescription

    $inventory.Add([pscustomobject][ordered]@{
        ComputerName                  = $item.ComputerName
        DNSHostName                   = $item.DNSHostName
        AvailabilityStatus            = $item.AvailabilityStatus
        ScanTimestampUTC              = $item.ScanTimestampUTC
        LicensingQueryStatus          = $item.LicensingQueryStatus
        LicensingQueryError           = $item.LicensingQueryError
        IPv4Address                   = if ($adComputer) { $adComputer.IPv4Address } else { $null }
        ADOperatingSystem             = if ($adComputer) { $adComputer.OperatingSystem } else { $null }
        OSCaption                     = $item.OSCaption
        OSEditionId                   = $item.OSEditionId
        OSDisplayVersion              = $item.OSDisplayVersion
        OSVersion                     = $item.OSVersion
        OSBuild                       = $item.OSBuild
        OSArchitecture                = $item.OSArchitecture
        InstallationType              = $item.InstallationType
        ActivationStatus              = $status
        LicenseChannel                = $channel
        ProductKeyChannel             = $item.ProductKeyChannel
        PartialProductKey             = $item.PartialProductKey
        WindowsProductName            = $item.WindowsProductName
        WindowsProductDescription     = $item.WindowsProductDescription
        ProductId                     = $item.ProductId
        LicenseStatusCode             = $item.LicenseStatusCode
        LicenseStatusReason           = $item.LicenseStatusReason
        LicenseFamily                 = $item.LicenseFamily
        SkuId                         = $item.SkuId
        GracePeriodRemainingMinutes   = $item.GracePeriodRemainingMinutes
        EvaluationEndDate             = $item.EvaluationEndDate
        DiscoveredKmsServer           = $item.DiscoveredKmsServer
        DiscoveredKmsPort             = $item.DiscoveredKmsPort
        ConfiguredKmsServer           = $item.ConfiguredKmsServer
        ConfiguredKmsPort             = $item.ConfiguredKmsPort
        KmsClientMachineId            = $item.KmsClientMachineId
        VolumeActivationIntervalMins  = $item.VolumeActivationIntervalMinutes
        VolumeRenewalIntervalMins     = $item.VolumeRenewalIntervalMinutes
        RemainingWindowsRearmCount    = $item.RemainingWindowsRearmCount
        FirmwareKeyDescription        = $item.FirmwareEmbeddedKeyDescription
        InstallDate                   = $item.InstallDate
        LastBootUpTime                = $item.LastBootUpTime
        UptimeDays                    = $item.UptimeDays
        ADLastLogonDate               = if ($adComputer) { $adComputer.LastLogonDate } else { $null }
        ADComputerCreated             = if ($adComputer) { $adComputer.Created } else { $null }
        Manufacturer                  = $item.Manufacturer
        Model                         = $item.Model
        IsVirtualMachine              = $item.IsVirtualMachine
        SocketCount                   = $item.SocketCount
        PhysicalCoreCount             = $item.PhysicalCoreCount
        LogicalProcessorCount         = $item.LogicalProcessorCount
        MemoryGB                      = $item.MemoryGB
        EntitlementVerification       = 'Required - activation does not prove purchased or assigned license rights'
    })
}

$unreachable = @($targets | Where-Object { $_ -notin $responded } | ForEach-Object {
    [pscustomobject]@{
        ComputerName       = $_
        AvailabilityStatus = 'Unknown - WinRM unavailable or access denied'
        ScanTimestampUTC   = (Get-Date).ToUniversalTime().ToString('o')
        Evidence           = 'No PowerShell remoting response; this does not by itself prove the server is offline'
    }
})

$availability = @(
    $inventory | Select-Object ComputerName,DNSHostName,AvailabilityStatus,ScanTimestampUTC,LastBootUpTime,UptimeDays
    $unreachable | Select-Object ComputerName,@{ Name = 'DNSHostName'; Expression = { $null } },AvailabilityStatus,ScanTimestampUTC,
        @{ Name = 'LastBootUpTime'; Expression = { $null } },@{ Name = 'UptimeDays'; Expression = { $null } }
)

$selectedFormats = if ($OutputFormat -contains 'All') {
    @('HTML','CSV','JSON')
}
else {
    @($OutputFormat | Sort-Object -Unique)
}

$activatedCount = @($inventory | Where-Object ActivationStatus -eq 'Licensed').Count
$notLicensedCount = @($inventory | Where-Object ActivationStatus -ne 'Licensed').Count
$kmsCount = @($inventory | Where-Object LicenseChannel -like '*KMS*').Count
$makCount = @($inventory | Where-Object LicenseChannel -like '*MAK*').Count
$oemCount = @($inventory | Where-Object LicenseChannel -eq 'OEM').Count
$retailCount = @($inventory | Where-Object LicenseChannel -eq 'Retail').Count
$unknownCount = @($inventory | Where-Object LicenseChannel -eq 'Unknown/not exposed').Count
$licenseQueryFailureCount = @($inventory | Where-Object LicensingQueryStatus -eq 'Failed').Count

$summary = @(
    [pscustomobject]@{ Metric = 'AD Windows servers targeted'; Value = $targets.Count }
    [pscustomobject]@{ Metric = 'Available to inventory through WinRM'; Value = $inventory.Count }
    [pscustomobject]@{ Metric = 'WinRM unavailable/access denied'; Value = $unreachable.Count }
    [pscustomobject]@{ Metric = 'Activated/licensed status'; Value = $activatedCount }
    [pscustomobject]@{ Metric = 'Not licensed, grace, notification or unknown'; Value = $notLicensedCount }
    [pscustomobject]@{ Metric = 'KMS channel'; Value = $kmsCount }
    [pscustomobject]@{ Metric = 'MAK channel'; Value = $makCount }
    [pscustomobject]@{ Metric = 'OEM channel'; Value = $oemCount }
    [pscustomobject]@{ Metric = 'Retail channel'; Value = $retailCount }
    [pscustomobject]@{ Metric = 'Unknown channel'; Value = $unknownCount }
    [pscustomobject]@{ Metric = 'Licensing queries failed'; Value = $licenseQueryFailureCount }
)

$htmlPath = Join-Path $OutputFolder 'Windows-Server-OS-License-Inventory.html'
$csvPath = Join-Path $OutputFolder 'Windows-Server-OS-License-Inventory.csv'
$unreachableCsvPath = Join-Path $OutputFolder 'Unreachable-Windows-Servers.csv'
$availabilityCsvPath = Join-Path $OutputFolder 'Windows-Server-Availability.csv'
$jsonPath = Join-Path $OutputFolder 'Windows-Server-OS-License-Inventory.json'

if ($selectedFormats -contains 'CSV') {
    $inventory | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    $unreachable | Export-Csv -Path $unreachableCsvPath -NoTypeInformation -Encoding UTF8
    $availability | Export-Csv -Path $availabilityCsvPath -NoTypeInformation -Encoding UTF8
}

if ($selectedFormats -contains 'JSON') {
    [pscustomobject][ordered]@{
        GeneratedAtUTC       = (Get-Date).ToUniversalTime().ToString('o')
        GeneratedBy          = "$env:USERDOMAIN\$env:USERNAME"
        LicensingNotice      = 'Activation is not proof of entitlement. Reconcile with Microsoft agreement, subscription, purchase and assignment records.'
        Summary              = @($summary)
        Availability         = @($availability)
        Servers              = @($inventory)
        UnreachableServers   = @($unreachable)
    } | ConvertTo-Json -Depth 7 | Set-Content -Path $jsonPath -Encoding UTF8
}

if ($selectedFormats -contains 'HTML') {
    $style = @"
<style>
* { box-sizing: border-box; }
html, body { width: 100%; max-width: 100%; overflow-x: hidden; }
body { font-family: Segoe UI, Arial, sans-serif; margin: 0; padding: 24px; color: #202124; }
h1, h2 { color: #174a7e; }
.notice { padding: 12px; background: #fff4ce; border-left: 5px solid #d6a400; margin: 12px 0 20px; }
.searchbar { position: sticky; top: 0; z-index: 10; width: 100%; padding: 12px; margin: 12px 0 20px; background: #eef4fb; border: 1px solid #b8cce4; }
.searchbar label { font-weight: 600; margin-right: 8px; }
.searchbar input { width: min(650px, 70%); padding: 8px 10px; border: 1px solid #8796a5; border-radius: 4px; font-size: 14px; }
.searchbar button { padding: 8px 12px; margin-left: 6px; border: 1px solid #174a7e; border-radius: 4px; background: #174a7e; color: white; cursor: pointer; }
.table-container { width: 100%; max-width: 100%; overflow-x: auto; margin-bottom: 24px; border: 1px solid #c7cbd1; }
table { border-collapse: separate; border-spacing: 0; width: max-content; min-width: 100%; margin: 0; font-size: 12px; }
th { background: #174a7e; color: white; text-align: left; position: sticky; top: 0; z-index: 2; }
th, td { border-right: 1px solid #c7cbd1; border-bottom: 1px solid #c7cbd1; padding: 6px; vertical-align: top; min-width: 110px; max-width: 320px; overflow-wrap: anywhere; }
tr:nth-child(even) { background: #f5f7fa; }
th:first-child, td:first-child { position: sticky; left: 0; z-index: 3; }
td:first-child { background: white; font-weight: 600; }
tr:nth-child(even) td:first-child { background: #f5f7fa; }
th:first-child { background: #174a7e; z-index: 4; }
.small { color: #5f6368; font-size: 12px; }
</style>
"@

    $summaryHtml = $summary | ConvertTo-Html -Fragment
    $availabilityHtml = $availability | ConvertTo-Html -Fragment
    $inventoryHtml = if ($inventory.Count) {
        $inventory | Select-Object ComputerName,DNSHostName,AvailabilityStatus,ScanTimestampUTC,UptimeDays,
            LicensingQueryStatus,OSCaption,OSEditionId,OSDisplayVersion,OSBuild,
            OSArchitecture,InstallationType,ActivationStatus,LicenseChannel,PartialProductKey,
            WindowsProductName,ProductId,ProductKeyChannel,LicenseStatusReason,GracePeriodRemainingMinutes,
            DiscoveredKmsServer,ConfiguredKmsServer,IsVirtualMachine,SocketCount,
            PhysicalCoreCount,LogicalProcessorCount,MemoryGB,LastBootUpTime,ADLastLogonDate |
            ConvertTo-Html -Fragment
    }
    else { '<p>No server details were collected.</p>' }
    $unreachableHtml = if ($unreachable.Count) { $unreachable | ConvertTo-Html -Fragment } else { '<p>None.</p>' }
    $generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'

    $body = @"
<h1>Windows Server OS and License Inventory</h1>
<p class="small">Generated: $generated &nbsp; | &nbsp; Run by: $env:USERDOMAIN\$env:USERNAME</p>
<div class="notice"><strong>Licensing limitation:</strong> Activation shows the technical state of Windows, not whether the organization owns enough licenses or has correctly assigned them. Reconcile this inventory with Microsoft agreements, subscriptions and purchasing records. Complete product keys are intentionally not collected.</div>
<div class="searchbar">
  <label for="inventorySearch">Search report:</label>
  <input id="inventorySearch" type="search" placeholder="Server, OS, build, activation, KMS, MAK, OEM or partial key..." oninput="filterInventory()">
  <button type="button" onclick="clearInventorySearch()">Clear</button>
  <span id="searchStatus" class="small"></span>
</div>
<h2>Summary</h2>
<div class="table-container">$summaryHtml</div>
<h2>Availability During Scan</h2>
<div class="table-container">$availabilityHtml</div>
<h2>Server Inventory</h2>
<div class="table-container">$inventoryHtml</div>
<h2>Unreachable or Access Denied</h2>
<div class="table-container">$unreachableHtml</div>
<p class="small">Use -OutputFormat CSV, -OutputFormat JSON, or -OutputFormat All when additional result files are required.</p>
<script>
function filterInventory() {
    var query = document.getElementById('inventorySearch').value.toLowerCase().trim();
    var visible = 0;
    var total = 0;
    var tables = document.querySelectorAll('table');
    tables.forEach(function(table, tableIndex) {
        if (tableIndex === 0) { return; }
        var rows = table.querySelectorAll('tr');
        rows.forEach(function(row, rowIndex) {
            if (rowIndex === 0) { return; }
            total++;
            var match = !query || row.textContent.toLowerCase().indexOf(query) !== -1;
            row.style.display = match ? '' : 'none';
            if (match) { visible++; }
        });
    });
    document.getElementById('searchStatus').textContent = query ? (' Showing ' + visible + ' of ' + total + ' rows') : '';
}
function clearInventorySearch() {
    var search = document.getElementById('inventorySearch');
    search.value = '';
    filterInventory();
    search.focus();
}
</script>
"@

    ConvertTo-Html -Title 'Windows Server OS and License Inventory' -Head $style -Body $body |
        Set-Content -Path $htmlPath -Encoding UTF8
}

Write-Host ''
Write-Host 'Windows Server inventory complete.' -ForegroundColor Green
Write-Host ("Selected output format(s): {0}" -f ($selectedFormats -join ', '))
if ($selectedFormats -contains 'HTML') { Write-Host ("HTML report: {0}" -f $htmlPath) }
if ($selectedFormats -contains 'CSV') {
    Write-Host ("Server CSV: {0}" -f $csvPath)
    Write-Host ("Availability CSV: {0}" -f $availabilityCsvPath)
    Write-Host ("Unreachable CSV: {0}" -f $unreachableCsvPath)
}
if ($selectedFormats -contains 'JSON') { Write-Host ("JSON report: {0}" -f $jsonPath) }

[pscustomobject]@{
    OutputFolder      = $OutputFolder
    OutputFormats     = ($selectedFormats -join ',')
    HtmlReport        = if ($selectedFormats -contains 'HTML') { $htmlPath } else { $null }
    CsvReport         = if ($selectedFormats -contains 'CSV') { $csvPath } else { $null }
    AvailabilityCsv   = if ($selectedFormats -contains 'CSV') { $availabilityCsvPath } else { $null }
    UnreachableCsv    = if ($selectedFormats -contains 'CSV') { $unreachableCsvPath } else { $null }
    JsonReport        = if ($selectedFormats -contains 'JSON') { $jsonPath } else { $null }
    TargetCount       = $targets.Count
    ReachedCount      = $inventory.Count
    LicensedCount     = $activatedCount
    AttentionCount    = $notLicensedCount
    UnreachableCount  = $unreachable.Count
}
