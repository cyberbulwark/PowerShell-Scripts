#requires -Version 5.1
#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Discovers Microsoft SQL Server instances on domain Windows computers and
    creates technical and license-relevant inventory reports.

.DESCRIPTION
    Uses Active Directory and PowerShell remoting to discover installed SQL
    Server Database Engine instances. It then attempts a direct, read-only SQL
    connection with the account running the script to collect engine and
    database details.

    IMPORTANT: Microsoft SQL Server does not expose purchased entitlements,
    agreement numbers, or a reliable product key through SQL queries. This
    report records edition, deployment and hardware facts that must be matched
    to your Microsoft licensing records.

.EXAMPLE
    .\SQL-Server-License-Inventory.ps1

.EXAMPLE
    .\SQL-Server-License-Inventory.ps1 -SearchBase "OU=Servers,DC=corp,DC=root,DC=heywood,DC=org"

.EXAMPLE
    .\SQL-Server-License-Inventory.ps1 -ComputerName SQL01,SQL02 -OutputFolder C:\Temp\SQL-Audit

.EXAMPLE
    .\SQL-Server-License-Inventory.ps1 -ComputerScope AllWindows -Credential (Get-Credential)

.EXAMPLE
    .\SQL-Server-License-Inventory.ps1 -OutputFormat HTML,JSON
#>

[CmdletBinding()]
param(
    [ValidateSet('Servers','AllWindows')]
    [string]$ComputerScope = 'Servers',

    [string]$SearchBase,

    [string[]]$ComputerName,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 24,

    [ValidateRange(2,60)]
    [int]$SqlConnectionTimeoutSeconds = 5,

    [switch]$SkipDatabaseQuery,

    [ValidateSet('All','HTML','CSV','JSON')]
    [string[]]$OutputFormat = @('HTML'),

    [string]$OutputFolder = (Join-Path $env:SystemDrive ("Temp\SQL-Inventory-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'

function Get-LicenseAssessment {
    param([AllowNull()][string]$Edition)

    if ([string]::IsNullOrWhiteSpace($Edition)) {
        return 'Unknown edition - verify installation and purchasing records'
    }
    switch -Regex ($Edition) {
        'Express'    { return 'Express edition - no paid SQL Server license normally required; verify use remains within Express terms and limits' }
        'Developer'  { return 'Developer edition - permitted for development/test only, not production workloads' }
        'Evaluation' { return 'Evaluation edition - time-limited; not evidence of a production entitlement' }
        'Web'        { return 'Web edition - validate eligible hosting/SPLA licensing and workload use' }
        'Enterprise' { return 'Commercial Enterprise edition - reconcile deployment, cores/VMs and Software Assurance benefits with purchase records' }
        'Standard'   { return 'Commercial Standard edition - reconcile Server/CAL or Per-Core licensing with purchase records' }
        default      { return 'Edition detected - validate licensing terms and reconcile with purchase records' }
    }
}

function Invoke-SqlInventoryQuery {
    param(
        [Parameter(Mandatory)][string]$DataSource,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $result = [ordered]@{
        Connected               = $false
        Error                   = $null
        ServerProperties        = $null
        Databases               = @()
    }

    $connection = New-Object System.Data.SqlClient.SqlConnection
    $connection.ConnectionString = "Data Source=$DataSource;Initial Catalog=master;Integrated Security=SSPI;Connect Timeout=$TimeoutSeconds;Encrypt=False;Application Name=SQL License Inventory"

    try {
        $connection.Open()

        $command = $connection.CreateCommand()
        $command.CommandTimeout = 20
        $command.CommandText = @"
SELECT
    CONVERT(nvarchar(128), SERVERPROPERTY('MachineName'))             AS MachineName,
    CONVERT(nvarchar(128), SERVERPROPERTY('ServerName'))              AS ServerName,
    COALESCE(CONVERT(nvarchar(128), SERVERPROPERTY('InstanceName')), 'MSSQLSERVER') AS InstanceName,
    CONVERT(nvarchar(128), SERVERPROPERTY('Edition'))                 AS Edition,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion'))          AS ProductVersion,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductLevel'))            AS ProductLevel,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductUpdateLevel'))      AS ProductUpdateLevel,
    CONVERT(nvarchar(128), SERVERPROPERTY('ProductUpdateReference'))  AS ProductUpdateReference,
    CONVERT(int, SERVERPROPERTY('EngineEdition'))                     AS EngineEdition,
    CONVERT(int, SERVERPROPERTY('IsClustered'))                       AS IsClustered,
    CONVERT(int, SERVERPROPERTY('IsHadrEnabled'))                     AS IsHadrEnabled,
    CONVERT(int, SERVERPROPERTY('IsIntegratedSecurityOnly'))          AS IsIntegratedSecurityOnly;
"@
        $reader = $command.ExecuteReader()
        if ($reader.Read()) {
            $properties = [ordered]@{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                $value = $reader.GetValue($i)
                if ($value -is [DBNull]) { $value = $null }
                $properties[$reader.GetName($i)] = $value
            }
            $result.ServerProperties = [pscustomobject]$properties
        }
        $reader.Close()

        if (-not $SkipDatabaseQuery) {
            $command.CommandText = @"
SELECT
    name AS DatabaseName,
    state_desc AS State,
    recovery_model_desc AS RecoveryModel,
    compatibility_level AS CompatibilityLevel,
    containment_desc AS Containment,
    is_read_only AS IsReadOnly,
    is_encrypted AS IsEncrypted,
    user_access_desc AS UserAccess,
    create_date AS CreateDate
FROM sys.databases
ORDER BY name;
"@
            $reader = $command.ExecuteReader()
            $databaseRows = New-Object System.Collections.Generic.List[object]
            while ($reader.Read()) {
                $row = [ordered]@{}
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $value = $reader.GetValue($i)
                    if ($value -is [DBNull]) { $value = $null }
                    $row[$reader.GetName($i)] = $value
                }
                $databaseRows.Add([pscustomobject]$row)
            }
            $reader.Close()
            $result.Databases = @($databaseRows)
        }

        $result.Connected = $true
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    finally {
        if ($connection.State -ne [System.Data.ConnectionState]::Closed) {
            $connection.Close()
        }
        $connection.Dispose()
    }

    return [pscustomobject]$result
}

Write-Host 'Building target computer list...' -ForegroundColor Cyan

if ($ComputerName) {
    $targets = @($ComputerName | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique)
}
else {
    $adParameters = @{
        Properties = @('DNSHostName','OperatingSystem','Enabled')
    }
    if ($ComputerScope -eq 'Servers') {
        $adParameters.Filter = 'Enabled -eq $true -and OperatingSystem -like "*Windows Server*"'
    }
    else {
        $adParameters.Filter = 'Enabled -eq $true -and OperatingSystem -like "*Windows*"'
    }
    if ($SearchBase) { $adParameters.SearchBase = $SearchBase }

    $targets = @(Get-ADComputer @adParameters |
        ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } } |
        Sort-Object -Unique)
}

if ($targets.Count -eq 0) {
    throw 'No computers were found for the specified scope.'
}

New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
Write-Host ("Scanning {0} computer(s) with PowerShell remoting..." -f $targets.Count) -ForegroundColor Cyan

$remoteCollector = {
    $computerSystem = Get-CimInstance Win32_ComputerSystem
    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $processors = @(Get-CimInstance Win32_Processor)
    $services = @(Get-CimInstance Win32_Service)

    $physicalCores = ($processors | Measure-Object -Property NumberOfCores -Sum).Sum
    $logicalProcessors = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    $socketCount = @($processors | Select-Object -ExpandProperty SocketDesignation -Unique).Count
    if (-not $socketCount) { $socketCount = $computerSystem.NumberOfProcessors }

    $vmPattern = 'Virtual|VMware|KVM|Hyper-V|Xen|HVM|VirtualBox|Amazon EC2|Google Compute'
    $isVirtual = ($computerSystem.Model -match $vmPattern -or
                  $computerSystem.Manufacturer -match $vmPattern -or
                  $computerSystem.HypervisorPresent -eq $true)

    $instanceMap = [ordered]@{}
    $instanceRegistryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL'
    )

    foreach ($instanceRegistryPath in $instanceRegistryPaths) {
        if (Test-Path $instanceRegistryPath) {
            $item = Get-ItemProperty $instanceRegistryPath
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -notmatch '^PS') {
                    $instanceMap[$property.Name] = [string]$property.Value
                }
            }
        }
    }

    foreach ($instanceName in $instanceMap.Keys) {
        $instanceId = $instanceMap[$instanceName]
        $basePath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId"
        if (-not (Test-Path $basePath)) {
            $basePath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\$instanceId"
        }

        $setup = $null
        if (Test-Path "$basePath\Setup") {
            $setup = Get-ItemProperty "$basePath\Setup"
        }

        $engineSettings = $null
        if (Test-Path "$basePath\MSSQLServer") {
            $engineSettings = Get-ItemProperty "$basePath\MSSQLServer"
        }

        $tcpSettings = $null
        $tcpIpAllPath = "$basePath\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
        if (Test-Path $tcpIpAllPath) {
            $tcpSettings = Get-ItemProperty $tcpIpAllPath
        }

        $tcpProtocol = $null
        $tcpProtocolPath = "$basePath\MSSQLServer\SuperSocketNetLib\Tcp"
        if (Test-Path $tcpProtocolPath) {
            $tcpProtocol = Get-ItemProperty $tcpProtocolPath
        }

        if ($instanceName -eq 'MSSQLSERVER') {
            $engineServiceName = 'MSSQLSERVER'
            $agentServiceName = 'SQLSERVERAGENT'
            $dataSource = $env:COMPUTERNAME
        }
        else {
            $engineServiceName = "MSSQL`$$instanceName"
            $agentServiceName = "SQLAgent`$$instanceName"
            $dataSource = "$env:COMPUTERNAME\$instanceName"
        }

        $engineService = $services | Where-Object Name -eq $engineServiceName | Select-Object -First 1
        $agentService = $services | Where-Object Name -eq $agentServiceName | Select-Object -First 1

        $loginMode = if ($engineSettings) { $engineSettings.LoginMode } else { $null }
        $authenticationMode = switch ($loginMode) {
            1 { 'Windows only' }
            2 { 'Mixed (Windows and SQL)' }
            default { 'Unknown' }
        }

        [pscustomobject][ordered]@{
            ResultType               = 'Instance'
            ScanComputer             = $env:COMPUTERNAME
            DNSHostName              = $computerSystem.DNSHostName
            DataSource               = $dataSource
            InstanceName             = $instanceName
            InstanceId               = $instanceId
            RegistryEdition          = if ($setup) { $setup.Edition } else { $null }
            RegistryVersion          = if ($setup) { $setup.Version } else { $null }
            RegistryPatchLevel       = if ($setup) { $setup.PatchLevel } else { $null }
            EngineServiceState       = if ($engineService) { $engineService.State } else { 'Not found' }
            EngineServiceStartMode   = if ($engineService) { $engineService.StartMode } else { $null }
            EngineServiceAccount     = if ($engineService) { $engineService.StartName } else { $null }
            AgentServiceState        = if ($agentService) { $agentService.State } else { 'Not found' }
            AgentServiceStartMode    = if ($agentService) { $agentService.StartMode } else { $null }
            AgentServiceAccount      = if ($agentService) { $agentService.StartName } else { $null }
            TcpEnabled               = if ($tcpProtocol) { [bool]$tcpProtocol.Enabled } else { $null }
            StaticTcpPort            = if ($tcpSettings) { $tcpSettings.TcpPort } else { $null }
            DynamicTcpPort           = if ($tcpSettings) { $tcpSettings.TcpDynamicPorts } else { $null }
            AuthenticationMode       = $authenticationMode
            OperatingSystem          = $operatingSystem.Caption
            OSVersion                = $operatingSystem.Version
            Manufacturer             = $computerSystem.Manufacturer
            Model                    = $computerSystem.Model
            IsVirtualMachine         = [bool]$isVirtual
            SocketCount              = $socketCount
            PhysicalCoreCount        = $physicalCores
            LogicalProcessorCount    = $logicalProcessors
            MemoryGB                 = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
        }
    }

    if ($instanceMap.Count -eq 0) {
        [pscustomobject]@{
            ResultType   = 'NoSql'
            ScanComputer = $env:COMPUTERNAME
            DNSHostName  = $computerSystem.DNSHostName
            OperatingSystem = $operatingSystem.Caption
        }
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

$remoteResults = @(Invoke-Command @invokeParameters)
$instances = @($remoteResults | Where-Object ResultType -eq 'Instance')
$noSqlComputers = @($remoteResults | Where-Object ResultType -eq 'NoSql')
$responded = @($remoteResults | Select-Object -ExpandProperty PSComputerName -Unique)
$unreachable = @($targets | Where-Object { $_ -notin $responded } | ForEach-Object {
    [pscustomobject]@{
        ComputerName = $_
        Status       = 'PowerShell remoting failed or access was denied'
    }
})

$databaseInventory = New-Object System.Collections.Generic.List[object]
$finalInventory = New-Object System.Collections.Generic.List[object]

Write-Host ("Discovered {0} SQL Database Engine instance(s)." -f $instances.Count) -ForegroundColor Cyan

foreach ($instance in $instances) {
    $sqlResult = Invoke-SqlInventoryQuery -DataSource $instance.DataSource -TimeoutSeconds $SqlConnectionTimeoutSeconds
    $serverProperties = $sqlResult.ServerProperties

    $edition = if ($serverProperties -and $serverProperties.Edition) { [string]$serverProperties.Edition } else { [string]$instance.RegistryEdition }
    $version = if ($serverProperties -and $serverProperties.ProductVersion) { [string]$serverProperties.ProductVersion } elseif ($instance.RegistryPatchLevel) { [string]$instance.RegistryPatchLevel } else { [string]$instance.RegistryVersion }
    $level = if ($serverProperties) { [string]$serverProperties.ProductLevel } else { $null }
    $updateLevel = if ($serverProperties) { [string]$serverProperties.ProductUpdateLevel } else { $null }
    $updateReference = if ($serverProperties) { [string]$serverProperties.ProductUpdateReference } else { $null }

    $finalInventory.Add([pscustomobject][ordered]@{
        ComputerName            = $instance.ScanComputer
        DNSHostName             = $instance.DNSHostName
        InstanceName            = $instance.InstanceName
        DataSource              = $instance.DataSource
        Edition                 = $edition
        ProductVersion          = $version
        ProductLevel            = $level
        ProductUpdateLevel      = $updateLevel
        ProductUpdateReference  = $updateReference
        EngineEditionCode       = if ($serverProperties) { $serverProperties.EngineEdition } else { $null }
        EngineServiceState      = $instance.EngineServiceState
        EngineServiceStartMode  = $instance.EngineServiceStartMode
        EngineServiceAccount    = $instance.EngineServiceAccount
        AgentServiceState       = $instance.AgentServiceState
        AgentServiceStartMode   = $instance.AgentServiceStartMode
        AgentServiceAccount     = $instance.AgentServiceAccount
        TcpEnabled              = $instance.TcpEnabled
        StaticTcpPort           = $instance.StaticTcpPort
        DynamicTcpPort          = $instance.DynamicTcpPort
        AuthenticationMode      = if ($serverProperties) { if ($serverProperties.IsIntegratedSecurityOnly -eq 1) { 'Windows only' } else { 'Mixed (Windows and SQL)' } } else { $instance.AuthenticationMode }
        IsClustered             = if ($serverProperties) { [bool]$serverProperties.IsClustered } else { $null }
        IsHadrEnabled           = if ($serverProperties) { [bool]$serverProperties.IsHadrEnabled } else { $null }
        OperatingSystem         = $instance.OperatingSystem
        OSVersion               = $instance.OSVersion
        Manufacturer            = $instance.Manufacturer
        Model                   = $instance.Model
        IsVirtualMachine        = $instance.IsVirtualMachine
        SocketCount             = $instance.SocketCount
        PhysicalCoreCount       = $instance.PhysicalCoreCount
        LogicalProcessorCount   = $instance.LogicalProcessorCount
        MemoryGB                = $instance.MemoryGB
        SqlConnectionStatus     = if ($sqlResult.Connected) { 'Connected' } else { 'Failed' }
        SqlConnectionError      = $sqlResult.Error
        DatabaseCount           = @($sqlResult.Databases).Count
        LicenseAssessment       = Get-LicenseAssessment -Edition $edition
        LicenseEvidenceRequired = 'Verify purchase records, agreement/subscription, license model, assigned cores/servers/CALs, mobility and Software Assurance; SQL Server does not expose entitlement or a reliable product key'
    })

    foreach ($database in $sqlResult.Databases) {
        $databaseInventory.Add([pscustomobject][ordered]@{
            ComputerName       = $instance.ScanComputer
            InstanceName       = $instance.InstanceName
            DataSource         = $instance.DataSource
            DatabaseName       = $database.DatabaseName
            State              = $database.State
            RecoveryModel      = $database.RecoveryModel
            CompatibilityLevel = $database.CompatibilityLevel
            Containment        = $database.Containment
            IsReadOnly         = $database.IsReadOnly
            IsEncrypted        = $database.IsEncrypted
            UserAccess         = $database.UserAccess
            CreateDate         = $database.CreateDate
        })
    }
}

$inventoryCsv = Join-Path $OutputFolder 'SQL-Server-Inventory.csv'
$databaseCsv = Join-Path $OutputFolder 'SQL-Database-Inventory.csv'
$unreachableCsv = Join-Path $OutputFolder 'Unreachable-Computers.csv'
$noSqlCsv = Join-Path $OutputFolder 'Scanned-Computers-Without-SQL.csv'
$htmlReport = Join-Path $OutputFolder 'SQL-Server-License-Inventory.html'
$jsonReport = Join-Path $OutputFolder 'SQL-Server-License-Inventory.json'

$selectedFormats = if ($OutputFormat -contains 'All') {
    @('HTML','CSV','JSON')
}
else {
    @($OutputFormat | Sort-Object -Unique)
}

if ($selectedFormats -contains 'CSV') {
    $finalInventory | Export-Csv -Path $inventoryCsv -NoTypeInformation -Encoding UTF8
    $databaseInventory | Export-Csv -Path $databaseCsv -NoTypeInformation -Encoding UTF8
    $unreachable | Export-Csv -Path $unreachableCsv -NoTypeInformation -Encoding UTF8
    $noSqlComputers | Select-Object ScanComputer,DNSHostName,OperatingSystem |
        Export-Csv -Path $noSqlCsv -NoTypeInformation -Encoding UTF8
}

$commercialCount = @($finalInventory | Where-Object Edition -Match 'Standard|Enterprise|Web').Count
$freeOrNonProdCount = @($finalInventory | Where-Object Edition -Match 'Express|Developer|Evaluation').Count
$failedSqlConnections = @($finalInventory | Where-Object SqlConnectionStatus -eq 'Failed').Count

$summary = @(
    [pscustomobject]@{ Metric = 'Computers targeted'; Value = $targets.Count }
    [pscustomobject]@{ Metric = 'Computers reached'; Value = $responded.Count }
    [pscustomobject]@{ Metric = 'Unreachable/access denied'; Value = $unreachable.Count }
    [pscustomobject]@{ Metric = 'SQL instances found'; Value = $finalInventory.Count }
    [pscustomobject]@{ Metric = 'Commercial-edition instances'; Value = $commercialCount }
    [pscustomobject]@{ Metric = 'Express/Developer/Evaluation instances'; Value = $freeOrNonProdCount }
    [pscustomobject]@{ Metric = 'SQL connections failed'; Value = $failedSqlConnections }
    [pscustomobject]@{ Metric = 'Databases inventoried'; Value = $databaseInventory.Count }
)

if ($selectedFormats -contains 'JSON') {
    [pscustomobject][ordered]@{
        GeneratedAtUTC       = (Get-Date).ToUniversalTime().ToString('o')
        GeneratedBy          = "$env:USERDOMAIN\$env:USERNAME"
        LicensingNotice      = 'Deployment inventory only. Reconcile detected edition, deployment and hardware facts with Microsoft purchasing, subscription and agreement records.'
        Summary              = @($summary)
        SqlInstances         = @($finalInventory)
        Databases            = @($databaseInventory)
        UnreachableComputers = @($unreachable)
        ComputersWithoutSql  = @($noSqlComputers | Select-Object ScanComputer,DNSHostName,OperatingSystem)
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonReport -Encoding UTF8
}

$style = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #222; }
h1, h2 { color: #174a7e; }
.notice { padding: 12px; background: #fff4ce; border-left: 5px solid #d6a400; margin: 12px 0 20px; }
.searchbar { position: sticky; top: 0; z-index: 10; padding: 12px; margin: 12px 0 20px; background: #eef4fb; border: 1px solid #b8cce4; }
.searchbar label { font-weight: 600; margin-right: 8px; }
.searchbar input { width: min(620px, 70%); padding: 8px 10px; border: 1px solid #8796a5; border-radius: 4px; font-size: 14px; }
.searchbar button { padding: 8px 12px; margin-left: 6px; border: 1px solid #174a7e; border-radius: 4px; background: #174a7e; color: white; cursor: pointer; }
table { border-collapse: collapse; width: 100%; margin-bottom: 24px; font-size: 12px; }
th { background: #174a7e; color: white; text-align: left; position: sticky; top: 0; }
th, td { border: 1px solid #ccc; padding: 6px; vertical-align: top; }
tr:nth-child(even) { background: #f5f7fa; }
.small { color: #555; font-size: 12px; }
</style>
"@

$summaryHtml = $summary | ConvertTo-Html -Fragment
$inventoryHtml = if ($finalInventory.Count) {
    $finalInventory | Select-Object ComputerName,InstanceName,Edition,ProductVersion,ProductLevel,ProductUpdateLevel,
        EngineServiceState,EngineServiceAccount,AuthenticationMode,StaticTcpPort,DynamicTcpPort,IsClustered,
        IsHadrEnabled,IsVirtualMachine,SocketCount,PhysicalCoreCount,LogicalProcessorCount,MemoryGB,
        SqlConnectionStatus,DatabaseCount,LicenseAssessment | ConvertTo-Html -Fragment
} else { '<p>No SQL Database Engine instances were found.</p>' }
$unreachableHtml = if ($unreachable.Count) { $unreachable | ConvertTo-Html -Fragment } else { '<p>None.</p>' }
$databaseHtml = if ($databaseInventory.Count) {
    $databaseInventory | ConvertTo-Html -Fragment
} else { '<p>No database details were collected.</p>' }
$noSqlHtml = if ($noSqlComputers.Count) {
    $noSqlComputers | Select-Object ScanComputer,DNSHostName,OperatingSystem | ConvertTo-Html -Fragment
} else { '<p>None.</p>' }

$generated = Get-Date -Format 'yyyy-MM-dd HH:mm:ss K'
$body = @"
<h1>SQL Server Technical and License-Relevant Inventory</h1>
<p class="small">Generated: $generated &nbsp; | &nbsp; Run by: $env:USERDOMAIN\$env:USERNAME</p>
<div class="notice"><strong>Licensing limitation:</strong> This is a deployment inventory, not proof of license compliance. SQL Server does not reliably expose purchased product keys, agreement entitlements, assigned licenses, CAL counts, or Software Assurance rights. Reconcile these results with Microsoft purchasing, subscription and agreement records.</div>
<div class="searchbar">
  <label for="inventorySearch">Search report:</label>
  <input id="inventorySearch" type="search" placeholder="Server, instance, edition, version, account, port or database..." oninput="filterInventory()">
  <button type="button" onclick="clearInventorySearch()">Clear</button>
  <span id="searchStatus" class="small"></span>
</div>
<h2>Summary</h2>
$summaryHtml
<h2>SQL Server Instances</h2>
$inventoryHtml
<h2>Unreachable or Access Denied</h2>
$unreachableHtml
<h2>Database Details</h2>
$databaseHtml
<h2>Scanned Computers Without SQL Server</h2>
$noSqlHtml
<p class="small">Use -OutputFormat CSV or -OutputFormat All when spreadsheet files are also required.</p>
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

if ($selectedFormats -contains 'HTML') {
    ConvertTo-Html -Title 'SQL Server License Inventory' -Head $style -Body $body |
        Set-Content -Path $htmlReport -Encoding UTF8
}

Write-Host ''
Write-Host 'Inventory complete.' -ForegroundColor Green
Write-Host ("Selected output format(s): {0}" -f ($selectedFormats -join ', '))
if ($selectedFormats -contains 'HTML') { Write-Host ("HTML report: {0}" -f $htmlReport) }
if ($selectedFormats -contains 'JSON') { Write-Host ("JSON report: {0}" -f $jsonReport) }
if ($selectedFormats -contains 'CSV') {
    Write-Host ("Instance CSV: {0}" -f $inventoryCsv)
    Write-Host ("Database CSV: {0}" -f $databaseCsv)
    Write-Host ("Unreachable CSV: {0}" -f $unreachableCsv)
    Write-Host ("No-SQL CSV: {0}" -f $noSqlCsv)
}

[pscustomobject]@{
    OutputFolder       = $OutputFolder
    OutputFormats      = ($selectedFormats -join ',')
    HtmlReport         = if ($selectedFormats -contains 'HTML') { $htmlReport } else { $null }
    JsonReport         = if ($selectedFormats -contains 'JSON') { $jsonReport } else { $null }
    InstanceCsv        = if ($selectedFormats -contains 'CSV') { $inventoryCsv } else { $null }
    DatabaseCsv        = if ($selectedFormats -contains 'CSV') { $databaseCsv } else { $null }
    UnreachableCsv     = if ($selectedFormats -contains 'CSV') { $unreachableCsv } else { $null }
    NoSqlCsv           = if ($selectedFormats -contains 'CSV') { $noSqlCsv } else { $null }
    TargetCount        = $targets.Count
    SqlInstanceCount   = $finalInventory.Count
}
