<# ==================================================================
 SystemUpdateCheck.ps1 – Selbst-Elevation + Exclude-Listen + Menü
 PS 5.1 & 7+. Approved Verbs, keine Cmdlet-Aliasse. Persistente Excludes.
 Menü 5: Exclude anzeigen/bearbeiten/exportieren/importieren
 Fixes: winget scan in USER+MACHINE Scope, „Zurück"/„Beenden" wirklich verlassen
================================================================== #>

# --- Selbst-Elevation ----------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "Nicht mit Administratorrechten gestartet." -ForegroundColor Yellow
    Write-Host "Installation von Updates benötigt Adminrechte." -ForegroundColor Yellow
    $opt = Read-Host "1=Als Admin neu starten  |  2=Beenden  (1 oder 2 eingeben)"
    switch ($opt) {
        '1' {
            if (-not $PSCommandPath) { Write-Host "Datei erst speichern und erneut ausführen." -ForegroundColor Red; return }
            $hostExe = (Get-Process -Id $PID).Path
            try { Start-Process $hostExe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; return }
            catch { Write-Host "Elevation fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red; return }
        }
        '2' { Write-Host "Beende…" -ForegroundColor Cyan; return }
        default { Write-Host "Ungültige Eingabe. Beende." -ForegroundColor Red; return }
    }
}

# --- Logging / Pfade -----------------------------------------------------------
$LogDir = 'C:\Logs'
$LogFile = Join-Path $LogDir 'SystemUpdates.log'
$ExcludePath = Join-Path $LogDir 'UpdateExcludes.json'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
"=== Update-Check gestartet: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (PS $($PSVersionTable.PSVersion)) ===" | Out-File $LogFile -Append

# --- Exclude-Konfiguration -----------------------------------------------------
function Get-ExcludeConfig {
    if (Test-Path $ExcludePath) {
        try { return Get-Content $ExcludePath -Raw | ConvertFrom-Json } catch { }
    }
    [pscustomobject]@{ WindowsKB = @(); WingetIDs = @() }
}

function Set-ExcludeConfig { param($Config) $Config | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 $ExcludePath }

# --- Wenn Exclude-Liste leer ist -----------------------------------------------
# --- Standard-Einträge deren Update Probleme machen könnten --------------------
$Excl = Get-ExcludeConfig
if (($Excl.WindowsKB.Count -eq 0) -and ($Excl.WingetIDs.Count -eq 0)) {
    $Excl.WingetIDs = @(
        'NVIDIA.GeForceExperience', 'NVIDIA.GraphicsDriver', 'AdvancedMicroDevices.AMDSoftware', 'Intel.GraphicsDriver',
        'Oracle.JavaRuntimeEnvironment', 'Oracle.JavaDevelopmentKit',
        'MySQL.MySQLServer', 'PostgreSQL.PostgreSQL', 'Node.js.Node.js', 'PHP.PHP'
    )
    Set-ExcludeConfig $Excl
    Write-Host "Exclude-Liste mit Standard-Einträgen initialisiert." -ForegroundColor Cyan
}

# --- Utilities -----------------------------------------------------------------
function Write-Section { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }
function Test-WingetPresent { [bool](Get-Command winget -ErrorAction SilentlyContinue) }
function Test-PSWindowsUpdatePresent { 
    # Robustere Prüfung - suche in allen möglichen PowerShell-Modulpfaden
    $moduleFound = $false
    
    # Standard Get-Module Prüfung
    if (Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue) {
        $moduleFound = $true
    }
    
    # Falls nicht gefunden, prüfe alle bekannten PowerShell-Modulpfade
    if (-not $moduleFound) {
        $searchPaths = @(
            "${env:ProgramFiles}\PowerShell\Modules",
            "${env:ProgramFiles}\WindowsPowerShell\Modules", 
            "${env:UserProfile}\Documents\PowerShell\Modules",
            "${env:UserProfile}\Documents\WindowsPowerShell\Modules"
        )
        
        foreach ($path in $searchPaths) {
            if (Test-Path (Join-Path $path "PSWindowsUpdate")) {
                $moduleFound = $true
                break
            }
        }
    }
    
    return $moduleFound
}
function Import-PSWindowsUpdateOrExplain {
    if (-not (Test-PSWindowsUpdatePresent)) {
        Write-Host "PSWindowsUpdate nicht gefunden." -ForegroundColor Red
        Write-Host "Install-Module PSWindowsUpdate -Scope AllUsers -Force" -ForegroundColor Yellow
        Write-Host "(NuGet ggf.: Get-PackageProvider NuGet -ForceBootstrap -Force)" -ForegroundColor Gray
        if (Test-Path variable:LogFile) { "!!! Fehler: PSWindowsUpdate fehlte." | Out-File $LogFile -Append }
        return $false
    }
    try {
        # Versuche zuerst normalen Import
        Import-Module PSWindowsUpdate -ErrorAction Stop
        return $true
    }
    catch {
        # Falls normaler Import fehlschlägt, suche nach dem Modul in allen Pfaden und importiere explizit
        $searchPaths = @(
            "${env:ProgramFiles}\PowerShell\Modules",
            "${env:ProgramFiles}\WindowsPowerShell\Modules", 
            "${env:UserProfile}\Documents\PowerShell\Modules",
            "${env:UserProfile}\Documents\WindowsPowerShell\Modules"
        )
        
        foreach ($path in $searchPaths) {
            $fullPath = Join-Path $path "PSWindowsUpdate"
            if (Test-Path $fullPath) {
                try {
                    # Expliziter Import über Pfad
                    Import-Module $fullPath -ErrorAction Stop
                    Write-Host "PSWindowsUpdate erfolgreich importiert aus: $fullPath" -ForegroundColor Green
                    return $true
                }
                catch {
                    continue
                }
            }
        }
        
        Write-Host "!!! Fehler beim Importieren von PSWindowsUpdate: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Versuchen Sie: Install-Module PSWindowsUpdate -Scope AllUsers -Force" -ForegroundColor Yellow
        if (Test-Path variable:LogFile) { "!!! Fehler Import PSWindowsUpdate: $($_.Exception.Message)" | Out-File $LogFile -Append }
        return $false
    }
}

# --- Anzeige & Toggle der Listen ----------------------------------------------
function Show-NumberedList {
    param([array]$Items, [string]$Kind, [ref]$ExcludeConfig)
    if (-not $Items -or $Items.Count -eq 0) { Write-Host "Keine $Kind Updates verfügbar." -ForegroundColor Yellow; return @() }

    $i = 0; foreach ($it in $Items) {
        $i++
        $isExcluded = if ($Kind -eq 'Windows') { $ExcludeConfig.Value.WindowsKB -contains $it.Key } else { $ExcludeConfig.Value.WingetIDs -contains $it.Key }
        $it | Add-Member Number $i -Force
        $it | Add-Member Excluded $isExcluded -Force
        $mark = if ($isExcluded) { '[X]' }else { '[ ]' }
        Write-Host ("{0,2}. {1} {2}  {3}" -f $i, $mark, $it.Title, $it.Extra)
    }

    Write-Host ""
    Write-Host "Möchten Sie Updates in der Ausschlussliste eintragen/entfernen? Wenn ja, dann Nummern (z.B. 1,3,5 oder 2-4). Wenn nicht, dann ENTER oder W=weiter eingeben" -ForegroundColor DarkGray
    $sel = Read-Host "Auswahl"
    if ([string]::IsNullOrWhiteSpace($sel) -or $sel -match '^[Ww]$') { return $Items }

    $tokens = $sel -split '[,; ]+' | Where-Object { $_ -match '\S' }
    $numbers = New-Object System.Collections.Generic.List[int]
    foreach ($t in $tokens) {
        if ($t -match '^\d+$') { $numbers.Add([int]$t) }
        elseif ($t -match '^(\d+)-(\d+)$') { $from = [int]$matches[1]; $to = [int]$matches[2]; if ($from -le $to) { $from..$to | ForEach-Object { $numbers.Add($_) } } }
    }

    foreach ($n in ($numbers | Select-Object -Unique | Where-Object { $_ -ge 1 -and $_ -le $Items.Count })) {
        $item = $Items[$n - 1]
        if ($Kind -eq 'Windows') {
            if ($ExcludeConfig.Value.WindowsKB -contains $item.Key) {
                $ExcludeConfig.Value.WindowsKB = @($ExcludeConfig.Value.WindowsKB | Where-Object { $_ -ne $item.Key }); $item.Excluded = $false
                Write-Host (" - {0} von Ausschlussliste entfernt" -f $item.Title) -ForegroundColor Green
            }
            else {
                $ExcludeConfig.Value.WindowsKB += $item.Key; $ExcludeConfig.Value.WindowsKB = $ExcludeConfig.Value.WindowsKB | Select-Object -Unique; $item.Excluded = $true
                Write-Host (" + {0} zur Ausschlussliste hinzugefügt" -f $item.Title) -ForegroundColor Yellow
            }
        }
        else {
            if ($ExcludeConfig.Value.WingetIDs -contains $item.Key) {
                $ExcludeConfig.Value.WingetIDs = @($ExcludeConfig.Value.WingetIDs | Where-Object { $_ -ne $item.Key }); $item.Excluded = $false
                Write-Host (" - {0} von Ausschlussliste entfernt" -f $item.Title) -ForegroundColor Green
            }
            else {
                $ExcludeConfig.Value.WingetIDs += $item.Key; $ExcludeConfig.Value.WingetIDs = $ExcludeConfig.Value.WingetIDs | Select-Object -Unique; $item.Excluded = $true
                Write-Host (" + {0} zur Ausschlussliste hinzugefügt" -f $item.Title) -ForegroundColor Yellow
            }
        }
    }
    Set-ExcludeConfig $ExcludeConfig.Value
    return $Items
}

# --- Kombinierte Anzeige für Option 3 (Windows + Software zusammen) -----------
function Show-CombinedUpdateList {
    param([array]$WindowsItems, [array]$SoftwareItems, [ref]$ExcludeConfig)
    
    $allItems = @()
    $currentNumber = 1
    
    # Windows Updates hinzufügen
    if ($WindowsItems -and $WindowsItems.Count -gt 0) {
        Write-Host "`nWindows Updates:" -ForegroundColor Cyan
        foreach ($item in $WindowsItems) {
            $isExcluded = $ExcludeConfig.Value.WindowsKB -contains $item.Key
            $item | Add-Member Number $currentNumber -Force
            $item | Add-Member Excluded $isExcluded -Force
            $item | Add-Member Kind 'Windows' -Force
            $mark = if ($isExcluded) { '[X]' } else { '[ ]' }
            Write-Host ("{0,2}. {1} {2}  {3}" -f $currentNumber, $mark, $item.Title, $item.Extra)
            $allItems += $item
            $currentNumber++
        }
    }
    
    # Software Updates hinzufügen
    if ($SoftwareItems -and $SoftwareItems.Count -gt 0) {
        Write-Host "`nSoftware Updates:" -ForegroundColor Cyan
        foreach ($item in $SoftwareItems) {
            $isExcluded = $ExcludeConfig.Value.WingetIDs -contains $item.Key
            $item | Add-Member Number $currentNumber -Force
            $item | Add-Member Excluded $isExcluded -Force
            $item | Add-Member Kind 'Software' -Force
            $mark = if ($isExcluded) { '[X]' } else { '[ ]' }
            Write-Host ("{0,2}. {1} {2}  {3}" -f $currentNumber, $mark, $item.Title, $item.Extra)
            $allItems += $item
            $currentNumber++
        }
    }
    
    if ($allItems.Count -eq 0) {
        Write-Host "Keine Updates verfügbar." -ForegroundColor Yellow
        return @()
    }

    Write-Host ""
    Write-Host "(X markierte Updates stehen auf Ausschlussliste)"
    Write-Host "Sollen Einträge auf Ausschlussliste eingetragen/entfernt werden?Wenn ja, dann Nummern (z.B. 1,3,5 oder 2-4). Wenn nicht, dann ENTER oder W=weiter eingeben" -ForegroundColor DarkGray
    $sel = Read-Host "Auswahl"
    if ([string]::IsNullOrWhiteSpace($sel) -or $sel -match '^[Ww]$') { return $allItems }

    $tokens = $sel -split '[,; ]+' | Where-Object { $_ -match '\S' }
    $numbers = New-Object System.Collections.Generic.List[int]
    foreach ($t in $tokens) {
        if ($t -match '^\d+$') { $numbers.Add([int]$t) }
        elseif ($t -match '^(\d+)-(\d+)$') { $from = [int]$matches[1]; $to = [int]$matches[2]; if ($from -le $to) { $from..$to | ForEach-Object { $numbers.Add($_) } } }
    }

    foreach ($n in ($numbers | Select-Object -Unique | Where-Object { $_ -ge 1 -and $_ -le $allItems.Count })) {
        $item = $allItems[$n - 1]
        if ($item.Kind -eq 'Windows') {
            if ($ExcludeConfig.Value.WindowsKB -contains $item.Key) {
                $ExcludeConfig.Value.WindowsKB = @($ExcludeConfig.Value.WindowsKB | Where-Object { $_ -ne $item.Key }); $item.Excluded = $false
                Write-Host (" - {0} von Ausschlussliste entfernt" -f $item.Title) -ForegroundColor Green
            }
            else {
                $ExcludeConfig.Value.WindowsKB += $item.Key; $ExcludeConfig.Value.WindowsKB = $ExcludeConfig.Value.WindowsKB | Select-Object -Unique; $item.Excluded = $true
                Write-Host (" + {0} zur Ausschlussliste hinzugefügt" -f $item.Title) -ForegroundColor Yellow
            }
        }
        else {
            if ($ExcludeConfig.Value.WingetIDs -contains $item.Key) {
                $ExcludeConfig.Value.WingetIDs = @($ExcludeConfig.Value.WingetIDs | Where-Object { $_ -ne $item.Key }); $item.Excluded = $false
                Write-Host (" - {0} von Ausschlussliste entfernt" -f $item.Title) -ForegroundColor Green
            }
            else {
                $ExcludeConfig.Value.WingetIDs += $item.Key; $ExcludeConfig.Value.WingetIDs = $ExcludeConfig.Value.WingetIDs | Select-Object -Unique; $item.Excluded = $true
                Write-Host (" + {0} zur Ausschlussliste hinzugefügt" -f $item.Title) -ForegroundColor Yellow
            }
        }
    }
    Set-ExcludeConfig $ExcludeConfig.Value
    return $allItems
}

# --- Windows Updates -----------------------------------------------------------

function Find-WindowsUpdates {
    if (-not (Import-PSWindowsUpdateOrExplain)) { return @() }
    try {
        Write-Progress -Activity "Windows Updates" -Status "Suche nach verfügbaren Updates..." -PercentComplete 0
        
        # Direkter Aufruf ohne Job - einfacher und zuverlässiger
        $list = Get-WindowsUpdate -MicrosoftUpdate
        
        Write-Progress -Activity "Windows Updates" -Status "Verarbeite gefundene Updates..." -PercentComplete 50
        $out = @(); foreach ($u in $list) {
            $kb = $u.KB; if ([string]::IsNullOrWhiteSpace($kb)) { $kb = $u.Title }
            $extra = if ($u.KB) { "(KB: $($u.KB))" }else { "" }
            $out += [pscustomobject]@{ Key = $kb; Title = $u.Title; Extra = $extra; Raw = $u }
        }
        Write-Progress -Activity "Windows Updates" -Status "Abgeschlossen" -PercentComplete 100
        Start-Sleep -Milliseconds 500
        Write-Progress -Activity "Windows Updates" -Completed
        return $out
    }
    catch { 
        Write-Progress -Activity "Windows Updates" -Completed
        Write-Host "!!! Fehler beim Abfragen der Windows-Updates: $($_.Exception.Message)" -ForegroundColor Red; "!!! Fehler Get-WindowsUpdate: $($_.Exception.Message)" | Out-File $LogFile -Append; return @() 
    }
}
function Invoke-WindowsUpdateInstall {
    param([switch]$AutoReboot, [array]$Allowed)
    if (-not (Import-PSWindowsUpdateOrExplain)) { return }
    if (-not (Test-Admin)) { Write-Host "Adminrechte nötig. Bitte als Administrator erneut ausführen." -ForegroundColor Yellow; "Abbruch: Keine Adminrechte (Windows)" | Out-File $LogFile -Append; return }
    try {
        $allowedKBs = $Allowed | Where-Object { $_ -match '^\d{4,}$' }
        if ($allowedKBs.Count -gt 0) {
            Write-Progress -Activity "Windows Update Installation" -Status "Installiere ausgewählte Updates ($($allowedKBs.Count) Updates)..." -PercentComplete 25
            $installParams = @{KBArticleID = $allowedKBs; AcceptAll = $true }
            if ($AutoReboot) { $installParams.AutoReboot = $true }else { $installParams.IgnoreReboot = $true }
            Install-WindowsUpdate @installParams | Tee-Object -FilePath $LogFile -Append | Out-Null
        }
        else {
            Write-Progress -Activity "Windows Update Installation" -Status "Installiere alle verfügbaren Updates..." -PercentComplete 25
            if ($AutoReboot) { Install-WindowsUpdate -AcceptAll -AutoReboot | Tee-Object -FilePath $LogFile -Append | Out-Null }
            else { Install-WindowsUpdate -AcceptAll -IgnoreReboot | Tee-Object -FilePath $LogFile -Append | Out-Null }
        }
        Write-Progress -Activity "Windows Update Installation" -Status "Prüfe Neustart-Anforderungen..." -PercentComplete 90
        if (-not $AutoReboot) { $reboot = Get-WURebootStatus; if ($reboot -and $reboot.RebootRequired) { Write-Host "↻ Neustart erforderlich/empfohlen." -ForegroundColor Yellow } }
        Write-Progress -Activity "Windows Update Installation" -Status "Abgeschlossen" -PercentComplete 100
        Start-Sleep -Milliseconds 500
        Write-Progress -Activity "Windows Update Installation" -Completed
        Write-Host "✅ Windows Updates: Installation abgeschlossen." -ForegroundColor Green
    }
    catch { 
        Write-Progress -Activity "Windows Update Installation" -Completed
        Write-Host "!!! Fehler bei der Windows-Installation: $($_.Exception.Message)" -ForegroundColor Red; "!!! Fehler Install-WindowsUpdate: $($_.Exception.Message)" | Out-File $LogFile -Append 
    }
}

# --- Software (winget) ---------------------------------------------------------

function Find-SoftwareUpdates {
    if (-not (Test-WingetPresent)) {
        Write-Host "!! winget nicht verfügbar. Installiere/aktualisiere den *App-Installer* (Microsoft Store)." -ForegroundColor Red
        "!!! Fehler: winget fehlte." | Out-File $LogFile -Append; return @()
    }

    Write-Progress -Activity "Software Updates" -Status "Initialisiere winget Suche..." -PercentComplete 0

    # Helper: JSON lesen, sonst Text-Fallback
    function Get-WingetUpgradesJson([string]$scope) {
        try {
            $wingetArgs = @('upgrade', '--include-unknown')
            if (-not [string]::IsNullOrWhiteSpace($scope)) { $wingetArgs += '--scope', $scope }
            $wingetArgs += '--output', 'json'
      
            $raw = & winget $wingetArgs | Out-String
            if (-not [string]::IsNullOrWhiteSpace($raw)) {
                $json = $raw | ConvertFrom-Json
                if ($json -and $json.PSObject.Properties['Data'] -and $json.Data) { 
                    return , $json.Data 
                }
                elseif ($json) { 
                    return , $json 
                }
            }
            return @()
        }
        catch { 
            return @() 
        }
    }
    function Get-WingetUpgradesText([string]$scope) {
        try {
            $wingetArgs = @('upgrade', '--include-unknown')
            if (-not [string]::IsNullOrWhiteSpace($scope)) { $wingetArgs += '--scope', $scope }
      
            $txt = & winget $wingetArgs
            if (-not $txt) { return @() }
      
            $lines = $txt -split "`r?`n" | Where-Object { $_ -match '\S' }
      
            # Filtere Header und Footerlines heraus
            $filteredLines = $lines | Where-Object { 
                $_ -notmatch '^Name\s+Id\s+Version' -and 
                $_ -notmatch '^-{3,}' -and 
                $_ -notmatch '\d+\s+upgrades available' -and 
                $_ -notmatch 'The following packages' -and
                $_ -notmatch '^\s*-\s*$' -and
                $_ -notmatch '^\s*$'
            }
      
            $out = @()
            foreach ($ln in $filteredLines) {
                # Verbesserte Regex für winget Ausgabe - die Spalten sind durch mehrere Leerzeichen getrennt
                # Format: Name    Id    Version    Available    Source
                if ($ln -match '^\s*(.+?)\s{2,}([^\s]+)\s{2,}([^\s]+)\s{2,}([^\s]+)\s{2,}([^\s]+)\s*$') {
                    $name = $matches[1].Trim()
                    $id = $matches[2].Trim()
                    $currentVer = $matches[3].Trim()
                    $availableVer = $matches[4].Trim()
                    $source = $matches[5].Trim()
          
                    if ($id -and $id -ne 'Id' -and $currentVer -ne 'Version' -and $source -eq 'winget') {
                        $out += [pscustomobject]@{ 
                            Id               = $id; 
                            Name             = $name; 
                            Version          = $currentVer; 
                            AvailableVersion = $availableVer; 
                            Source           = 'winget' 
                        }
                    }
                }
            }
            return $out
        }
        catch { 
            return @() 
        }
    }

    # Zuerst ohne Scope versuchen (wie der direkte Befehl), dann mit Scopes
    $all = @()
  
    # Ohne Scope (wie direkter winget upgrade --include-unknown Befehl)
    Write-Progress -Activity "Software Updates" -Status "Suche nach Updates (Standard-Scope)..." -PercentComplete 25
    $part = Get-WingetUpgradesJson ""
    if (-not $part -or $part.Count -eq 0) { 
        $part = Get-WingetUpgradesText "" 
    }
    $all += $part
  
    # Falls keine Ergebnisse, versuche mit spezifischen Scopes
    if ($all.Count -eq 0) {
        $scopeIndex = 0
        foreach ($scope in @('user', 'machine')) {
            $scopeIndex++
            Write-Progress -Activity "Software Updates" -Status "Suche nach Updates ($scope Scope)..." -PercentComplete (25 + ($scopeIndex * 20))
            $part = Get-WingetUpgradesJson $scope
            if (-not $part -or $part.Count -eq 0) { $part = Get-WingetUpgradesText $scope }
            $all += $part
        }
    }

    # Zu anzeigbaren Objekten mappen und doppelte Ids entfernen
    Write-Progress -Activity "Software Updates" -Status "Verarbeite gefundene Updates..." -PercentComplete 70
    $map = @{}
    foreach ($p in $all) {
        $id = $null
        $name = $null
        $ver = $null
        $av = $null
    
        # JSON-Format aus winget (neuere Versionen)
        if ($p.PSObject.Properties['PackageIdentifier']) {
            $id = $p.PackageIdentifier
            $name = if ($p.PSObject.Properties['Name']) { $p.Name } else { $p.PackageIdentifier }
            $ver = if ($p.PSObject.Properties['InstalledVersion']) { $p.InstalledVersion } else { 'Unknown' }
            $av = if ($p.PSObject.Properties['AvailableVersion']) { $p.AvailableVersion } else { '' }
        }
        # Text-Format oder ältere JSON-Struktur
        elseif ($p.Id) {
            $id = $p.Id
            $name = if ($p.Name) { $p.Name } else { $p.Id }
            $ver = if ($p.Version) { $p.Version } else { 'Unknown' }
            $av = if ($p.AvailableVersion) { $p.AvailableVersion } else { '' }
        }
        # Legacy-Format
        else {
            $id = if ($p.PSObject.Properties['Id']) { $p.Id } else { $null }
            $name = if ($p.PSObject.Properties['Name']) { $p.Name } else { $id }
            $ver = if ($p.PSObject.Properties['Version']) { $p.Version } else { 'Unknown' }
            $av = if ($p.PSObject.Properties['AvailableVersion']) { $p.AvailableVersion } else { '' }
        }
    
        if ($id -and $id -ne 'Id') {
            $title = "$name ($id)  $ver -> $av"
            $map[$id] = [pscustomobject]@{ Key = $id; Title = $title; Extra = ''; Raw = $p }
        }
    }
  
    Write-Progress -Activity "Software Updates" -Status "Abgeschlossen" -PercentComplete 100
    Start-Sleep -Milliseconds 500
    Write-Progress -Activity "Software Updates" -Completed
    return $map.Values
}

function Invoke-SoftwareUpdateInstall {
    param([array]$AllowedIds)
    if (-not (Test-WingetPresent)) { return }
    if (-not (Test-Admin)) { Write-Host "Adminrechte empfohlen/erforderlich für Software-Updates." -ForegroundColor Yellow; "Abbruch: Keine Adminrechte (Software)" | Out-File $LogFile -Append; return }
    try {
        if ($AllowedIds -and $AllowedIds.Count -gt 0) {
            $totalCount = $AllowedIds.Count
            $currentCount = 0
            foreach ($id in $AllowedIds) {
                $currentCount++
                $percent = [math]::Round(($currentCount / $totalCount) * 100)
                Write-Progress -Activity "Software Installation" -Status "Installiere $id ($currentCount von $totalCount)" -PercentComplete $percent
                winget upgrade --id $id --accept-source-agreements --accept-package-agreements `
                | Tee-Object -FilePath $LogFile -Append | Out-Null
            }
        }
        else {
            Write-Progress -Activity "Software Installation" -Status "Installiere alle verfügbaren Updates..." -PercentComplete 50
            $excludeArg = if ($Excl.WingetIDs.Count -gt 0) { "--exclude $($Excl.WingetIDs -join ',')" } else { "" }
            winget upgrade --all --accept-source-agreements --accept-package-agreements $excludeArg `
            | Tee-Object -FilePath $LogFile -Append | Out-Null
        }
        Write-Progress -Activity "Software Installation" -Status "Abgeschlossen" -PercentComplete 100
        Start-Sleep -Milliseconds 500
        Write-Progress -Activity "Software Installation" -Completed
        Write-Host "✅ Software Updates: Installation abgeschlossen." -ForegroundColor Green
    }
    catch { 
        Write-Progress -Activity "Software Installation" -Completed
        Write-Host "!!! Fehler bei der Software-Installation: $($_.Exception.Message)" -ForegroundColor Red; "!!! Fehler winget upgrade: $($_.Exception.Message)" | Out-File $LogFile -Append 
    }
}

function Show-ExcludeMenu {
    do {
        Write-Host ""
        Write-Host "-------------- Ausschlussliste ---------------" -ForegroundColor Cyan
        Write-Host "WindowsKB : $($Excl.WindowsKB -join ', ')" -ForegroundColor Gray
        Write-Host "WingetIDs : $($Excl.WingetIDs -join ', ')" -ForegroundColor Gray
        Write-Host "----------------------------------------------" -ForegroundColor Cyan
        Write-Host "1) Eintrag hinzufügen (WindowsKB oder WingetID)"
        Write-Host "2) Eintrag entfernen"
        Write-Host "3) Exportieren nach Datei (JSON)"
        Write-Host "4) Importieren aus Datei (JSON)"
        Write-Host "5) Zurück zum Hauptmenü"
        $sel = Read-Host "Auswahl (1-5)"

        switch ($sel) {
            '1' {
                $type = Read-Host "Typ wählen: W=WindowsKB / S=Software-ID"
                $val = Read-Host "Wert eingeben (KB-Nummer oder exakte Winget-ID)"
                if ([string]::IsNullOrWhiteSpace($val)) { continue }
                if ($type -match '^[Ww]$') {
                    if ($Excl.WindowsKB -notcontains $val) { $Excl.WindowsKB += $val; $Excl.WindowsKB = $Excl.WindowsKB | Select-Object -Unique }
                }
                elseif ($type -match '^[Ss]$') {
                    if ($Excl.WingetIDs -notcontains $val) { $Excl.WingetIDs += $val; $Excl.WingetIDs = $Excl.WingetIDs | Select-Object -Unique }
                }
                Set-ExcludeConfig $Excl
            }
            '2' {
                $type = Read-Host "Typ wählen: W=WindowsKB / S=Software-ID"
                $val = Read-Host "Welchen Wert entfernen?"
                if ([string]::IsNullOrWhiteSpace($val)) { continue }
                if ($type -match '^[Ww]$') { $Excl.WindowsKB = @($Excl.WindowsKB | Where-Object { $_ -ne $val }) }
                elseif ($type -match '^[Ss]$') { $Excl.WingetIDs = @($Excl.WingetIDs | Where-Object { $_ -ne $val }) }
                Set-ExcludeConfig $Excl
            }
            '3' {
                $path = Read-Host "Exportpfad (z.B. C:\Logs\MeineExcludes.json)"
                if (-not [string]::IsNullOrWhiteSpace($path)) { Set-ExcludeConfig $Excl; Copy-Item $ExcludePath $path -Force; Write-Host "Export abgeschlossen." -ForegroundColor Green }
            }
            '4' {
                $path = Read-Host "Importpfad (z.B. C:\Logs\MeineExcludes.json)"
                if (Test-Path $path) {
                    try {
                        $tmp = Get-Content $path -Raw | ConvertFrom-Json
                        if ($tmp.WindowsKB -and $tmp.WingetIDs) { $global:Excl = $tmp; Set-ExcludeConfig $Excl; Write-Host "Import erfolgreich." -ForegroundColor Green }
                        else { Write-Host "Ungültiges Format." -ForegroundColor Red }
                    }
                    catch { Write-Host "!!! Fehler beim Import: $($_.Exception.Message)" -ForegroundColor Red }
                }
                else { Write-Host "Datei nicht gefunden." -ForegroundColor Red }
            }
            '5' { $global:Excl = $Excl; return }   # <- wirklich zurück zum Hauptmenü
            default { Write-Host "Ungültige Eingabe." -ForegroundColor Red }
        }
    } while ($true)
}

# --- Menü ----------------------------------------------------------------------

function Show-Menu {
    Write-Host ""
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "   System Update Check Menü     " -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "1) Windows Updates prüfen/installieren"
    Write-Host "2) Software Updates (winget) prüfen/installieren"
    Write-Host "3) Alles prüfen (Windows + Software) – gruppiert prüfen/installieren"
    Write-Host "4) Ausschlussliste anzeigen/bearbeiten/exportieren/importieren"
    Write-Host "Q) Programm beenden (Quit)"
    Write-Host "===============================" -ForegroundColor Cyan
}

# --- Hauptloop -----------------------------------------------------------------
do {
    Show-Menu
    $choice = Read-Host "Bitte Auswahl (1-4 oder Q)"

    switch ($choice) {
        "1" {
            Write-Section "Windows Updates verfügbar:"
            $win = Find-WindowsUpdates
            if ($win.Count -gt 0) {
                $win = Show-NumberedList -Items $win -Kind 'Windows' -ExcludeConfig ([ref]$Excl)
                $allowed = $win | Where-Object { -not $_.Excluded } | Select-Object -ExpandProperty Key
                if ($allowed.Count -gt 0 -and (Read-Host "Sollen die NICHT ausgeschlossenen Windows-Updates installiert werden? (J/N)") -match '^(J|j)$') {
                    $auto = (Read-Host "Bei Bedarf automatisch neu starten? (J/N)") -match '^(J|j)$'
                    Invoke-WindowsUpdateInstall -AutoReboot:$auto -Allowed $allowed
                }
                elseif ($allowed.Count -eq 0) {
                    Write-Host "Alles für Windows steht auf der Ausschlussliste. Nichts zu installieren." -ForegroundColor Yellow
                }
            }
            else { Write-Host "Keine Windows Updates verfügbar." -ForegroundColor Yellow }
        }

        "2" {
            Write-Section "Software Updates verfügbar:"
            $sw = Find-SoftwareUpdates
            if ($sw.Count -gt 0) {
                $sw = Show-NumberedList -Items $sw -Kind 'Software' -ExcludeConfig ([ref]$Excl)
                $allowedIds = $sw | Where-Object { -not $_.Excluded } | Select-Object -ExpandProperty Key
                if ($allowedIds.Count -gt 0 -and (Read-Host "Sollen die NICHT ausgeschlossenen Software-Updates installiert werden? (J/N)") -match '^(J|j)$') {
                    Invoke-SoftwareUpdateInstall -AllowedIds $allowedIds
                }
                elseif ($allowedIds.Count -eq 0) {
                    Write-Host "Alles für Software steht auf der Ausschlussliste. Nichts zu installieren." -ForegroundColor Yellow
                }
            }
            else { Write-Host "Keine Software Updates verfügbar." -ForegroundColor Yellow }
        }

        "3" {
            Write-Section "Verfügbare Updates (Windows + Software):"
            Write-Host "Suche nach Windows Updates..." -ForegroundColor Gray
            $win = Find-WindowsUpdates
            Write-Host "Suche nach Software Updates..." -ForegroundColor Gray
            $sw = Find-SoftwareUpdates

            # Verwende die neue kombinierte Anzeige-Funktion
            $allUpdates = Show-CombinedUpdateList -WindowsItems $win -SoftwareItems $sw -ExcludeConfig ([ref]$Excl)

            # Filtere erlaubte Updates aus der kombinierten Liste
            $allowedKBs = $allUpdates | Where-Object { $_.Kind -eq 'Windows' -and (-not $_.Excluded) } | Select-Object -ExpandProperty Key
            $allowedIDs = $allUpdates | Where-Object { $_.Kind -eq 'Software' -and (-not $_.Excluded) } | Select-Object -ExpandProperty Key

            if (($allowedKBs.Count -gt 0) -or ($allowedIDs.Count -gt 0)) {
                if ((Read-Host "`nSollen alle NICHT ausgeschlossenen Updates installiert werden? (J/N)") -match '^(J|j)$') {
                    if ($allowedKBs.Count -gt 0) {
                        $auto = (Read-Host "Bei Bedarf automatisch neu starten? (J/N)") -match '^(J|j)$'
                        Invoke-WindowsUpdateInstall -AutoReboot:$auto -Allowed $allowedKBs
                    }
                    if ($allowedIDs.Count -gt 0) { Invoke-SoftwareUpdateInstall -AllowedIds $allowedIDs }
                    Write-Host "✅ Updates erfolgreich!" -ForegroundColor Green
                }
                else { Write-Host "Abgebrochen. Es wurden keine Updates installiert." -ForegroundColor Yellow }
            }
            else { Write-Host "`nAlles auf der Ausschlussliste – nichts zu installieren." -ForegroundColor Yellow }
        }

        "4" { Show-ExcludeMenu }
        { $_ -match '^[Qq]$' } { return }  # <- Programm beenden mit Q/q
        default { Write-Host "Ungültige Eingabe. Bitte 1–4 oder Q wählen." -ForegroundColor Red }
    }
} while ($true)

# --- Abschluss ----------------------------------------------------------------
$end = "=== Update-Check beendet: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
Write-Host $end -ForegroundColor Cyan
$end | Out-File $LogFile -Append