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
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'
$PSDefaultParameterValues['Set-Content:Encoding'] = 'utf8'

# Zentrales UTF-8 Logging (vermeidet "gespacte" Zeichen aus Unicode/UTF-16)
function Write-Log {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        [string]$Text
    )
    process {
        if ($null -ne $Text) {
            Add-Content -Path $LogFile -Value $Text -Encoding UTF8
        }
    }
}
$ExcludePath = Join-Path $LogDir 'UpdateExcludes.json'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
"=== Update-Check gestartet: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (PS $($PSVersionTable.PSVersion)) ===" | Out-File $LogFile -Append -Encoding utf8

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
        Import-Module PSWindowsUpdate -ErrorAction Stop -Force
        
        # Zusätzliche Prüfung: Stelle sicher dass die wichtigsten Cmdlets verfügbar sind
        $requiredCmdlets = @('Get-WindowsUpdate', 'Get-WURebootStatus')
        foreach ($cmdlet in $requiredCmdlets) {
            if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
                throw "Cmdlet $cmdlet nicht verfügbar nach Import"
            }
        }
        
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
                    Import-Module $fullPath -ErrorAction Stop -Force
                    
                    # Prüfe wieder die Cmdlets
                    $requiredCmdlets = @('Get-WindowsUpdate', 'Get-WURebootStatus')
                    $allAvailable = $true
                    foreach ($cmdlet in $requiredCmdlets) {
                        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
                            $allAvailable = $false
                            break
                        }
                    }
                    
                    if ($allAvailable) {
                        #Write-Host "PSWindowsUpdate erfolgreich importiert aus: $fullPath" -ForegroundColor Green
                        return $true
                    }
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

    while ($true) {
        $i = 0
        foreach ($it in $Items) {
            $i++
            $isExcluded = if ($Kind -eq 'Windows') { $ExcludeConfig.Value.WindowsKB -contains $it.Key } else { $ExcludeConfig.Value.WingetIDs -contains $it.Key }
            $it | Add-Member Number $i -Force
            $it | Add-Member Excluded $isExcluded -Force
            $mark = if ($isExcluded) { '[X]' } else { '[ ]' }
            Write-Host ("{0,2}. {1} {2}  {3}" -f $i, $mark, $it.Title, $it.Extra)
        }

        Write-Host ""
        Write-Host "(Mit X markierte Updates stehen auf Ausschlussliste)" -ForegroundColor DarkGray
        Write-Host "Sollen Einträge auf Ausschlussliste eingetragen/entfernt werden?" -ForegroundColor DarkGray
        Write-Host "Wenn ja, dann Nummer(n) (z.B. 1,3,5 oder 2-4)." -ForegroundColor DarkGray
        Write-Host "Wenn nicht, dann weiter=W/ENTER eingeben." -ForegroundColor DarkGray

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
        # Schleife fortsetzen, um weiteres Togglen zu erlauben
    }
}

# --- Kombinierte Anzeige für Option 3 (Windows + Software zusammen) -----------
function Show-CombinedUpdateList {
    param([array]$WindowsItems, [array]$SoftwareItems, [ref]$ExcludeConfig)
    
    while ($true) {
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
        Write-Host "(Mit X markierte Updates stehen auf Ausschlussliste)" -ForegroundColor DarkGray
        Write-Host "Sollen Einträge auf Ausschlussliste eingetragen/entfernt werden?" -ForegroundColor DarkGray
        Write-Host "Wenn ja, dann Nummer(n) (z.B. 1,3,5 oder 2-4)." -ForegroundColor DarkGray
        Write-Host "Wenn nicht, dann Weiter=W/ENTER eingeben." -ForegroundColor DarkGray

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
        # Schleife fortsetzen, damit weiteres Togglen möglich ist
    }
}

# --- Auswahl der zu installierenden Updates (A/K/Nummern) ---------------------
function Select-InstallSelection {
    param(
        [Parameter(Mandatory = $true)][array]$Items,
        [string]$Prompt = "Was installieren? Alle=A, Keine=K/Enter oder Nummern (z.B. 1,3,5 oder 2-4)"
    )

    if (-not $Items -or $Items.Count -eq 0) { return @() }

    $inputUpdates = Read-Host $Prompt
    if ([string]::IsNullOrWhiteSpace($inputUpdates) -or $inputUpdates -match '^[Kk]$') { return @() }
    if ($inputUpdates -match '^[Aa]$') {
        return @($Items | Where-Object { -not $_.Excluded })
    }

    $tokens = $inputUpdates -split '[,; ]+' | Where-Object { $_ -match '\S' }
    $numbers = New-Object System.Collections.Generic.List[int]
    foreach ($t in $tokens) {
        if ($t -match '^\d+$') { $numbers.Add([int]$t) }
        elseif ($t -match '^(\d+)-(\d+)$') {
            $from = [int]$matches[1]; $to = [int]$matches[2]
            if ($from -le $to) { $from..$to | ForEach-Object { $numbers.Add($_) } }
        }
    }

    $picked = @()
    $skipped = @()
    foreach ($n in ($numbers | Select-Object -Unique | Where-Object { $_ -ge 1 -and $_ -le $Items.Count })) {
        $it = $Items[$n - 1]
        if ($it.Excluded) { $skipped += $it }
        else { $picked += $it }
    }
    if ($skipped.Count -gt 0) {
        Write-Host ("Hinweis: {0} ausgewählte(r) Eintrag/Einträge wurden übersprungen (auf Ausschlussliste)." -f $skipped.Count) -ForegroundColor DarkYellow
    }
    return $picked
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
    
    # Zusätzliche Prüfung: Stelle sicher, dass Get-WindowsUpdate verfügbar ist
    if (-not (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue)) {
        Write-Host "Get-WindowsUpdate Cmdlet nicht verfügbar. PSWindowsUpdate Modul nicht korrekt geladen." -ForegroundColor Red
        "!!! Fehler: Get-WindowsUpdate Cmdlet nicht verfügbar" | Out-File $LogFile -Append
        return
    }
    
    try {
        # Extrahiere numerische KB-IDs aus übergebenen Keys (unterstützt z.B. "KB2267602" -> 2267602)
        $allowedKBs = @()
        foreach ($a in ($Allowed | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            if ($a -match '(\d{4,})') { $allowedKBs += $matches[1] }
        }
        # Wenn eine Auswahl übergeben wurde, aber keine gültigen KB-IDs erkannt wurden, NICHT alle installieren
        if ($Allowed -and $Allowed.Count -gt 0 -and ($null -eq $allowedKBs -or $allowedKBs.Count -eq 0)) {
            Write-Host "Keine gültigen KB-IDs in der Auswahl erkannt – Windows-Installation übersprungen." -ForegroundColor Yellow
            "Hinweis: Windows-Install übersprungen, keine gültigen KB-IDs in Auswahl: $($Allowed -join ', ')" | Out-File $LogFile -Append
            return
        }
        $iwObjs = @()
        if ($allowedKBs.Count -gt 0) {
            Write-Progress -Activity "Windows Update Installation" -Status "Installiere ausgewählte Updates ($($allowedKBs.Count) Updates)..." -PercentComplete 25
            $installParams = @{KBArticleID = $allowedKBs; AcceptAll = $true; Install = $true }
            if ($AutoReboot) { $installParams.AutoReboot = $true } else { $installParams.IgnoreReboot = $true }
            $iwObjs = Get-WindowsUpdate @installParams
            ($iwObjs | Out-String) | Write-Log | Out-Null
        }
        else {
            Write-Progress -Activity "Windows Update Installation" -Status "Installiere alle verfügbaren Updates..." -PercentComplete 25
            if ($AutoReboot) { $iwObjs = Get-WindowsUpdate -AcceptAll -Install -AutoReboot }
            else { $iwObjs = Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot }
            ($iwObjs | Out-String) | Write-Log | Out-Null
        }
        Write-Progress -Activity "Windows Update Installation" -Status "Prüfe Neustart-Anforderungen..." -PercentComplete 90
        if (-not $AutoReboot) { $reboot = Get-WURebootStatus; if ($reboot -and $reboot.RebootRequired) { Write-Host "↻ Neustart erforderlich/empfohlen." -ForegroundColor Yellow } }
        Write-Progress -Activity "Windows Update Installation" -Status "Abgeschlossen" -PercentComplete 100
        Start-Sleep -Milliseconds 500
        Write-Progress -Activity "Windows Update Installation" -Completed
        # Zusammenfassung Windows (erfolgreich/fehlgeschlagen)
        try {
            $succWU = @()
            $failWU = @()
            foreach ($o in ($iwObjs | Where-Object { $_ })) {
                $nameWU = if ($o.PSObject.Properties['Title'] -and $o.Title) { $o.Title } elseif ($o.PSObject.Properties['KB'] -and $o.KB) { "KB$($o.KB)" } else { ($o | Out-String).Trim() }
                $isSuccess = ($o.PSObject.Properties['Result'] -and ($o.Result -match 'Success|Succeeded|Installed|OK')) -or ($o.PSObject.Properties['Status'] -and ($o.Status -match 'Success|Installed|OK'))
                $isFail = ($o.PSObject.Properties['Result'] -and ($o.Result -match 'Fail|Error')) -or ($o.PSObject.Properties['Status'] -and ($o.Status -match 'Fail|Error'))
                if ($isSuccess) { $succWU += $nameWU }
                elseif ($isFail) { $failWU += $nameWU }
            }
            # Entferne Duplikate
            $succWU = $succWU | Select-Object -Unique
            $failWU = $failWU | Select-Object -Unique
            
            Write-Host "Updates erfolgreich:" -ForegroundColor Green
            if ($succWU -and $succWU.Count -gt 0) { $succWU | ForEach-Object { Write-Host " - $_" -ForegroundColor Green } } else { Write-Host " - Keine" -ForegroundColor DarkGreen }
            Write-Host "Updates fehlgeschlagen:" -ForegroundColor Red
            if ($failWU -and $failWU.Count -gt 0) { $failWU | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow } } else { Write-Host " - Keine" -ForegroundColor DarkYellow }
        }
        catch { }
        Write-Host "Windows Updates: Installation abgeschlossen." -ForegroundColor Green
    }
    catch { 
        Write-Progress -Activity "Windows Update Installation" -Completed
        Write-Host "!!! Fehler bei der Windows-Installation: $($_.Exception.Message)" -ForegroundColor Red; "!!! Fehler Install-WindowsUpdate: $($_.Exception.Message)" | Out-File $LogFile -Append 
    }
}

# --- Software (winget) ---------------------------------------------------------

function Find-SoftwareUpdates {
    if (-not (Test-WingetPresent)) {
        Write-Host "! winget nicht verfügbar. Installiere/aktualisiere den *App-Installer* (Microsoft Store)." -ForegroundColor Red
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
    param(
        [array]$AllowedIds,
        [hashtable]$NameById
    )
    if (-not (Test-WingetPresent)) { return }
    if (-not (Test-Admin)) { Write-Host "Adminrechte empfohlen/erforderlich für Software-Updates." -ForegroundColor Yellow; "Abbruch: Keine Adminrechte (Software)" | Out-File $LogFile -Append; return }
    try {
        # Einmalige Aktualisierung der winget-Quellen bei Hash-Mismatch, dann Retry
        if (-not (Get-Variable -Name WingetSourceRefreshed -Scope Script -ErrorAction SilentlyContinue)) { $script:WingetSourceRefreshed = $false }
        $results = New-Object System.Collections.Generic.List[object]

        function Invoke-WingetUpgradeOnce([string]$pkgId) {
            $wingetCmdArgs = @('upgrade', '--id', $pkgId, '--exact', '--source', 'winget', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity')
            $outPath = Join-Path $LogDir "winget-$($pkgId)-out.log"
            $errPath = Join-Path $LogDir "winget-$($pkgId)-err.log"
            $proc = Start-Process -FilePath 'winget' -ArgumentList $wingetCmdArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outPath -RedirectStandardError $errPath
            if (Test-Path $outPath) { Get-Content $outPath | Out-File $LogFile -Append }
            if (Test-Path $errPath) { Get-Content $errPath | Out-File $LogFile -Append }
            $outText = if (Test-Path $outPath) { Get-Content $outPath -Raw } else { '' }
            $errText = if (Test-Path $errPath) { Get-Content $errPath -Raw } else { '' }
            $noUpdatePatterns = @(
                'No applicable update found',
                'No installed package found',
                'ist nicht installiert',
                'keine.*aktualisierung',
                'keine.*updates.*verfügbar'
            )
            $hashMismatch = ($outText -match 'Installer-Hash.*stimmt.*nicht' -or $errText -match 'Installer-Hash.*stimmt.*nicht' -or $outText -match 'Installer hash' -or $errText -match 'Installer hash' -or $proc.ExitCode -eq -1978335215)
            $noUpdate = ($noUpdatePatterns | ForEach-Object { $outText -match $_ -or $errText -match $_ } | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count)
            return [pscustomobject]@{
                Id           = $pkgId
                ExitCode     = $proc.ExitCode
                OutText      = $outText
                ErrText      = $errText
                HashMismatch = [bool]$hashMismatch
                NoUpdate     = [bool]($noUpdate -gt 0)
                Success      = ($proc.ExitCode -eq 0 -and -not $hashMismatch -and -not ($noUpdate -gt 0))
            }
        }
        if ($AllowedIds -and $AllowedIds.Count -gt 0) {
            $totalCount = $AllowedIds.Count
            $currentCount = 0
            foreach ($id in $AllowedIds) {
                $currentCount++
                $percent = [math]::Round(($currentCount / $totalCount) * 100)
                Write-Progress -Activity "Software Installation" -Status "Installiere $id ($currentCount von $totalCount)" -PercentComplete $percent
                try {
                    $res = Invoke-WingetUpgradeOnce -pkgId $id
                    if ($res.HashMismatch -and -not $script:WingetSourceRefreshed) {
                        Write-Host "↻ Aktualisiere winget-Quellen einmalig (winget source update)..." -ForegroundColor DarkYellow
                        try { & winget source update | Out-Null } catch {}
                        $script:WingetSourceRefreshed = $true
                        $res = Invoke-WingetUpgradeOnce -pkgId $id
                    }

                    $pkgName = if ($NameById -and $NameById.ContainsKey($id)) { $NameById[$id] } else { $id }
                    if ($res.ExitCode -ne 0 -and $res.HashMismatch) {
                        Write-Host "${id}: Installer-Hash stimmt nicht. Manifest vermutlich veraltet. Führen Sie 'winget source update' aus und versuchen Sie es später erneut oder setzen Sie das Paket vorübergehend auf die Ausschlussliste." -ForegroundColor Yellow
                        $ans = Read-Host "${id} jetzt zur Ausschlussliste hinzufügen? (J/N)"
                        if ($ans -match '^(J|j)$') { $Excl.WingetIDs += $id; $Excl.WingetIDs = $Excl.WingetIDs | Select-Object -Unique; Set-ExcludeConfig $Excl; Write-Host "${id} auf Ausschlussliste gesetzt." -ForegroundColor Yellow }
                        "Hinweis: ${id} – Installer-Hash-Mismatch erkannt (ExitCode $($res.ExitCode))." | Out-File $LogFile -Append
                        $results.Add([pscustomobject]@{Id = $id; Name = $pkgName; Status = 'HashMismatch'; ExitCode = $res.ExitCode }) | Out-Null
                    }
                    elseif ($res.NoUpdate) {
                        Write-Host "ℹ︎ ${id}: Keine Aktualisierung durchgeführt (laut winget)." -ForegroundColor Yellow
                        $results.Add([pscustomobject]@{Id = $id; Name = $pkgName; Status = 'NoUpdate'; ExitCode = $res.ExitCode }) | Out-Null
                    }
                    elseif ($res.Success) {
                        Write-Host "✓ ${id}: Upgrade abgeschlossen" -ForegroundColor Green
                        $results.Add([pscustomobject]@{Id = $id; Name = $pkgName; Status = 'Success'; ExitCode = $res.ExitCode }) | Out-Null
                    }
                    else {
                        Write-Host "${id}: Upgrade fehlgeschlagen (ExitCode $($res.ExitCode)). Siehe Log." -ForegroundColor Red
                        $results.Add([pscustomobject]@{Id = $id; Name = $pkgName; Status = 'Failed'; ExitCode = $res.ExitCode }) | Out-Null
                    }
                }
                catch {
                    Write-Host "${id}: winget-Aufruf fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red
                    "!!! Fehler winget ($id): $($_.Exception.Message)" | Out-File $LogFile -Append
                    $pkgName = if ($NameById -and $NameById.ContainsKey($id)) { $NameById[$id] } else { $id }
                    $results.Add([pscustomobject]@{Id = $id; Name = $pkgName; Status = 'Exception'; ExitCode = $null }) | Out-Null
                }
            }
        }
        else {
            Write-Progress -Activity "Software Installation" -Status "Installiere alle verfügbaren Updates..." -PercentComplete 50
            $wingetCmdArgs = @('upgrade', '--all', '--source', 'winget', '--accept-source-agreements', '--accept-package-agreements', '--silent', '--disable-interactivity')
            if ($Excl.WingetIDs -and $Excl.WingetIDs.Count -gt 0) { $wingetCmdArgs += '--exclude'; $wingetCmdArgs += ($Excl.WingetIDs -join ',') }
            try {
                $proc = Start-Process -FilePath 'winget' -ArgumentList $wingetCmdArgs -NoNewWindow -Wait -PassThru -RedirectStandardOutput (Join-Path $LogDir 'winget-all-out.log') -RedirectStandardError (Join-Path $LogDir 'winget-all-err.log')
                if (Test-Path (Join-Path $LogDir 'winget-all-out.log')) { Get-Content (Join-Path $LogDir 'winget-all-out.log') | Out-File $LogFile -Append }
                if (Test-Path (Join-Path $LogDir 'winget-all-err.log')) { Get-Content (Join-Path $LogDir 'winget-all-err.log') | Out-File $LogFile -Append }
                if ($proc.ExitCode -ne 0) { Write-Host "winget --all: ExitCode $($proc.ExitCode). Siehe Log." -ForegroundColor Red }
            }
            catch { Write-Host "winget --all fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red; "!!! Fehler winget --all: $($_.Exception.Message)" | Out-File $LogFile -Append }
        }
        Write-Progress -Activity "Software Installation" -Status "Abgeschlossen" -PercentComplete 100
        Start-Sleep -Milliseconds 500
        Write-Progress -Activity "Software Installation" -Completed
        # Zusammenfassung (ohne Zählwerte)
        # Zusammenfassung (Listen der Namen)
        if ($results.Count -gt 0) {
            $succNames = ($results | Where-Object { $_.Status -eq 'Success' } | ForEach-Object { $_.Name })
            $failNames = ($results | Where-Object { $_.Status -in @('Failed', 'HashMismatch', 'Exception') } | ForEach-Object { $_.Name })
            Write-Host "Updates erfolgreich:" -ForegroundColor Green
            if ($succNames -and $succNames.Count -gt 0) { $succNames | ForEach-Object { Write-Host " - $_" -ForegroundColor Green } } else { Write-Host " - Keine" -ForegroundColor DarkGreen }
            Write-Host "Updates fehlgeschlagen:" -ForegroundColor Red
            if ($failNames -and $failNames.Count -gt 0) { $failNames | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow } } else { Write-Host " - Keine" -ForegroundColor DarkYellow }
        }
        else {
            Write-Host "Software Updates: Installation abgeschlossen." -ForegroundColor Green
        }
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
            while ($true) {
                $win = Find-WindowsUpdates
                if (-not $win -or $win.Count -le 0) { Write-Host "Keine Windows Updates verfügbar." -ForegroundColor Yellow; break }
                $win = Show-NumberedList -Items $win -Kind 'Windows' -ExcludeConfig ([ref]$Excl)
                $selected = Select-InstallSelection -Items $win -Prompt "Welche Windows-Updates installieren? A=Alle, K=Keine/Enter, Nummern (z.B. 1,3,5 oder 2-4)"
                $allowed = @($selected | Select-Object -ExpandProperty Key -ErrorAction SilentlyContinue)
                if ($allowed.Count -gt 0) {
                    $auto = (Read-Host "Bei Bedarf automatisch neu starten? (J/N)") -match '^(J|j)$'
                    Invoke-WindowsUpdateInstall -AutoReboot:$auto -Allowed $allowed
                    # Nach der Installation erneut prüfen/auswählen, bis Nutzer beendet
                    continue
                }
                else {
                    Write-Host "Keine Windows-Updates ausgewählt." -ForegroundColor Yellow
                    break
                }
            }
        }

        "2" {
            Write-Section "Software Updates verfügbar:"
            while ($true) {
                $sw = Find-SoftwareUpdates
                if (-not $sw -or $sw.Count -le 0) { Write-Host "Keine Software Updates verfügbar." -ForegroundColor Yellow; break }
                $sw = Show-NumberedList -Items $sw -Kind 'Software' -ExcludeConfig ([ref]$Excl)
                $selected = Select-InstallSelection -Items $sw -Prompt "Welche Software-Updates installieren? A=Alle, K=Keine/Enter, Nummern (z.B. 1,3,5 oder 2-4)"
                $allowedIds = @($selected | Select-Object -ExpandProperty Key -ErrorAction SilentlyContinue)
                # Baue Name-Map: Id -> Name aus Raw.Name, sonst aus Title bis vor " ("
                $nameById = @{}
                foreach ($it in $sw) {
                    $n = if ($it.Raw -and $it.Raw.PSObject.Properties['Name']) { $it.Raw.Name } else { ($it.Title -replace '\s*\(.*$', '').Trim() }
                    if (-not [string]::IsNullOrWhiteSpace($it.Key)) { $nameById[$it.Key] = $n }
                }
                if ($allowedIds.Count -gt 0) { 
                    Invoke-SoftwareUpdateInstall -AllowedIds $allowedIds -NameById $nameById
                    # Nach der Installation erneut prüfen/auswählen
                    continue
                }
                else { 
                    Write-Host "Keine Software-Updates ausgewählt." -ForegroundColor Yellow 
                    break
                }
            }
        }

        "3" {
            Write-Section "Verfügbare Updates (Windows + Software):"
            while ($true) {
                Write-Host "Suche nach Windows Updates..." -ForegroundColor Gray
                $win = Find-WindowsUpdates
                Write-Host "Suche nach Software Updates..." -ForegroundColor Gray
                $sw = Find-SoftwareUpdates

                # Verwende die neue kombinierte Anzeige-Funktion
                $allUpdates = Show-CombinedUpdateList -WindowsItems $win -SoftwareItems $sw -ExcludeConfig ([ref]$Excl)
                if (-not $allUpdates -or $allUpdates.Count -le 0) { Write-Host "Keine Updates verfügbar." -ForegroundColor Yellow; break }

                # Auswahl der Installation aus der kombinierten Liste
                $selectedCombined = Select-InstallSelection -Items $allUpdates -Prompt "Welche Updates installieren? A=Alle, K=Keine/Enter, Nummern (z.B. 1,3,5 oder 2-4)"
                $allowedKBs = @($selectedCombined | Where-Object { $_.Kind -eq 'Windows' } | Select-Object -ExpandProperty Key -ErrorAction SilentlyContinue)
                $allowedIDs = @($selectedCombined | Where-Object { $_.Kind -eq 'Software' } | Select-Object -ExpandProperty Key -ErrorAction SilentlyContinue)

                if (($allowedKBs.Count -gt 0) -or ($allowedIDs.Count -gt 0)) {
                    if ($allowedKBs.Count -gt 0) {
                        $auto = (Read-Host "Bei Bedarf automatisch neu starten? (J/N)") -match '^(J|j)$'
                        Invoke-WindowsUpdateInstall -AutoReboot:$auto -Allowed $allowedKBs
                    }
                    if ($allowedIDs.Count -gt 0) {
                        # Name-Map nur für Software-Items aufbauen
                        $nameById = @{}
                        foreach ($it in $sw) { if ($it -and $it.Key) { $n = if ($it.Raw -and $it.Raw.PSObject.Properties['Name']) { $it.Raw.Name } else { ($it.Title -replace '\s*\(.*$', '').Trim() }; $nameById[$it.Key] = $n } }
                        Invoke-SoftwareUpdateInstall -AllowedIds $allowedIDs -NameById $nameById
                    }
                    Write-Host "Updates erfolgreich!" -ForegroundColor Green
                    # Nach der Installation erneut prüfen/auswählen
                    continue
                }
                else { Write-Host "Keine Updates ausgewählt." -ForegroundColor Yellow; break }
            }
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