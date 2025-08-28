<# ==================================================================
 SystemUpdateCheck.ps1 – Selbst-Elevation + Updates-Menü
 PS 5.1 & 7+. Approved Verbs, keine Cmdlet-Aliasse.
================================================================== #>

# --- Selbst-Elevation ----------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "🔒 Dieses Skript ist nicht mit Administratorrechten gestartet." -ForegroundColor Yellow
    Write-Host "   Für das INSTALLIEREN von Updates sind Adminrechte erforderlich." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Optionen:" -ForegroundColor Cyan
    Write-Host "  1) Als Admin neu starten"
    Write-Host "  2) Beenden (und später manuell als Administrator starten)"
    $elevChoice = Read-Host "Bitte 1 oder 2 wählen"

    switch ($elevChoice) {
        '1' {
            $hostExe = (Get-Process -Id $PID).Path
            if (-not $PSCommandPath) {
                Write-Host "❌ Skriptpfad konnte nicht ermittelt werden. Bitte Datei speichern und erneut ausführen." -ForegroundColor Red
                exit 1
            }
            try {
                Start-Process -FilePath $hostExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
                exit 0
            }
            catch {
                Write-Host "❌ Erhöhtes Neustarten fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor Red
                exit 1
            }
        }
        '2' { Write-Host "Beende. Starte das Skript später per Rechtsklick → 'Als Administrator ausführen'." -ForegroundColor Cyan; exit 0 }
        Default { Write-Host "Ungültige Auswahl. Beende." -ForegroundColor Red; exit 1 }
    }
}

# --- Einstellungen / Logging ---------------------------------------------------
$LogDir = 'C:\Logs'
$LogFile = Join-Path $LogDir 'SystemUpdates.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }
$TS = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$PSVer = $PSVersionTable.PSVersion
"=== Update-Check gestartet: $TS (PS $PSVer) ===" | Out-File $LogFile -Append

Write-Host "PowerShell-Version: $PSVer" -ForegroundColor Cyan
if ($PSVer.Major -lt 7) { Write-Host "⚠ Du verwendest noch Windows PowerShell 5.1. Für neue Features empfiehlt sich PowerShell 7." -ForegroundColor Yellow }

# --- Hilfsfunktionen (approved verbs, keine Aliasse) --------------------------
function Write-Section { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }

function Test-WingetPresent { return [bool](Get-Command winget -ErrorAction SilentlyContinue) }

function Test-PSWindowsUpdatePresent { return [bool](Get-Module -ListAvailable -Name PSWindowsUpdate) }

function Import-PSWindowsUpdateOrExplain {
    if (-not (Test-PSWindowsUpdatePresent)) {
        Write-Host "❌ PSWindowsUpdate nicht gefunden." -ForegroundColor Red
        Write-Host "👉 Installation (als Admin):  Install-Module -Name PSWindowsUpdate -Scope AllUsers -Force" -ForegroundColor Yellow
        Write-Host "   Falls NuGet fehlt:  Get-PackageProvider NuGet -ForceBootstrap -Force" -ForegroundColor Gray
        "Fehler: PSWindowsUpdate fehlte." | Out-File $LogFile -Append
        return $false
    }
    Import-Module PSWindowsUpdate -ErrorAction Stop
    return $true
}

function Find-WindowsUpdates {
    if (-not (Import-PSWindowsUpdateOrExplain)) { return @() }
    try { return Get-WindowsUpdate -MicrosoftUpdate }
    catch {
        Write-Host "❌ Fehler beim Abfragen der Windows-Updates: $($_.Exception.Message)" -ForegroundColor Red
        "Fehler Get-WindowsUpdate: $($_.Exception.Message)" | Out-File $LogFile -Append
        return @()
    }
}

function Invoke-WindowsUpdateInstall {
    param([switch]$AutoReboot)
    if (-not (Import-PSWindowsUpdateOrExplain)) { return }
    if (-not (Test-Admin)) {
        Write-Host "🔒 Administratorrechte erforderlich, um Windows-Updates zu INSTALLIEREN." -ForegroundColor Yellow
        Write-Host "   → Skript/Terminal **als Administrator** neu starten und erneut ausführen." -ForegroundColor Gray
        "Abbruch: Keine Adminrechte für Windows-Install." | Out-File $LogFile -Append
        return
    }
    try {
        if ($AutoReboot) {
            Install-WindowsUpdate -AcceptAll -AutoReboot | Tee-Object -FilePath $LogFile -Append | Out-Null
        }
        else {
            Install-WindowsUpdate -AcceptAll -IgnoreReboot | Tee-Object -FilePath $LogFile -Append | Out-Null
            $reboot = Get-WURebootStatus
            if ($reboot -and ($reboot.RebootRequired -eq $true)) {
                Write-Host "↻ Neustart wird empfohlen/benötigt. (Auto-Neustart war deaktiviert)" -ForegroundColor Yellow
            }
        }
        Write-Host "✅ Windows Updates: Installation abgeschlossen." -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Fehler bei der Windows-Installation: $($_.Exception.Message)" -ForegroundColor Red
        "Fehler Install-WindowsUpdate: $($_.Exception.Message)" | Out-File $LogFile -Append
    }
}

function Find-SoftwareUpdates {
    if (-not (Test-WingetPresent)) {
        Write-Host "❌ winget ist nicht verfügbar." -ForegroundColor Red
        Write-Host "👉 Lösung: *App-Installer* aus dem Microsoft Store installieren/aktualisieren (Publisher: Microsoft)." -ForegroundColor Yellow
        "Fehler: winget fehlte." | Out-File $LogFile -Append
        return ""
    }
    try { return winget upgrade --include-unknown }
    catch {
        Write-Host "❌ Fehler beim Abfragen der Software-Updates (winget): $($_.Exception.Message)" -ForegroundColor Red
        "Fehler winget upgrade: $($_.Exception.Message)" | Out-File $LogFile -Append
        return ""
    }
}

function Invoke-SoftwareUpdateInstall {
    if (-not (Test-WingetPresent)) { return }
    if (-not (Test-Admin)) {
        Write-Host "🔒 Administratorrechte empfohlen/erforderlich für die meisten Software-Installationen." -ForegroundColor Yellow
        Write-Host "   → Terminal **als Administrator** neu starten für eine reibungslose Aktualisierung." -ForegroundColor Gray
        "Abbruch: Keine Adminrechte für Software-Install." | Out-File $LogFile -Append
        return
    }
    try {
        winget upgrade --all --accept-source-agreements --accept-package-agreements `
      | Tee-Object -FilePath $LogFile -Append | Out-Null
        Write-Host "✅ Software Updates installiert." -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Fehler bei der Software-Installation: $($_.Exception.Message)" -ForegroundColor Red
        "Fehler winget upgrade --all: $($_.Exception.Message)" | Out-File $LogFile -Append
    }
}

function Show-Menu {
    Write-Host ""
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "   System Update Check Menü     " -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "1) Windows Updates prüfen/installieren"
    Write-Host "2) Software Updates (winget) prüfen/installieren"
    Write-Host "3) Alles prüfen (Windows + Software) – gruppierte Ausgabe"
    Write-Host "4) Beenden"
    Write-Host "===============================" -ForegroundColor Cyan
}

# --- Hauptschleife -------------------------------------------------------------
do {
    Show-Menu
    $choice = Read-Host "Bitte Auswahl (1-4)"

    switch ($choice) {

        "1" {
            Write-Section "Windows Updates verfügbar:"
            $wu = Find-WindowsUpdates
            if ($wu -and $wu.Count -gt 0) {
                $wu | Select-Object Title, KB, Size | Format-Table -AutoSize
                $wu | Select-Object Title, KB, Size | Out-File $LogFile -Append
                if ((Read-Host "Sollen diese Windows-Updates installiert werden? (J/N)") -match '^(J|j)$') {
                    $auto = (Read-Host "Bei Bedarf automatisch neu starten? (J/N)") -match '^(J|j)$'
                    Invoke-WindowsUpdateInstall -AutoReboot:$auto
                }
                else {
                    Write-Host "Abgebrochen. Keine Windows-Updates installiert." -ForegroundColor Yellow
                    "Windows: Nutzer hat Installation abgelehnt." | Out-File $LogFile -Append
                }
            }
            else {
                Write-Host "Keine Windows Updates verfügbar." -ForegroundColor Yellow
                "Keine Windows Updates verfügbar." | Out-File $LogFile -Append
            }
        }

        "2" {
            Write-Section "Software Updates verfügbar:"
            $wgText = Find-SoftwareUpdates
            if ($wgText -and ($wgText -replace '\s', '').Length -gt 0 -and ($wgText -notmatch 'No applicable updates')) {
                $wgText | Out-Host
                $wgText | Out-File $LogFile -Append
                if ((Read-Host "Sollen diese Software-Updates installiert werden? (J/N)") -match '^(J|j)$') {
                    Invoke-SoftwareUpdateInstall
                }
                else {
                    Write-Host "Abgebrochen. Keine Software-Updates installiert." -ForegroundColor Yellow
                    "Software: Nutzer hat Installation abgelehnt." | Out-File $LogFile -Append
                }
            }
            else {
                Write-Host "Keine Software Updates verfügbar." -ForegroundColor Yellow
                "Keine Software Updates verfügbar." | Out-File $LogFile -Append
            }
        }

        "3" {
            $any = $false

            Write-Section "Windows Updates verfügbar:"
            $wu = Find-WindowsUpdates
            if ($wu -and $wu.Count -gt 0) {
                $any = $true
                $wu | Select-Object Title, KB, Size | Format-Table -AutoSize
                $wu | Select-Object Title, KB, Size | Out-File $LogFile -Append
            }
            else {
                Write-Host "Keine Windows Updates verfügbar." -ForegroundColor Yellow
                "Keine Windows Updates verfügbar." | Out-File $LogFile -Append
            }

            Write-Section "Software Updates verfügbar:"
            $wgText = Find-SoftwareUpdates
            if ($wgText -and ($wgText -replace '\s', '').Length -gt 0 -and ($wgText -notmatch 'No applicable updates')) {
                $any = $true
                $wgText | Out-Host
                $wgText | Out-File $LogFile -Append
            }
            else {
                Write-Host "Keine Software Updates verfügbar." -ForegroundColor Yellow
                "Keine Software Updates verfügbar." | Out-File $LogFile -Append
            }

            if ($any) {
                if ((Read-Host "`nSollen alle gefundenen Updates installiert werden? (J/N)") -match '^(J|j)$') {
                    if ($wu -and $wu.Count -gt 0) {
                        $auto = (Read-Host "Bei Bedarf automatisch neu starten? (J/N)") -match '^(J|j)$'
                        Invoke-WindowsUpdateInstall -AutoReboot:$auto
                    }
                    if ($wgText -and ($wgText -replace '\s', '').Length -gt 0 -and ($wgText -notmatch 'No applicable updates')) {
                        Invoke-SoftwareUpdateInstall
                    }
                    Write-Host "✅ Updates erfolgreich!" -ForegroundColor Green
                }
                else {
                    Write-Host "Abgebrochen. Es wurden keine Updates installiert." -ForegroundColor Yellow
                    "Kombi: Nutzer hat Installation abgelehnt." | Out-File $LogFile -Append
                }
            }
            else {
                Write-Host "`nAlles aktuell – keine Updates verfügbar." -ForegroundColor Green
            }
        }

        "4" { break }

        Default { Write-Host "Ungültige Eingabe. Bitte 1–4 wählen." -ForegroundColor Red }
    }

} while ($true)

# --- Abschluss ----------------------------------------------------------------
$TS2 = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$end = "=== Update-Check beendet: $TS2 ==="
Write-Host $end -ForegroundColor Cyan
$end | Out-File $LogFile -Append