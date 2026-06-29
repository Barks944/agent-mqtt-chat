<#
.SYNOPSIS
    Install the agentmsg daemon as a Windows service that runs on boot.

.DESCRIPTION
    Registers a Windows service that runs `agentmsg daemon run` in the
    foreground under a fixed AGENTMSG_HOME. Defaults to the WinSW wrapper
    (deploy/windows/agentmsg.winsw.xml). nssm and sc.exe / schtasks
    alternatives are documented at the bottom of this script.

    REQUIRED: each agent needs its own AGENTMSG_HOME and its own service
    instance. To host multiple agents on one machine, run this script once per
    agent with a distinct -ServiceId and -AgentHome.

    Run from an elevated (Administrator) PowerShell prompt.

.EXAMPLE
    .\install-service.ps1 -ExePath 'C:\Program Files\agentmsg\agentmsg.exe' `
        -AgentHome 'C:\ProgramData\agentmsg' -WinswPath '.\WinSW.exe'
#>
[CmdletBinding()]
param(
    [string]$ServiceId = 'agentmsg',
    [string]$ExePath   = 'C:\Program Files\agentmsg\agentmsg.exe',
    [string]$AgentHome = 'C:\ProgramData\agentmsg',
    # Path to WinSW.exe (https://github.com/winsw/winsw/releases). If omitted,
    # the script falls back to sc.exe (see note about AGENTMSG_HOME below).
    [string]$WinswPath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $ExePath)) {
    throw "agentmsg.exe not found at '$ExePath' — pass -ExePath."
}
New-Item -ItemType Directory -Force -Path $AgentHome | Out-Null

if ($WinswPath) {
    # --- Preferred: WinSW ----------------------------------------------------
    # Place agentmsg.winsw.xml next to WinSW.exe, renamed to match the exe base
    # name (e.g. agentmsg-service.exe + agentmsg-service.xml), with <executable>,
    # <env AGENTMSG_HOME>, and <id> edited. WinSW reads env vars from the XML, so
    # the daemon gets the correct AGENTMSG_HOME.
    Write-Host "Installing service '$ServiceId' via WinSW ($WinswPath)..."
    & $WinswPath install
    & $WinswPath start
    Write-Host "Done. Manage with: $WinswPath {start|stop|status|uninstall}"
    return
}

# --- Fallback: sc.exe --------------------------------------------------------
# NOTE: sc.exe cannot set a per-service environment variable directly. Set
# AGENTMSG_HOME as a MACHINE-level environment variable so the service process
# inherits it. This only works for ONE agent per machine; use WinSW or nssm
# (below) to host multiple agents with distinct AGENTMSG_HOME values.
Write-Host "No -WinswPath given; installing '$ServiceId' via sc.exe."
[Environment]::SetEnvironmentVariable('AGENTMSG_HOME', $AgentHome, 'Machine')

$binPath = "`"$ExePath`" daemon run"
sc.exe create $ServiceId binPath= $binPath start= auto DisplayName= "agentmsg daemon"
sc.exe description $ServiceId "Cross-host agent messaging over MQTT (agentmsg daemon run)."
sc.exe failure $ServiceId reset= 86400 actions= restart/5000
Start-Service -Name $ServiceId
Write-Host "Done. Manage with: Start-Service / Stop-Service / sc.exe delete $ServiceId"

<#
ALTERNATIVES
============

nssm (https://nssm.cc) — supports per-service environment variables, so it can
host multiple agents on one machine:

    nssm install agentmsg "C:\Program Files\agentmsg\agentmsg.exe" daemon run
    nssm set agentmsg AppEnvironmentExtra AGENTMSG_HOME=C:\ProgramData\agentmsg
    nssm set agentmsg Start SERVICE_AUTO_START
    nssm start agentmsg

sc.exe (built in) — see the fallback above; one machine-level AGENTMSG_HOME only.

schtasks (built in) — run at startup without registering a true service:

    schtasks /Create /TN agentmsg /SC ONSTART /RU SYSTEM /RL HIGHEST ^
        /TR "cmd /c set AGENTMSG_HOME=C:\ProgramData\agentmsg && \"C:\Program Files\agentmsg\agentmsg.exe\" daemon run"
#>
