# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install, remove or inspect the GLKVM paste hook on a device over SSH.
# Windows PowerShell 5.1+ / PowerShell 7 port of apply_paste_hook.sh.
#
#   .\apply_paste_hook.ps1 install|remove|status
#
# Environment: GLKVM_HOST (default glkvm.local), GLKVM_PORT (default 22).
# Uses the built-in Windows OpenSSH client (ssh.exe, scp.exe). Password
# authentication is left entirely to ssh/scp: this script never stores, reads
# or accepts a password. Windows OpenSSH has no ControlMaster support, so ssh
# asks for the password once per connection (an SSH key avoids that).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RemoteHost = if ($env:GLKVM_HOST) { $env:GLKVM_HOST } else { 'glkvm.local' }
$RemoteUser = 'root'
$SshPort    = if ($env:GLKVM_PORT) { $env:GLKVM_PORT } else { '22' }
$Target     = "$RemoteUser@$RemoteHost"

$LocalJs   = Join-Path $PSScriptRoot 'paste-hook.js'
$LocalHook = Join-Path $PSScriptRoot 'S90paste-hook.sh'

$Paths = [ordered]@{
    '@REMOTE_JS_DIR@'      = '/etc/kvmd/user/paste-hook'
    '@REMOTE_JS@'          = '/etc/kvmd/user/paste-hook/paste-hook.js'
    '@REMOTE_SCRIPTS_DIR@' = '/etc/kvmd/user/scripts'
    '@REMOTE_HOOK@'        = '/etc/kvmd/user/scripts/S90paste-hook.sh'
    '@WEB_IDX@'            = '/usr/share/kvmd/glweb/index.html'
    '@WEB_JS@'             = '/usr/share/kvmd/glweb/paste-hook.js'
    '@ROM_IDX@'            = '/rom/usr/share/kvmd/glweb/index.html'
}

# Fail fast on unreachable hosts instead of waiting for the TCP timeout.
$SshOpts = @('-o', 'ConnectTimeout=10')

# Remote scripts are sent as UTF-8 without BOM on stdin.
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Show-Usage {
    $name = Split-Path -Leaf $PSCommandPath
    Write-Output "Usage: $name install|remove|status"
    Write-Output "  GLKVM_HOST=$RemoteHost GLKVM_PORT=$SshPort"
    exit 2
}

function Expand-Remote([string]$Script) {
    foreach ($k in $Paths.Keys) { $Script = $Script.Replace($k, $Paths[$k]) }
    return $Script
}

# Run a BusyBox sh script on the device. The script goes over stdin instead of
# the command line, which avoids Windows argument-quoting pitfalls; CRs (this
# .ps1 may be checked out with CRLF) are stripped on the device before sh runs.
function Invoke-Remote([string]$Script) {
    $body = (Expand-Remote $Script) + "`n"
    $body | & $script:Ssh @SshOpts -p $SshPort $Target "tr -d '\r' | sh -s"
    return $LASTEXITCODE
}

function Copy-ToRemote([string[]]$Files, [string]$Dest) {
    & $script:Scp @SshOpts -P $SshPort @Files "${Target}:$Dest"
    return $LASTEXITCODE
}

function Assert-LocalFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Output "Error: '$Path' does not exist."
        exit 1
    }
}

function Invoke-Install {
    Assert-LocalFile $LocalJs
    Assert-LocalFile $LocalHook

    Write-Output "Uploading to ${Target}:/tmp/ ..."
    if ((Copy-ToRemote @($LocalJs, $LocalHook) '/tmp/') -ne 0) {
        Write-Output 'Failed!'
        exit 1
    }

    Write-Output 'Installing and activating ...'
    $rc = Invoke-Remote @'
set -e
mkdir -p @REMOTE_JS_DIR@ @REMOTE_SCRIPTS_DIR@
mv -f /tmp/paste-hook.js @REMOTE_JS@
mv -f /tmp/S90paste-hook.sh @REMOTE_HOOK@
sed -i 's/\r$//' @REMOTE_JS@ @REMOTE_HOOK@
chmod 644 @REMOTE_JS@
chmod 755 @REMOTE_HOOK@
sh @REMOTE_HOOK@ start
n=$(grep -c paste-hook @WEB_IDX@ || true)
echo "grep -c paste-hook @WEB_IDX@: $n"
ls -l @WEB_JS@
[ "$n" = 1 ]
'@
    if ($rc -eq 0) {
        Write-Output 'OK! Hard-reload the KVM web UI (Ctrl+Shift+R / Cmd+Shift+R, or restart the GLKVM app). No reboot needed.'
    } else {
        Write-Output 'Failed! The hook did not activate; see the messages above.'
        exit 1
    }
}

function Invoke-Remove {
    Assert-LocalFile $LocalHook

    # The local hook copy is used only if the device copy is already gone,
    # so leftover overlay files are still cleaned up.
    Write-Output "Uploading S90paste-hook.sh to ${Target}:/tmp/ ..."
    if ((Copy-ToRemote @($LocalHook) '/tmp/S90paste-hook.sh') -ne 0) {
        Write-Output 'Failed!'
        exit 1
    }

    $rc = Invoke-Remote @'
if [ -f @REMOTE_HOOK@ ]; then
	sh @REMOTE_HOOK@ remove
else
	sed -i 's/\r$//' /tmp/S90paste-hook.sh
	sh /tmp/S90paste-hook.sh remove
fi
rm -f /tmp/S90paste-hook.sh
rm -f @REMOTE_JS@ @REMOTE_HOOK@
rmdir @REMOTE_JS_DIR@ 2>/dev/null || true
if diff -q @ROM_IDX@ @WEB_IDX@; then
	echo 'index.html is identical to the firmware original.'
else
	echo 'WARNING: index.html differs from the firmware original.'
	exit 1
fi
'@
    if ($rc -eq 0) {
        Write-Output 'OK! Paste hook removed. Hard-reload the KVM web UI.'
    } else {
        Write-Output 'Failed!'
        exit 1
    }
}

function Invoke-Status {
    $rc = Invoke-Remote @'
for f in @REMOTE_JS@ @REMOTE_HOOK@ @WEB_JS@; do
	if [ -e $f ]; then ls -l $f; else echo "missing: $f"; fi
done
n=$(grep -c paste-hook.js @WEB_IDX@ 2>/dev/null || true)
echo "index.html marker count: ${n:-0}"
if diff -q @ROM_IDX@ @WEB_IDX@ >/dev/null 2>&1; then
	echo 'index.html: firmware original'
else
	echo 'index.html: differs from firmware original (patched)'
fi
'@
    if ($rc -ne 0) {
        Write-Output "Failed! (ssh exit code $rc)"
        exit 1
    }
}

$ssh = Get-Command -Name 'ssh' -CommandType Application -ErrorAction SilentlyContinue
$scp = Get-Command -Name 'scp' -CommandType Application -ErrorAction SilentlyContinue
if (-not $ssh -or -not $scp) {
    Write-Output 'Error: OpenSSH client (ssh.exe / scp.exe) not found.'
    Write-Output 'Enable it in Settings > System > Optional features > Add a feature > "OpenSSH Client",'
    Write-Output 'or from an elevated PowerShell:'
    Write-Output '  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0'
    exit 1
}
$script:Ssh = @($ssh)[0].Source
$script:Scp = @($scp)[0].Source

$Verb = if ($args.Count -gt 0) { [string]$args[0] } else { '' }
if (@('install', 'remove', 'status') -notcontains $Verb) { Show-Usage }

Write-Output "REMOTE TARGET: $Target (port $SshPort)"
$conns = @{ install = 2; remove = 2; status = 1 }[$Verb]
Write-Output "Note: ssh may ask for the root password once per connection ($conns for '$Verb'); Windows OpenSSH cannot share one connection. An SSH key avoids the prompts."

switch ($Verb) {
    'install' { Invoke-Install }
    'remove'  { Invoke-Remove }
    'status'  { Invoke-Status }
}
exit 0
