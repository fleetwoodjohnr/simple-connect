param([ValidateSet('x86_64','aarch64')][string]$Architecture)
$ErrorActionPreference = 'Stop'
$packages = @{
  x86_64 = @{ Name = 'OpenSSH-Win64'; Sha = 'b67ff8becd203502190ec42ac7787c24c2cd3325ed7700485fe7a1c83d2a7957' }
  aarch64 = @{ Name = 'OpenSSH-ARM64'; Sha = 'd2b1928225479fec9e0c938f527fdb5ed676446cca1bbcc5af84aca1f272842e' }
}
$package = $packages[$Architecture]
$archive = Join-Path $env:RUNNER_TEMP "$($package.Name).zip"
Invoke-WebRequest "https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/$($package.Name).zip" -OutFile $archive
if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLower() -ne $package.Sha) { throw 'OpenSSH archive checksum mismatch' }
$staging = Join-Path $env:RUNNER_TEMP "openssh-$Architecture"
Expand-Archive $archive -DestinationPath $staging -Force
New-Item src-tauri/openssh -ItemType Directory -Force | Out-Null
Get-ChildItem $staging -Recurse -File | Where-Object {
  $_.Name -in @('ssh.exe','ssh-keygen.exe','ssh-sk-helper.exe') -or $_.Extension -eq '.dll' -or $_.Name -match '(?i)licen[cs]e|notice|copyright'
} | Copy-Item -Destination src-tauri/openssh
if (!(Test-Path src-tauri/openssh/ssh.exe) -or !(Test-Path src-tauri/openssh/ssh-keygen.exe)) { throw 'OpenSSH client files missing' }
