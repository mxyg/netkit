package winssh

import "strings"

// ps1 在 Windows 上由管理员执行：安装 OpenSSH、放行 22、把每一步 POST 回本机。
// 函数不能叫 R：那是 Invoke-History 的别名，调用会去翻历史而不是记日志。
const ps1 = `$ErrorActionPreference = 'Continue'
$base = 'http://__NKHOST__'
function Note([string]$m) {
  Write-Host $m
  $tmp = Join-Path $env:TEMP 'nk-ssh-line.txt'
  Set-Content -Path $tmp -Value $m -Encoding ascii
  & curl.exe -s -m 5 -X POST --data-binary "@$tmp" "$base/log" | Out-Null
}
try {
  $pr = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Note 'not-admin'; exit 1 }
  Note ('admin ' + $env:USERNAME)
  $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like 'OpenSSH.Server*' } | Select-Object -First 1
  if (-not $cap) { Note 'no-capability'; exit 1 }
  Note ('state ' + $cap.State)
  if ([string]$cap.State -ne 'Installed') {
    Note 'installing'
    Add-WindowsCapability -Online -Name $cap.Name | Out-Null
    Note 'installed'
  }
  Set-Service -Name sshd -StartupType Automatic
  Start-Service sshd
  Note ('sshd ' + (Get-Service sshd).Status)
  $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
  if (-not $rule) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
  } else {
    Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled True -Action Allow | Out-Null
  }
  Note 'firewall-ok'
  Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } | ForEach-Object { Note ('ip ' + $_.IPAddress) }
  Note 'DONE'
} catch {
  Note ('ERR ' + $_.Exception.Message)
  exit 1
}
`

const cmd = "@echo off\r\n" +
	"curl.exe -s -m 20 -o C:\\Users\\Public\\nk-ssh.ps1 http://__NKHOST__/go.ps1\r\n" +
	"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Start-Process cmd.exe -Verb RunAs -Wait -ArgumentList '/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\nk-ssh.ps1'\"\r\n" +
	"echo.\r\n" +
	"echo log sent\r\n" +
	"pause\r\n"

func scriptPS1(hostport string) string {
	return strings.ReplaceAll(strings.ReplaceAll(ps1, "\n", "\r\n"), "__NKHOST__", hostport)
}

func scriptCMD(hostport string) string {
	return strings.ReplaceAll(cmd, "__NKHOST__", hostport)
}
