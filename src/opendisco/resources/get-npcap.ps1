# Install Npcap, the packet-capture driver OpenDisco's Sniff, Trunk VLANs and Direct
# modes need on Windows. Npcap's license doesn't allow bundling it, so this downloads the current
# official installer from npcap.com, checks that it's signed by Npcap's publisher and no one else,
# and starts it (Windows asks for permission first). Npcap's free license covers 5 computers.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Npcap's publisher, the Nmap Project's company: the name (CN) and the organization (O) on the
# certificate its installers are signed with, which the certificate authority checked. Each must
# be exactly this, in this case: a company whose name only contains it isn't it.
$Publisher = 'Nmap Software LLC'
$page = Invoke-WebRequest -UseBasicParsing -Uri 'https://npcap.com/'
$name = ([regex]'dist/(npcap-[0-9.]+\.exe)').Match($page.Content).Groups[1].Value
if (-not $name) { throw "Couldn't find the Npcap installer on npcap.com" }
# A folder made for this download and removed after it: only the file checked here can be run
$folder = Join-Path $env:TEMP ('opendisco-npcap-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder | Out-Null
try {
    $file = Join-Path $folder $name
    Write-Output "Downloading $name from npcap.com..."
    Invoke-WebRequest -UseBasicParsing -Uri "https://npcap.com/dist/$name" -OutFile $file
    $sig = Get-AuthenticodeSignature -FilePath $file
    $cert = $sig.SignerCertificate
    if ($sig.Status -ne 'Valid' -or -not $cert) {
        throw "The download isn't validly signed ($($sig.StatusMessage)), so it wasn't run"
    }
    # The subject's fields one per line, unquoted ("CN=...", "O=..."), so a value is compared whole
    $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]'UseNewLines, DoNotUseQuotes'
    $fields = $cert.SubjectName.Decode($flags) -split "`r?`n"
    $cn = @($fields | Where-Object { $_ -clike 'CN=*' } | ForEach-Object { $_.Substring(3) })
    $org = @($fields | Where-Object { $_ -clike 'O=*' } | ForEach-Object { $_.Substring(2) })
    if ($cn.Count -ne 1 -or $org.Count -ne 1 -or $cn[0] -cne $Publisher -or $org[0] -cne $Publisher) {
        throw "The download is signed by $($cert.Subject), not by $Publisher (Npcap's publisher), so it wasn't run"
    }
    Write-Output "Signed by $($cert.Subject). Starting the Npcap installer..."
    Start-Process -FilePath $file -Wait
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $folder
}
