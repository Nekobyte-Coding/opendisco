# Install Npcap, the packet-capture driver OpenDisco's Sniff, Trunk VLANs and Direct
# modes need on Windows. Npcap's license doesn't allow bundling it, so this downloads the current
# official installer from npcap.com, checks that it's signed by the Nmap Project, and starts it:
# you click through it (and Windows asks for permission). Npcap's free license covers 5 computers.
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$page = Invoke-WebRequest -UseBasicParsing -Uri 'https://npcap.com/'
$name = ([regex]'dist/(npcap-[0-9.]+\.exe)').Match($page.Content).Groups[1].Value
if (-not $name) { throw "Couldn't find the Npcap installer on npcap.com" }
$file = Join-Path $env:TEMP $name
Write-Output "Downloading $name from npcap.com..."
Invoke-WebRequest -UseBasicParsing -Uri "https://npcap.com/dist/$name" -OutFile $file
$sig = Get-AuthenticodeSignature -FilePath $file
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Nmap Software') {
    Remove-Item -Force $file
    throw "The download isn't validly signed by the Nmap Project, so it wasn't run"
}
Write-Output "Signed by $($sig.SignerCertificate.Subject). Starting the Npcap installer..."
Start-Process -FilePath $file -Wait
Remove-Item -Force -ErrorAction SilentlyContinue $file
