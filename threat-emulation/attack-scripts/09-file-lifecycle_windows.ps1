# Stage 9 — File Lifecycle (FIM)
# Host: Windows 11 victim, run through the reverse shell
# Exercises the FIM "modified" and "deleted" events on the monitored folder.

# Modified
Add-Content -Path C:\Users\LENOVO\Downloads\virustotaltest\eicar2.com -Value "modified"

# Deleted
Remove-Item C:\Users\LENOVO\Downloads\virustotaltest\eicar2.com -Force
