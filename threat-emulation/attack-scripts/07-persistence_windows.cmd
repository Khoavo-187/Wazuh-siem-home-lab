:: Stage 7 — Persistence (T1547.001)
:: Host: Windows 11 victim
:: Creates a Run key pointing at a harmless binary (calc.exe) for testing.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdaterSvc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f

:: Cleanup after the test:
:: reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "UpdaterSvc" /f
