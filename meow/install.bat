@echo off
cd %~dp0
del C:\Windows\meow.log
start powershell -Command "& {Get-content C:\Windows\meow.log -wait | where { $_ -cmatch 'INF|WRN|ERR' }}"
sc create meow type= kernel binPath= "%~dp0meow.sys"
sc start meow
start meow_client disarm exit
