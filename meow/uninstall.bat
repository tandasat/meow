@echo off
sc stop meow
sc delete meow 
taskkill /f /im meow_client.exe
taskkill /f /im powershell.exe
