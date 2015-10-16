@echo off
del *.sdf
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q arm
rmdir /s /q x64
rmdir /s /q meow_client\arm  
rmdir /s /q meow_client\x64  
rmdir /s /q meow\arm  
rmdir /s /q meow\x64  
del /s *.aps
pause
