@echo off
chcp 65001 >nul
echo [MAO] GitHub reposu hazir, kurulum baslatiliyor...

:: Python kontrolu
python --version >nul 2>&1
if errorlevel 1 (
    echo Python bulunamadi, winget ile kuruluyor...
    winget install Python.Python.3.14 --silent --accept-source-agreements --accept-package-agreements
    echo Python kuruldu. Lutfen CMD'yi kapatip tekrar acin ve betigi yeniden calistirin!
    pause
    exit /b
)

:: PyInstaller kontrolu
python -m pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo PyInstaller yukleniyor...
    pip install pyinstaller
)

:: script.py kontrolu ve derleme
if not exist "Windows\script.py" (
    echo Hata: Windows\script.py bulunamadi!
    pause
    exit /b
)

echo script.py EXE haline getiriliyor...
python -m pyinstaller --noconsole --onefile Windows\script.py

:: Hedef klasore tasima
set "TARGET_DIR=%LOCALAPPDATA%\Programs\MAO-Windows-Reclaimer"
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
move /y "dist\script.exe" "%TARGET_DIR%\MAO-Windows-Reclaimer.exe"

:: Masaustune kisayol ekleme
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('%USERPROFILE%\Desktop\MAO Windows Reclaimer.lnk'); $sc.TargetPath = '%TARGET_DIR%\MAO-Windows-Reclaimer.exe'; $sc.Save()"

echo Kurulum basariyla tamamlandi! Masaustu kisayolu olusturuldu.
pause
