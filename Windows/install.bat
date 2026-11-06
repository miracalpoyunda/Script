@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [MAO] Kurulum baslatiliyor...

:: Python kontrolu
python --version >nul 2>&1
if errorlevel 1 (
    echo Python bulunamadi, winget ile kuruluyor...
    winget install Python.Python.3.14 --silent --accept-source-agreements --accept-package-agreements
    echo Python kuruldu. Lutfen CMD'yi kapatip tekrar acin ve betigi yeniden calistirin!
    pause
    exit /b
)

:: PyInstaller'i dogru Python ortamina yukle
echo PyInstaller kontrol ediliyor ve yukleniyor...
python -m pip install --upgrade pip
python -m pip install pyinstaller

:: script.py kontrolu
if not exist "script.py" (
    echo Hata: script.py bulunamadi!
    pause
    exit /b
)

echo script.py EXE haline getiriliyor...
python -m PyInstaller --noconsole --onefile script.py

:: EXE olustu mu kontrol et
if not exist "dist\script.exe" (
    echo Hata: Derleme basarisiz oldu, EXE dosyasi olusturulamadi!
    pause
    exit /b
)

:: Hedef klasore tasima
set "TARGET_DIR=%LOCALAPPDATA%\Programs\MAO-Windows-Reclaimer"
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
move /y "dist\script.exe" "%TARGET_DIR%\MAO-Windows-Reclaimer.exe"

:: Masaustune kisayol ekleme
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut('%USERPROFILE%\Desktop\MAO Windows Reclaimer.lnk'); $sc.TargetPath = '%TARGET_DIR%\MAO-Windows-Reclaimer.exe'; $sc.Save()"

echo Kurulum basariyla tamamlandi! Masaustu kisayolu olusturuldu.
pause
