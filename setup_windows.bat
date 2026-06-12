@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo.
echo ╔══════════════════════════════════════════════════╗
echo ║   Home Network Guardian — Установка на Windows  ║
echo ╚══════════════════════════════════════════════════╝
echo.

:: ── Проверить Python ────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не найден.
    echo Скачайте Python 3.11+ с https://www.python.org/downloads/
    echo Убедитесь что поставили галочку "Add Python to PATH"
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [OK] Python %PY_VER%

:: ── Перейти в папку скрипта ────────────────────────────────────
cd /d "%~dp0"

:: ── Создать виртуальное окружение ──────────────────────────────
if not exist "backend\venv" (
    echo [..] Создаём виртуальное окружение...
    python -m venv backend\venv
    if errorlevel 1 (
        echo [ОШИБКА] Не удалось создать venv
        pause
        exit /b 1
    )
    echo [OK] Виртуальное окружение создано
) else (
    echo [OK] Виртуальное окружение уже существует
)

:: ── Установить зависимости ──────────────────────────────────────
echo [..] Устанавливаем зависимости Python...
backend\venv\Scripts\pip install --quiet --upgrade pip
backend\venv\Scripts\pip install --quiet -r backend\requirements.txt
if errorlevel 1 (
    echo [ОШИБКА] Не удалось установить зависимости
    echo Проверьте backend\requirements.txt
    pause
    exit /b 1
)
echo [OK] Зависимости установлены

:: ── Создать .env если нет ──────────────────────────────────────
if not exist "backend\.env" (
    echo [..] Создаём backend\.env из шаблона...
    copy "backend\.env.example" "backend\.env" >nul
    echo [OK] Создан backend\.env
    echo.
    echo  *** ВАЖНО: Откройте backend\.env и заполните:
    echo      ADMIN_PASSWORD=  (пароль для входа в веб-интерфейс)
    echo      TELEGRAM_TOKEN=  (токен вашего бота, если нужен)
    echo      TELEGRAM_CHAT_ID= (ваш Telegram ID)
    echo.
) else (
    echo [OK] backend\.env уже существует
)

:: ── Создать start_server.bat ───────────────────────────────────
if not exist "start_server.bat" (
echo [..] Создаём start_server.bat...
(
echo @echo off
echo chcp 65001 ^>nul
echo cd /d "%%~dp0"
echo echo Запускаем Home Network Guardian...
echo echo Веб-интерфейс: http://localhost:8000
echo echo Для остановки нажмите Ctrl+C
echo echo.
echo backend\venv\Scripts\python -m uvicorn main:app --host 0.0.0.0 --port 8000 --app-dir backend
) > start_server.bat
    echo [OK] Создан start_server.bat
)

:: ── Проверить npcap для ARP-сканирования ───────────────────────
echo.
echo [i] Проверяем Npcap (нужен для ARP-сканирования)...
if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [OK] Npcap установлен
) else if exist "C:\Windows\System32\wpcap.dll" (
    echo [OK] WinPcap/Npcap установлен
) else (
    echo [!] Npcap не найден — ARP-сканирование недоступно
    echo     Система будет использовать TCP-сканирование (менее точно^)
    echo     Рекомендуется установить: https://npcap.com/#download
)

:: ── Итог ───────────────────────────────────────────────────────
echo.
echo ╔══════════════════════════════════════════════════╗
echo ║              Установка завершена!               ║
echo ╠══════════════════════════════════════════════════╣
echo ║  Для запуска: дважды кликните start_server.bat  ║
echo ║  Веб-интерфейс: http://localhost:8000           ║
echo ║  Логин: admin / пароль из backend\.env          ║
echo ╚══════════════════════════════════════════════════╝
echo.

:: Предложить сразу запустить
set /p LAUNCH="Запустить сервер сейчас? (y/n): "
if /i "!LAUNCH!"=="y" (
    start "" start_server.bat
)

pause
