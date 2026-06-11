#!/data/data/com.termux/files/usr/bin/bash
# ╔══════════════════════════════════════════════════════╗
# ║   FAMILY SECURITY — Установка на Android (Termux)   ║
# ╚══════════════════════════════════════════════════════╝
# Запусти один раз: bash termux_setup.sh
# После этого система будет запускаться сама при каждой загрузке телефона.

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
step()  { echo -e "\n${YELLOW}══ $1 ══${NC}"; }

REPO_DIR="$HOME/family-security"
BACKEND_DIR="$REPO_DIR/backend"
FRONTEND_DIR="$REPO_DIR/frontend"

step "1/7 — Обновление пакетов Termux"
pkg update -y && pkg upgrade -y

step "2/7 — Установка Python, Git, Node.js"
pkg install -y python git nodejs-lts make clang

step "3/7 — Клонирование репозитория"
if [ -d "$REPO_DIR" ]; then
    warn "Репозиторий уже есть — обновляю"
    cd "$REPO_DIR" && git pull origin claude/home-network-guardian-mvp-kt4yap
else
    git clone -b claude/home-network-guardian-mvp-kt4yap \
        https://github.com/smith77788/Security-.git "$REPO_DIR"
fi

step "4/7 — Установка Python-зависимостей"
cd "$BACKEND_DIR"
# Пакеты с нативным кодом — ставим через pkg (Termux pre-built)
pkg install -y python python-psutil
# Чистые Python пакеты — через pip
pip install \
    fastapi \
    "uvicorn[standard]" \
    sqlalchemy \
    pydantic \
    apscheduler \
    ipwhois \
    requests \
    aiofiles \
    "python-multipart"

step "5/7 — Сборка фронтенда (5-10 минут на первый раз)"
cd "$FRONTEND_DIR"
npm install
npm run build
# Копируем собранные файлы в папку backend/static
mkdir -p "$BACKEND_DIR/static"
cp -r dist/* "$BACKEND_DIR/static/"
info "Фронтенд собран и скопирован в backend/static"

step "6/7 — Настройка .env"
ENV_FILE="$BACKEND_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    cp "$REPO_DIR/.env.example" "$ENV_FILE"
    # Генерируем случайный JWT_SECRET
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    sed -i "s/change-me-use-long-random-secret/$JWT_SECRET/" "$ENV_FILE"
    sed -i "s/ADMIN_PASSWORD=changeme/ADMIN_PASSWORD=Smile1212+/" "$ENV_FILE"
    info "Создан .env — пароль и JWT настроены автоматически"
    # Вставляем Telegram credentials
    echo "" >> "$ENV_FILE"
    echo "TELEGRAM_BOT_TOKEN=8904805144:AAEnfZCeUCUmva7svg5MFQPpLjP6Eldq_8w" >> "$ENV_FILE"
    echo "TELEGRAM_CHAT_ID=391641532" >> "$ENV_FILE"
else
    info ".env уже существует — не перезаписываю"
fi

step "7/7 — Автозапуск при загрузке телефона"
# Termux:Boot — устанавливается отдельно из F-Droid
BOOT_DIR="$HOME/.termux/boot"
mkdir -p "$BOOT_DIR"
cat > "$BOOT_DIR/family-security.sh" << 'BOOT'
#!/data/data/com.termux/files/usr/bin/bash
# Автозапуск Family Security
cd $HOME/family-security/backend
source $HOME/family-security/backend/.env 2>/dev/null || true
export $(cat $HOME/family-security/backend/.env | grep -v '^#' | xargs) 2>/dev/null
nohup python3 -m uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 1 \
    > $HOME/family-security/backend/server.log 2>&1 &
echo $! > $HOME/family-security/backend/server.pid
BOOT
chmod +x "$BOOT_DIR/family-security.sh"

# Создаём скрипты управления
cat > "$REPO_DIR/start.sh" << 'START'
#!/data/data/com.termux/files/usr/bin/bash
cd $HOME/family-security/backend
export $(cat .env | grep -v '^#' | xargs) 2>/dev/null
echo "Запуск Family Security на http://localhost:8000 ..."
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
START
chmod +x "$REPO_DIR/start.sh"

cat > "$REPO_DIR/stop.sh" << 'STOP'
#!/data/data/com.termux/files/usr/bin/bash
PID_FILE=$HOME/family-security/backend/server.pid
if [ -f "$PID_FILE" ]; then
    kill $(cat "$PID_FILE") 2>/dev/null && echo "Остановлено" || echo "Процесс не найден"
    rm -f "$PID_FILE"
else
    pkill -f "uvicorn main:app" && echo "Остановлено" || echo "Уже не запущен"
fi
STOP
chmod +x "$REPO_DIR/stop.sh"

cat > "$REPO_DIR/status.sh" << 'STATUS'
#!/data/data/com.termux/files/usr/bin/bash
if pgrep -f "uvicorn main:app" > /dev/null; then
    echo "✅ Family Security РАБОТАЕТ"
    echo "   Веб-интерфейс: http://localhost:8000"
    IP=$(ip route get 1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    [ -n "$IP" ] && echo "   Из другого устройства: http://$IP:8000"
else
    echo "❌ Family Security НЕ ЗАПУЩЕН"
    echo "   Запустить: bash ~/family-security/start.sh"
fi
STATUS
chmod +x "$REPO_DIR/status.sh"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              ✅ УСТАНОВКА ЗАВЕРШЕНА!                 ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  Запустить:   bash ~/family-security/start.sh        ║"
echo "║  Остановить:  bash ~/family-security/stop.sh         ║"
echo "║  Статус:      bash ~/family-security/status.sh       ║"
echo "║                                                      ║"
echo "║  Веб-интерфейс: http://localhost:8000                ║"
echo "║  Telegram-бот: уже работает (@Obmennik_OAEbot)       ║"
echo "║                                                      ║"
echo "║  Автозапуск при загрузке телефона:                   ║"
echo "║  Установи Termux:Boot из F-Droid                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
warn "ВАЖНО: Выполни один раз:"
warn "  nano $BACKEND_DIR/.env"
warn "  Поменяй ADMIN_PASSWORD=changeme на свой пароль"
echo ""
read -p "Запустить сейчас? (y/n): " answer
if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    bash "$REPO_DIR/start.sh"
fi
