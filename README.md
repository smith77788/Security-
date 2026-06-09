# FAMILY SECURITY — Home Network Guardian

Локальная система мониторинга домашней сети. Без облака. Без платных API. Без утечки данных.

```
┌─────────────────────────────────────────────────────┐
│  Browser → http://localhost:3000                    │
│                                                     │
│  ┌─────────────────┐   REST/JSON   ┌─────────────┐ │
│  │  React/Vite UI  │ ───────────►  │  FastAPI    │ │
│  │  (nginx:80)     │               │  (port 8000)│ │
│  └─────────────────┘               └──────┬──────┘ │
│                                           │        │
│              ┌────────────────────────────┘        │
│              ▼                                     │
│  ┌────────────────────┐   ┌──────────────────────┐ │
│  │  SQLite (local)    │   │  Background tasks    │ │
│  │  devices           │   │  - ARP/nmap scan     │ │
│  │  dns_queries       │   │  - Anomaly checks    │ │
│  │  alerts            │   │  - Log retention     │ │
│  └────────────────────┘   └──────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Быстрый старт (Demo Mode)

```bash
cp .env.example .env
docker compose up --build
```

Открыть: **http://localhost:3000**

Demo-режим включён по умолчанию — данные сети не нужны, дашборд сразу показывает пример.

---

## Реальный режим (реальная сеть)

### 1. Требования

| Что нужно | Зачем |
|-----------|-------|
| Linux (Ubuntu, Debian, Raspbian и др.) | ARP-сканирование работает только на Linux |
| `net-tools` / `arp` | Чтение ARP-таблицы без root |
| `nmap` (опционально) | Более надёжный host discovery |
| `CAP_NET_RAW` или `sudo` | Только для DNS packet capture |

### 2. Настройка

```bash
cp .env.example .env
```

Отредактировать `.env`:

```env
DEMO_MODE=false
NETWORK_INTERFACE=eth0         # ваш сетевой интерфейс: ip link show
LOCAL_SUBNET=192.168.1.0/24   # ваша подсеть: ip route
ADMIN_PASSWORD=мой_пароль
```

### 3. Запуск

```bash
docker compose up --build -d
```

### 4. DNS-мониторинг (опционально)

Для пассивного перехвата DNS-запросов нужны права `CAP_NET_RAW`.

Раскомментировать в `docker-compose.yml`:

```yaml
services:
  backend:
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN
```

И в `.env`:

```env
DNS_CAPTURE_ENABLED=true
```

> **Важно:** DNS capture собирает только доменные имена (например `youtube.com`).
> Никаких URL-путей, cookies, содержимого запросов или TLS-данных.

---

## Функции

### Обнаружение устройств

- Читает `/proc/net/arp` (без root)
- Запускает `arp -n` как fallback
- Опционально: `nmap -sn` для полного sweep
- Определяет vendor по OUI (MAC-prefix lookup)
- Хранит: MAC, IP, hostname, vendor, first_seen, last_seen
- Помечает новые устройства
- Позволяет задать friendly name: "Телефон Андрей", "Телевизор"

### DNS-мониторинг

- Пассивный захват через scapy (если включён)
- Top domains за 1ч / 24ч / 7 дней
- Top devices по числу запросов
- Только домены — без URL, без содержимого

### Anomaly Detection (rule-based)

| Правило | Описание |
|---------|----------|
| `new_device` | Новое MAC-устройство в сети |
| `suspicious_domain` | DNS-запрос к известному плохому домену |
| `dns_spike` | Резкий рост запросов (>3× средний часовой) |
| `new_domain_burst` | Устройство обратилось к 30+ новых доменов за час |
| `unusual_time` | Активность устройства в 02:00–05:00 UTC |
| DGA detection | Высокоэнтропийное длинное доменное имя |

### Network Score

Рейтинг сети от 0 до 100 (A–F) на основе:
- Новых устройств
- Критических событий
- Предупреждений
- Устройств без имени

### Локальный помощник (без LLM)

Rule-based ответы на вопросы:
- "Почему интернет медленный?"
- "Есть ли новые устройства?"
- "Что подозрительного сегодня?"
- "Какие устройства самые активные?"

---

## Структура проекта

```
family-security/
├── docker-compose.yml
├── .env.example
├── README.md
├── data/
│   └── suspicious_domains.txt   # редактируемый список IoC
├── backend/
│   ├── main.py                  # FastAPI app + lifespan + scheduler
│   ├── config.py                # env-based config
│   ├── database.py              # SQLAlchemy + SQLite
│   ├── models.py                # Device, DNSQuery, Alert, AppSetting
│   ├── schemas.py               # Pydantic schemas
│   ├── routers/
│   │   ├── devices.py
│   │   ├── dns.py
│   │   ├── alerts.py
│   │   ├── dashboard.py
│   │   ├── assistant.py
│   │   └── settings.py
│   ├── services/
│   │   ├── device_scanner.py    # ARP + nmap discovery
│   │   ├── dns_monitor.py       # Packet capture thread
│   │   ├── anomaly_detector.py  # Rule-based detection
│   │   ├── network_score.py     # Score calculator
│   │   ├── assistant.py         # Query answerer
│   │   └── demo_seed.py         # Demo data generator
│   ├── utils/
│   │   ├── oui_lookup.py
│   │   └── suspicious_domains.py
│   └── tests/
│       └── test_anomaly.py
└── frontend/
    ├── src/
    │   ├── App.jsx
    │   ├── components/
    │   │   ├── Overview.jsx
    │   │   ├── Devices.jsx
    │   │   ├── DNSActivity.jsx
    │   │   ├── Alerts.jsx
    │   │   ├── Assistant.jsx
    │   │   └── Settings.jsx
    │   └── api/client.js
    └── nginx.conf
```

---

## Запуск тестов

```bash
cd backend
pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## Безопасность и конфиденциальность

- Все данные — только в локальном SQLite на вашем устройстве
- DNS capture: только доменные имена, никаких URL-путей/cookies/тел запросов
- Нет offensive функций: нет эксплуатации, нет перебора паролей, нет скрытного мониторинга
- Кнопка очистки логов на странице Настройки
- Retention: автоудаление старых данных по расписанию
- Admin password защищает endpoint /api/settings в продакшн-режиме

---

## Расширение

**Добавить full OUI database:**
```bash
wget -O data/oui.txt https://linuxnet.ca/ieee/oui.txt
```

**Добавить свои suspicious domains:**
```bash
echo "evil-domain.ru" >> data/suspicious_domains.txt
```

**Интеграция с Pi-hole:**
Настроить Pi-hole как DNS-сервер сети и добавить парсер его лога (`/var/log/pihole.log`) в `services/dns_monitor.py`.

---

## Что планируется в следующей версии

- [ ] Парсер логов Pi-hole/dnsmasq
- [ ] Экспорт данных в CSV
- [ ] Prometheus metrics endpoint
- [ ] Уведомления через Telegram Bot
- [ ] Временной график активности устройства
- [ ] Карточка устройства с историей событий
- [ ] Мобильно-адаптивный UI
