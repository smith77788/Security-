"""
Реальная блокировка устройств через iptables (DROP по MAC-адресу).
Требует CAP_NET_ADMIN или запуск от root.
Если iptables недоступен — молча деградирует до режима наблюдения.
"""
import logging
import subprocess

log = logging.getLogger("network_blocker")


def is_available() -> bool:
    """Проверяет, доступен ли iptables с нужными правами."""
    try:
        result = subprocess.run(
            ["iptables", "-L", "FORWARD", "-n"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _rule_exists(mac: str) -> bool:
    try:
        result = subprocess.run(
            ["iptables", "-C", "FORWARD", "-m", "mac",
             "--mac-source", mac.upper(), "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def block_mac(mac: str) -> bool:
    """
    Добавляет правило iptables: DROP всех пакетов от этого MAC.
    Возвращает True если заблокировано (или уже было заблокировано).
    """
    mac = mac.upper()
    try:
        if _rule_exists(mac):
            return True
        result = subprocess.run(
            ["iptables", "-I", "FORWARD", "-m", "mac",
             "--mac-source", mac, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            log.info("iptables: заблокирован MAC %s", mac)
            return True
        log.warning("iptables block failed [%s]: %s", mac, result.stderr.decode())
        return False
    except FileNotFoundError:
        log.debug("iptables не найден — работаем в режиме наблюдения")
        return False
    except Exception as e:
        log.warning("iptables block error [%s]: %s", mac, e)
        return False


def unblock_mac(mac: str) -> bool:
    """Удаляет правило DROP для данного MAC."""
    mac = mac.upper()
    try:
        if not _rule_exists(mac):
            return True
        result = subprocess.run(
            ["iptables", "-D", "FORWARD", "-m", "mac",
             "--mac-source", mac, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        if result.returncode == 0:
            log.info("iptables: разблокирован MAC %s", mac)
            return True
        log.warning("iptables unblock failed [%s]: %s", mac, result.stderr.decode())
        return False
    except Exception as e:
        log.warning("iptables unblock error [%s]: %s", mac, e)
        return False


def sync_blocks(blocked_macs: list[str]):
    """
    При старте системы синхронизирует iptables с базой заблокированных устройств.
    Вызывается один раз из main.py lifespan.
    """
    if not is_available():
        log.info("iptables недоступен — блокировка только в режиме наблюдения")
        return
    count = 0
    for mac in blocked_macs:
        if block_mac(mac):
            count += 1
    log.info("iptables sync: %d/%d MACs заблокировано", count, len(blocked_macs))


def get_blocked_macs() -> list[str]:
    """Читает текущие DROP-правила для MAC из iptables FORWARD."""
    macs = []
    try:
        result = subprocess.run(
            ["iptables", "-L", "FORWARD", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "MAC" in line and "DROP" in line:
                # Строка вида: DROP  all  --  0.0.0.0/0  0.0.0.0/0  MAC AA:BB:CC:DD:EE:FF
                parts = line.split()
                for p in parts:
                    if len(p) == 17 and p.count(":") == 5:
                        macs.append(p.upper())
    except Exception:
        pass
    return macs
