"""
OUI (Organizationally Unique Identifier) vendor lookup.
Uses a bundled minimal OUI table for common vendors.
For a full database, download from https://linuxnet.ca/ieee/oui.txt
"""
import os
from functools import lru_cache

# Embedded minimal OUI table for the most common vendors
_BUILTIN_OUI: dict[str, str] = {
    "00:00:0C": "Cisco",
    "00:1A:11": "Google",
    "00:17:F2": "Apple",
    "00:1C:B3": "Apple",
    "00:23:12": "Apple",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Apple",
    "AC:BC:32": "Apple",
    "7C:D1:C3": "Apple",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1B:44": "Samsung",
    "00:26:37": "Samsung",
    "50:32:75": "Samsung",
    "E8:03:9A": "Samsung",
    "CC:32:E5": "Huawei",
    "00:E0:FC": "Huawei",
    "48:FD:8E": "Huawei",
    "00:25:9C": "Cisco",
    "00:1D:70": "Cisco",
    "F8:7B:20": "TP-Link",
    "50:C7:BF": "TP-Link",
    "B0:4E:26": "TP-Link",
    "00:1F:1F": "D-Link",
    "14:D6:4D": "D-Link",
    "1C:7E:E5": "D-Link",
    "00:26:B9": "Dell",
    "18:66:DA": "Dell",
    "00:14:22": "Dell",
    "00:21:6B": "Intel",
    "8C:8D:28": "Intel",
    "B4:B6:76": "Intel",
    "00:50:F2": "Microsoft",
    "28:18:78": "Microsoft",
    "3C:18:A0": "Microsoft",
    "00:23:AE": "Xbox",
    "7C:1E:52": "Sony",
    "00:13:A9": "Sony",
    "10:4A:7D": "Amazon",
    "44:65:0D": "Amazon",
    "FC:A1:83": "Amazon",
    "B0:FC:0D": "LG",
    "A8:23:FE": "LG",
    "00:1E:75": "LG",
    "00:12:EE": "Netgear",
    "20:4E:7F": "Netgear",
    "A0:40:A0": "Netgear",
}


@lru_cache(maxsize=1)
def _load_oui_file(path: str) -> dict[str, str]:
    table: dict[str, str] = {}
    if not os.path.exists(path):
        return table
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) == 2:
                        oui = parts[0].strip().replace("-", ":").upper()
                        vendor = parts[1].strip()
                        table[oui] = vendor
    except Exception:
        pass
    return table


def lookup_vendor(mac: str, oui_file: str = "") -> str:
    if not mac:
        return "Unknown"
    mac_upper = mac.upper().replace("-", ":").replace(".", ":")
    # normalise to xx:xx:xx:xx:xx:xx
    parts = mac_upper.split(":")
    if len(parts) < 3:
        return "Unknown"
    oui = ":".join(parts[:3])

    # Try builtin first
    if oui in _BUILTIN_OUI:
        return _BUILTIN_OUI[oui]

    # Try full file
    if oui_file:
        file_table = _load_oui_file(oui_file)
        if oui in file_table:
            return file_table[oui]

    return "Unknown"
