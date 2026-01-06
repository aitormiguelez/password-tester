import hashlib
import requests

# Endpoint de la API de Pwned Passwords (no necesita API key)
HIBP_API = "https://api.pwnedpasswords.com/range/"


def sha1_hex(texto):
    h = hashlib.sha1()
    h.update(texto.encode("utf-8"))
    return h.hexdigest().upper()


def check_pwned(password, timeout=5.0):
    """
    Devuelve:
      - número de apariciones en filtraciones
      - 0 si no está
      - None si hay algún problema de red
    """
    if not password:
        return 0

    full_hash = sha1_hex(password)
    prefix = full_hash[:5]
    suffix = full_hash[5:]

    try:
        r = requests.get(HIBP_API + prefix, timeout=timeout)
    except Exception:
        return None

    if r.status_code != 200:
        return None

    for line in r.text.splitlines():
        if ":" not in line:
            continue
        suf, count = line.split(":")
        if suf.strip().upper() == suffix:
            try:
                return int(count.strip())
            except ValueError:
                return None

    return 0