import hashlib
import requests

def is_password_pwned(password, threshold=1):
    """
    Sprawdza, czy hasło występuje w publicznych wyciekach za pomocą API Have I Been Pwned.
    threshold - ile razy hasło musi się pojawić, by zostało uznane za 'pwned'
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return False  # Jeśli API padnie, nie blokujemy usera

        for line in response.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix and int(count) >= threshold:
                return True
    except Exception:
        return False  # fail safe

    return False
