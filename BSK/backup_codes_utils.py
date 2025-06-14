import secrets
import hashlib

from BSK.models import BackupCode


def generate_backup_codes(user, count=5):
    codes = []
    for _ in range(count):
        raw = secrets.token_urlsafe(8)
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        BackupCode.objects.create(user=user, code_hash=hashed)
        codes.append(raw)  # tylko raz pokazujemy surowy kod
    return codes