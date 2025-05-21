from django.utils.timezone import now, timedelta

MAX_FAILED_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15


def check_and_handle_blocking(user, success):
    if success:
        user.failed_attempts = 0
        user.blocked_until = None
        user.is_blocked = False
        user.save()
        return None

    # Failed login attempt
    user.failed_attempts += 1
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        user.blocked_until = now() + timedelta(minutes=BLOCK_DURATION_MINUTES)
        user.is_blocked = True
    user.save()

    if user.blocked_until and user.blocked_until > now():
        return 'Konto zablokowane'

    return None
