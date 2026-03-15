import sys, string, secrets

def print_error(error_msg: str) -> None:
    print(f"[ERROR]: {error_msg}", file=sys.stderr)


def print_msg(msg: str) -> None:
    print(f"[PWVAULT]: {msg}")

def print_password(password: str) -> None:
    if len(password) > 6:
        first = password[:2]
        last = password[-2:]
        print(f"[PWVAULT]: Password: {first}**********{last}")
    else:
        print(f"[PWVAULT]: Password: {password[0]}**********")

def generate_complex_password() -> string:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(24))
    return password

def generate_common_password() -> string:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*();"
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    return password

def generate_safe_password() -> string:
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    return password