import sys

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