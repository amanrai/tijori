#!/usr/bin/env python3
import json
import os
import sys
from getpass import getpass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:8211"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"


def clear_screen() -> None:
    os.system("clear")


def divider(char: str = "─", width: int = 52) -> str:
    return char * width


def print_header() -> None:
    print()
    print(f"{CYAN}{divider('═')}{RESET}")
    print(f"{BOLD}{CYAN}Scryer Secrets CLI{RESET}")
    print(f"{DIM}Service: {BASE_URL}{RESET}")
    print(f"{CYAN}{divider('═')}{RESET}")


def print_status(status: dict) -> None:
    initialized = "yes" if status.get("initialized") else "no"
    locked = "yes" if status.get("locked") else "no"
    unlocked_until = status.get("unlocked_until") or "—"
    default_ttl = status.get("default_unlock_ttl_seconds")
    ttl_label = str(default_ttl) if default_ttl is not None else "—"

    initialized_color = GREEN if status.get("initialized") else YELLOW
    locked_color = YELLOW if status.get("locked") else GREEN

    print(f"{BOLD}Status{RESET}")
    print(f"{DIM}{divider()}{RESET}")
    print(f"Initialized   : {initialized_color}{initialized}{RESET}")
    print(f"Locked        : {locked_color}{locked}{RESET}")
    print(f"Unlocked Until: {BLUE}{unlocked_until}{RESET}")
    print(f"Default TTL   : {BLUE}{ttl_label}{RESET}")
    print(f"{DIM}{divider()}{RESET}")


def print_success(message: str) -> None:
    print(f"{GREEN}[ok]{RESET} {message}")


def print_warning(message: str) -> None:
    print(f"{YELLOW}[warn]{RESET} {message}")


def print_error(message: str) -> None:
    print(f"{RED}[error]{RESET} {message}")


def request_json(method: str, path: str, payload: dict | None = None) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        detail = body
        try:
            parsed = json.loads(body)
            detail = parsed.get("detail", body)
        except json.JSONDecodeError:
            pass
        raise RuntimeError(f"{method} {path} failed: {exc.code} {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Unable to reach secrets service at {BASE_URL}: {exc.reason}") from exc


def prompt_init() -> str:
    answer = input("Secrets service is not initialized. Initialize now? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        return "[warn] Initialization skipped."

    while True:
        passphrase = getpass("Choose passphrase: ")
        confirm = getpass("Confirm passphrase: ")
        if not passphrase:
            print_warning("Passphrase cannot be empty.")
            continue
        if passphrase != confirm:
            print_warning("Passphrases did not match.")
            continue
        break

    ttl_text = input("Unlock TTL seconds [3600]: ").strip()
    ttl_seconds = int(ttl_text) if ttl_text else 3600

    result = request_json(
        "POST",
        "/init",
        {
            "passphrase": passphrase,
            "unlock_ttl_seconds": ttl_seconds,
        },
    )
    return f"[ok] Initialized secrets service. Unlocked Until: {result.get('unlocked_until') or '—'}"


def prompt_testing_reset() -> str:
    answer = input("Wipe all secrets, config, and sentinel data? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        return "[warn] Wipe cancelled."

    result = request_json("POST", "/testingReset")
    return f"[ok] Secrets service reset. Initialized: {'yes' if result.get('initialized') else 'no'}"


def prompt_add_secret() -> str:
    name = input("Secret name: ").strip()
    if not name:
        return "[warn] Secret name cannot be empty."

    user_defined_type = input("User-defined type: ").strip()
    if not user_defined_type:
        return "[warn] User-defined type cannot be empty."

    passphrase = getpass("Passphrase: ")
    if not passphrase:
        return "[warn] Passphrase cannot be empty."

    value = input("Secret value: ")
    result = request_json(
        "POST",
        "/secrets",
        {
            "name": name,
            "user_defined_type": user_defined_type,
            "passphrase": passphrase,
            "value": value,
        },
    )
    return (
        "[ok] Secret created. "
        f"Name: {result.get('name', '—')}, "
        f"Type: {result.get('user_defined_type', '—')}, "
        f"Secret ID: {result.get('secret_id', '—')}"
    )


def prompt_unlock_one_hour() -> str:
    passphrase = getpass("Passphrase: ")
    if not passphrase:
        return "[warn] Passphrase cannot be empty."

    result = request_json(
        "POST",
        "/unlock",
        {
            "passphrase": passphrase,
            "unlock_ttl_seconds": 3600,
        },
    )
    return f"[ok] Secrets service unlocked for 1 hour. Unlocked Until: {result.get('unlocked_until') or '—'}"


def prompt_lock() -> str:
    result = request_json("POST", "/lock")
    return f"[ok] Secrets service locked. Locked: {'yes' if result.get('locked') else 'no'}"


def prompt_show_secrets() -> str:
    result = request_json("GET", "/secrets")
    secrets = result.get("secrets", [])
    if not secrets:
        return "[ok] No secrets stored."

    lines = ["[ok] Existing secrets:"]
    for item in secrets:
        lines.append(
            "  - "
            f"{item.get('name', '—')} "
            f"[{item.get('user_defined_type', '—')}] "
            f"({item.get('secret_id', '—')}): "
            f"{item.get('value', '')}"
        )
    return "\n".join(lines)


def print_feedback(message: str | None) -> None:
    if not message:
        return
    if message.startswith("[ok] "):
        print_success(message.removeprefix("[ok] "))
        return
    if message.startswith("[warn] "):
        print_warning(message.removeprefix("[warn] "))
        return
    if message.startswith("[error] "):
        print_error(message.removeprefix("[error] "))
        return
    print(message)


def menu(status: dict) -> tuple[bool, str | None]:
    print()
    print(f"{BOLD}Actions{RESET}")
    print(f"{DIM}{divider()}{RESET}")
    print(f"{CYAN}1){RESET} Initialize service")
    print(f"{CYAN}2){RESET} Unlock for 1 hour")
    print(f"{CYAN}3){RESET} Lock")
    print(f"{CYAN}4){RESET} Add secret")
    print(f"{CYAN}5){RESET} Show existing secrets")
    print(f"{CYAN}6){RESET} Wipe everything")
    print(f"{CYAN}7){RESET} Exit")
    print(f"{DIM}{divider()}{RESET}")

    choice = input("Select action: ").strip()
    if choice == "1":
        if status.get("initialized", False):
            return True, "[warn] Secrets service is already initialized."
        return True, prompt_init()
    if choice == "2":
        if not status.get("initialized", False):
            return True, "[warn] Secrets service is not initialized."
        return True, prompt_unlock_one_hour()
    if choice == "3":
        if not status.get("initialized", False):
            return True, "[warn] Secrets service is not initialized."
        return True, prompt_lock()
    if choice == "4":
        if not status.get("initialized", False):
            return True, "[warn] Secrets service is not initialized."
        return True, prompt_add_secret()
    if choice == "5":
        if not status.get("initialized", False):
            return True, "[warn] Secrets service is not initialized."
        if status.get("locked", True):
            return True, "[warn] Secrets service is locked."
        return True, prompt_show_secrets()
    if choice == "6":
        return True, prompt_testing_reset()
    if choice == "7":
        print("Exiting.")
        return False, None
    return True, "[warn] Unknown option."


def main() -> int:
    try:
        status = request_json("GET", "/status")
    except Exception as exc:  # noqa: BLE001
        print(str(exc), file=sys.stderr)
        return 1

    feedback_message = None

    while True:
        try:
            status = request_json("GET", "/status")
        except Exception as exc:  # noqa: BLE001
            print(str(exc), file=sys.stderr)
            return 1

        clear_screen()
        print_header()
        print_status(status)
        print_feedback(feedback_message)
        try:
            should_continue, feedback_message = menu(status)
        except Exception as exc:  # noqa: BLE001
            feedback_message = f"[error] {exc}"
            should_continue = True
        if not should_continue:
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
