# shield.py — Shield Vault CLI
# Install: pip install -e .
# Usage:
#   shield setup    ← first run, create vault
#   shield login    ← open vault session

import argparse
import getpass
import os
from vault import Vault
from shield_db import VaultMeta


# ─── Display Helpers ─────────────────────────────────────────────────────────


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header():
    print()
    print("  ╔══════════════════════════════╗")
    print("  ║         SHIELD VAULT         ║")
    print("  ╚══════════════════════════════╝")
    print()


def divider():
    print("  " + "─" * 30)


def success(msg):
    print(f"\n  [✓] {msg}")


def error(msg):
    print(f"\n  [!] {msg}")


def info(msg):
    print(f"      {msg}")


def prompt_password(label="Master password"):
    """getpass with plain prompt — fixes Windows terminal freeze with special chars."""
    print(f"  {label:<18}: ", end="", flush=True)
    return getpass.getpass("")


# ─── Setup Command ────────────────────────────────────────────────────────────


def cmd_setup():

    clear()
    header()

    try:
        vm = VaultMeta()
    except Exception:
        error("Could not access vault storage. Check folder permissions.")
        return

    if vm.is_initialized():
        error("Vault already exists.")
        info("To reset, delete the 'database' folder manually.")
        print()
        return

    print("  Creating your vault.")
    print("  This master password cannot be recovered if lost.")
    print()

    while True:
        try:
            password = prompt_password("Master password")
        except KeyboardInterrupt:
            print()
            info("Setup cancelled.")
            return

        if not password or password.isspace():
            error("Password cannot be empty. Try again.")
            print()
            continue

        if len(password) < 6:
            error("Too short. Minimum 6 characters.")
            print()
            continue

        try:
            confirm = prompt_password("Confirm password")
        except KeyboardInterrupt:
            print()
            info("Setup cancelled.")
            return

        if password != confirm:
            error("Passwords do not match. Try again.")
            print()
            continue

        break

    try:
        vault = Vault()
        vault.auth.setup_master(password)
    except PermissionError:
        error("Vault already initialized. Setup blocked.")
        return
    except OSError:
        error("Could not write to disk. Check folder permissions.")
        return
    except Exception as e:
        error(f"Setup failed: {e}")
        return

    success("Vault created successfully.")
    info("Run 'shield login' to open your vault.")
    print()


# ─── Login Command ────────────────────────────────────────────────────────────


def cmd_login():

    clear()
    header()

    try:
        vm = VaultMeta()
    except Exception:
        error("Could not access vault storage. Check folder permissions.")
        return

    if not vm.is_initialized():
        error("No vault found.")
        info("Run 'shield setup' first to create your vault.")
        print()
        return

    try:
        vault = Vault()
    except Exception:
        error("Failed to load vault. Database may be corrupted.")
        return

    # ── Authentication gate ──
    print("  Enter your master password to continue.")
    print()

    while True:

        try:
            if vault.auth.is_locked_out():
                error("Too many failed attempts. Locked out for 30 seconds.")
                info("Try again after 30 seconds.")
                print()
                return
        except Exception:
            error("Could not read lockout state. Try again.")
            return

        try:
            password = prompt_password("Master password")
        except KeyboardInterrupt:
            print()
            info("Login cancelled.")
            return

        try:
            result = vault.auth.verify_master(password)
        except ValueError as e:
            # lockout raised mid-attempt
            error(str(e))
            info("Try again after 30 seconds.")
            print()
            return
        except Exception:
            error("Verification failed. Database may be corrupted.")
            return

        if result:
            clear()
            break

        try:
            failed = vault.auth.attempt.get_data()["failed_count"]
        except Exception:
            failed = 0

        remaining = 3 - failed

        if remaining <= 0:
            error("Too many failed attempts. Locked out for 30 seconds.")
            info("Try again after 30 seconds.")
            print()
            return

        error(f"Wrong password. {remaining} attempt(s) remaining.")
        print()

    # ── Session loop ──
    menu_loop(vault)


# ─── Menu ─────────────────────────────────────────────────────────────────────


def show_menu():
    divider()
    print("  [1]  List services")
    print("  [2]  Add credential")
    print("  [3]  Get credential")
    print("  [4]  Update credential")
    print("  [5]  Delete credential")
    print("  [6]  Exit")
    divider()
    print()


def menu_loop(vault: Vault):

    actions = {
        "1": action_list,
        "2": action_add,
        "3": action_get,
        "4": action_update,
        "5": action_delete,
    }

    while True:
        header()
        show_menu()

        try:
            choice = input("  Choice: ").strip()
        except KeyboardInterrupt:
            print()
            info("Use [6] to exit.")
            continue
        except EOFError:
            break

        if choice == "6":
            print()
            info("Vault locked. Goodbye.")
            print()
            break

        if choice not in actions:
            error("Invalid choice. Enter a number from 1 to 6.")
            input("\n  Press Enter to continue...")
            clear()
            continue

        try:
            actions[choice](vault)
        except KeyboardInterrupt:
            print()
            info("Action cancelled.")
        except PermissionError:
            error("Access denied. You are not authenticated.")
        except ValueError as e:
            error(str(e))
        except OSError:
            error("Disk error. Could not read or write vault data.")
        except Exception as e:
            error(f"Unexpected error: {e}")

        print()
        input("  Press Enter to continue...")
        clear()


# ─── Actions ─────────────────────────────────────────────────────────────────


def action_list(vault: Vault):

    services = vault.list_services()

    print()
    divider()
    print("  STORED SERVICES")
    divider()

    if not services:
        info("No credentials stored yet.")
    else:
        for i, (service, label) in enumerate(services, 1):
            if label == "default":
                print(f"  {i:>2}.  {service}")
            else:
                print(f"  {i:>2}.  {service}  ({label})")

    divider()


def action_add(vault: Vault):

    print()
    divider()
    print("  ADD CREDENTIAL")
    divider()
    print()

    try:
        service = input("  Service name      : ").strip()
        label = input("  Label    (default): ").strip() or "default"
        username = input("  Username          : ").strip()
        password = prompt_password("Password")
    except KeyboardInterrupt:
        print()
        info("Add cancelled.")
        return

    if not service or service.isspace():
        error("Service name cannot be empty.")
        return

    if not username or username.isspace():
        error("Username cannot be empty.")
        return

    if not password or password.isspace():
        error("Password cannot be empty.")
        return

    try:
        vault.add_credential(service, username, password, label=label)
    except ValueError as e:
        error(str(e))
        return

    success(f"'{service}/{label}' saved.")


def action_get(vault: Vault):

    print()
    divider()
    print("  GET CREDENTIAL")
    divider()
    print()

    try:
        service = input("  Service name      : ").strip()
    except KeyboardInterrupt:
        print()
        info("Cancelled.")
        return

    if not service or service.isspace():
        error("Service name cannot be empty.")
        return

    try:
        all_for_service = vault.get_credential_by_service_name(service)
    except Exception:
        error("Could not read vault data. Database may be corrupted.")
        return

    if not all_for_service:
        error(f"No credentials found for '{service}'.")
        return

    # Multiple accounts — show labels, ask which
    try:
        if len(all_for_service) > 1:
            print()
            info(f"Multiple accounts found for '{service}':")
            for i, c in enumerate(all_for_service, 1):
                print(f"        {i}. {c.label}")
            print()
            label = input("  Enter label: ").strip()
        else:
            label = input("  Label    (default): ").strip() or "default"
    except KeyboardInterrupt:
        print()
        info("Cancelled.")
        return

    try:
        credential = vault.get_credential(service, label)
    except Exception:
        error("Could not retrieve credential.")
        return

    if not credential:
        error(f"No credential found for '{service}/{label}'.")
        return

    print()
    divider()
    print(f"  Service  : {credential.service_name}")
    print(f"  Label    : {credential.label}")
    print(f"  Username : {credential.username}")
    divider()

    # Re-auth before showing password
    print()
    print("  Confirm master password to view password.")
    print()

    try:
        confirm = prompt_password("Master password")
    except KeyboardInterrupt:
        print()
        info("Password view cancelled.")
        return

    if vault.auth.confirm_identity(confirm):
        print()
        print(f"  Password : {credential.password}")
        divider()
        input("\n  Press Enter to continue...")
        clear()
    else:
        error("Wrong password. Password not shown.")


def action_update(vault: Vault):

    print()
    divider()
    print("  UPDATE CREDENTIAL")
    divider()
    print()

    try:
        service = input("  Service name      : ").strip()
        label = input("  Label    (default): ").strip() or "default"
    except KeyboardInterrupt:
        print()
        info("Update cancelled.")
        return

    if not service or service.isspace():
        error("Service name cannot be empty.")
        return

    try:
        credential = vault.get_credential(service, label)
    except Exception:
        error("Could not read vault data.")
        return

    if not credential:
        error(f"No credential found for '{service}/{label}'.")
        return

    print()
    info("Leave blank to keep current value.")
    print()

    try:
        new_service = (
            input(f"  Service name  [{credential.service_name}]: ").strip() or None
        )
        new_label = input(f"  Label         [{credential.label}]: ").strip() or None
        new_username = (
            input(f"  Username      [{credential.username}]: ").strip() or None
        )

        print()
        change_pw = input("  Change password? (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print()
        info("Update cancelled.")
        return

    new_password = None

    if change_pw == "y":
        try:
            new_password = prompt_password("New password")
        except KeyboardInterrupt:
            print()
            info("Update cancelled.")
            return

        if not new_password or new_password.isspace():
            error("Password cannot be empty. Update cancelled.")
            return

    try:
        vault.update_credential(
            service,
            label=label,
            new_service_name=new_service,
            new_label=new_label,
            new_username=new_username,
            new_password=new_password,
        )
    except ValueError as e:
        error(str(e))
        return
    except Exception:
        error("Could not save update. Database may be corrupted.")
        return

    success(f"'{service}/{label}' updated.")


def action_delete(vault: Vault):

    print()
    divider()
    print("  DELETE CREDENTIAL")
    divider()
    print()

    try:
        service = input("  Service name      : ").strip()
        label = input("  Label    (default): ").strip() or "default"
    except KeyboardInterrupt:
        print()
        info("Delete cancelled.")
        return

    if not service or service.isspace():
        error("Service name cannot be empty.")
        return

    try:
        credential = vault.get_credential(service, label)
    except Exception:
        error("Could not read vault data.")
        return

    if not credential:
        error(f"No credential found for '{service}/{label}'.")
        return

    print()

    try:
        confirm = (
            input(f"  Delete '{service}/{label}'? Cannot be undone. (y/n): ")
            .strip()
            .lower()
        )
    except KeyboardInterrupt:
        print()
        info("Delete cancelled.")
        return

    if confirm != "y":
        info("Delete cancelled.")
        return

    try:
        vault.delete_credential(service, label)
    except ValueError as e:
        error(str(e))
        return
    except Exception:
        error("Could not delete. Database may be corrupted.")
        return

    success(f"'{service}/{label}' deleted.")


# ─── Entry Point ──────────────────────────────────────────────────────────────


def main():

    parser = argparse.ArgumentParser(
        prog="shield",
        description="Shield Vault — CLI Password Manager",
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("setup", help="Create a new vault (first run only)")

    subparsers.add_parser("login", help="Open your vault")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup()
    elif args.command == "login":
        cmd_login()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
