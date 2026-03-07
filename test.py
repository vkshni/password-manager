# test.py — Password Manager Test Suite
# Tests all core functionality using isolated test files
# Cleans up after itself automatically

from engine import Vault
from authservice import AuthService
from db import VaultMeta, VaultData, Attempts
from pathlib import Path
import json

# ─── Test File Names ────────────────────────────────────────────────────────

TEST_META = "test_vault_meta.json"
TEST_DATA = "test_vault_data.json"
TEST_ATTEMPTS = "test_attempts.json"

MASTER_PASSWORD = "TestMaster@123"
WRONG_PASSWORD = "wrongpassword"

# ─── Helpers ────────────────────────────────────────────────────────────────

passed = 0
failed = 0


def get_vault():
    return Vault(meta_file=TEST_META, data_file=TEST_DATA, attempts_file=TEST_ATTEMPTS)


def get_auth():
    return AuthService(meta_file=TEST_META, attempts_file=TEST_ATTEMPTS)


def ok(test_name):
    global passed
    passed += 1
    print(f"  ✓  {test_name}")


def fail(test_name, reason):
    global failed
    failed += 1
    print(f"  ✗  {test_name}")
    print(f"       → {reason}")


def section(title):
    print(f"\n{'─' * 50}")
    print(f"  {title}")
    print(f"{'─' * 50}")


def cleanup():
    BASE_DIR = Path(__file__).parent
    DB_DIR = BASE_DIR / "database"
    for name in [TEST_META, TEST_DATA, TEST_ATTEMPTS]:
        path = DB_DIR / name
        if path.exists():
            path.unlink()


# ─── Tests ──────────────────────────────────────────────────────────────────


def test_setup_master():
    section("1. Setup Master Password")

    v = get_vault()

    # Setup should succeed on fresh vault
    try:
        v.auth.setup_master(MASTER_PASSWORD)
        ok("Master password setup succeeds on fresh vault")
    except Exception as e:
        fail("Master password setup succeeds on fresh vault", str(e))

    # Setup should fail if already initialized
    try:
        v.auth.setup_master("anotherpassword")
        fail("Re-setup rejected on initialized vault", "No error raised")
    except PermissionError:
        ok("Re-setup rejected on initialized vault")
    except Exception as e:
        fail("Re-setup rejected on initialized vault", str(e))


def test_login():
    section("2. Login")

    v = get_vault()

    # Correct password
    try:
        result = v.auth.verify_master(MASTER_PASSWORD)
        if result:
            ok("Correct master password returns True")
        else:
            fail("Correct master password returns True", "Returned False")
    except Exception as e:
        fail("Correct master password returns True", str(e))

    # Wrong password
    try:
        result = v.auth.verify_master(WRONG_PASSWORD)
        if not result:
            ok("Wrong master password returns False")
        else:
            fail("Wrong master password returns False", "Returned True")
    except Exception as e:
        fail("Wrong master password returns False", str(e))

    # is_authenticated flag set after correct login
    try:
        v2 = get_vault()
        v2.auth.verify_master(MASTER_PASSWORD)
        if v2.auth.is_authenticated:
            ok("is_authenticated is True after successful login")
        else:
            fail("is_authenticated is True after successful login", "Flag still False")
    except Exception as e:
        fail("is_authenticated is True after successful login", str(e))

    # is_authenticated stays False after wrong login
    try:
        v3 = get_vault()
        v3.auth.verify_master(WRONG_PASSWORD)
        if not v3.auth.is_authenticated:
            ok("is_authenticated stays False after failed login")
        else:
            fail("is_authenticated stays False after failed login", "Flag was set True")
    except Exception as e:
        fail("is_authenticated stays False after failed login", str(e))


def test_lockout():
    section("3. Lockout After 3 Failed Attempts")

    # Fresh auth instance with clean attempts
    auth = get_auth()

    # Force 3 wrong attempts
    try:
        for i in range(3):
            auth.verify_master(WRONG_PASSWORD)

        # 4th attempt should raise lockout
        try:
            auth.verify_master(WRONG_PASSWORD)
            fail("Locked out after 3 failed attempts", "No error raised on 4th attempt")
        except ValueError as e:
            if "locked" in str(e).lower():
                ok("Locked out after 3 failed attempts")
            else:
                fail("Locked out after 3 failed attempts", str(e))

    except Exception as e:
        fail("Lockout test setup failed", str(e))

    # Reset attempts for next tests
    attempts = Attempts(TEST_ATTEMPTS)
    attempts.reset()


def test_require_authenticated():
    section("4. require_authenticated Guard")

    v = get_vault()

    # Without login — should raise
    try:
        v.list_services()
        fail("Unauthenticated access blocked", "No error raised")
    except PermissionError:
        ok("Unauthenticated access blocked")
    except Exception as e:
        fail("Unauthenticated access blocked", str(e))

    # After login — should pass through
    try:
        v.auth.verify_master(MASTER_PASSWORD)
        v.list_services()
        ok("Authenticated access allowed")
    except Exception as e:
        fail("Authenticated access allowed", str(e))


def test_add_credential():
    section("5. Add Credential")

    v = get_vault()
    v.auth.verify_master(MASTER_PASSWORD)

    # Add valid credential
    try:
        v.add_credential("github", "john@example.com", "ghpass123")
        ok("Add valid credential succeeds")
    except Exception as e:
        fail("Add valid credential succeeds", str(e))

    # Duplicate service/label rejected
    try:
        v.add_credential("github", "john@example.com", "ghpass123")
        fail("Duplicate service/label rejected", "No error raised")
    except ValueError:
        ok("Duplicate service/label rejected")
    except Exception as e:
        fail("Duplicate service/label rejected", str(e))

    # Same service different label allowed
    try:
        v.add_credential("github", "work@example.com", "ghworkpass", label="work")
        ok("Same service different label allowed")
    except Exception as e:
        fail("Same service different label allowed", str(e))

    # Empty service name rejected
    try:
        v.add_credential("", "john@example.com", "pass")
        fail("Empty service name rejected", "No error raised")
    except ValueError:
        ok("Empty service name rejected")
    except Exception as e:
        fail("Empty service name rejected", str(e))

    # Empty username rejected
    try:
        v.add_credential("netflix", "", "pass")
        fail("Empty username rejected", "No error raised")
    except ValueError:
        ok("Empty username rejected")
    except Exception as e:
        fail("Empty username rejected", str(e))

    # Empty password rejected
    try:
        v.add_credential("netflix", "john@example.com", "")
        fail("Empty password rejected", "No error raised")
    except ValueError:
        ok("Empty password rejected")
    except Exception as e:
        fail("Empty password rejected", str(e))


def test_list_services():
    section("6. List Services")

    v = get_vault()
    v.auth.verify_master(MASTER_PASSWORD)

    try:
        services = v.list_services()

        # Should contain github entries from previous test
        names = [s[0] for s in services]
        if "github" in names:
            ok("Listed services contains added credentials")
        else:
            fail("Listed services contains added credentials", f"Got: {services}")

        # Should show both github labels
        github_entries = [s for s in services if s[0] == "github"]
        if len(github_entries) == 2:
            ok("Both github labels shown in list")
        else:
            fail("Both github labels shown in list", f"Got: {github_entries}")

    except Exception as e:
        fail("list_services() runs without error", str(e))


def test_get_credential():
    section("7. Get Credential")

    v = get_vault()
    v.auth.verify_master(MASTER_PASSWORD)

    # Get existing credential
    try:
        c = v.get_credential("github")
        if c and c.service_name.lower() == "github":
            ok("Get existing credential returns correct record")
        else:
            fail("Get existing credential returns correct record", f"Got: {c}")
    except Exception as e:
        fail("Get existing credential returns correct record", str(e))

    # Get with label
    try:
        c = v.get_credential("github", label="work")
        if c and c.label.lower() == "work":
            ok("Get credential with specific label works")
        else:
            fail("Get credential with specific label works", f"Got: {c}")
    except Exception as e:
        fail("Get credential with specific label works", str(e))

    # Get non-existent returns None
    try:
        c = v.get_credential("nonexistentservice")
        if c is None:
            ok("Get non-existent credential returns None")
        else:
            fail("Get non-existent credential returns None", f"Got: {c}")
    except Exception as e:
        fail("Get non-existent credential returns None", str(e))

    # Get by service name returns all matching
    try:
        results = v.get_credential_by_service_name("github")
        if len(results) == 2:
            ok("get_credential_by_service_name returns all matching records")
        else:
            fail(
                "get_credential_by_service_name returns all matching records",
                f"Got {len(results)} results",
            )
    except Exception as e:
        fail("get_credential_by_service_name returns all matching records", str(e))


def test_update_credential():
    section("8. Update Credential")

    v = get_vault()
    v.auth.verify_master(MASTER_PASSWORD)

    # Add a fresh credential to update
    v.add_credential("twitter", "old_user", "old_pass")

    # Update username
    try:
        v.update_credential("twitter", new_username="new_user")
        c = v.get_credential("twitter")
        if c and c.username == "new_user":
            ok("Update username works")
        else:
            fail("Update username works", f"Got username: {c.username if c else None}")
    except Exception as e:
        fail("Update username works", str(e))

    # Update password
    try:
        v.update_credential("twitter", new_password="new_pass")
        c = v.get_credential("twitter")
        if c and c.password == "new_pass":
            ok("Update password works")
        else:
            fail("Update password works", f"Got password: {c.password if c else None}")
    except Exception as e:
        fail("Update password works", str(e))

    # updated_at is set after update
    try:
        c = v.get_credential("twitter")
        if c and c.updated_at is not None:
            ok("updated_at is set after update")
        else:
            fail("updated_at is set after update", "updated_at is None")
    except Exception as e:
        fail("updated_at is set after update", str(e))

    # Update non-existent raises error
    try:
        v.update_credential("doesnotexist", new_username="x")
        fail("Update non-existent credential raises error", "No error raised")
    except ValueError:
        ok("Update non-existent credential raises error")
    except Exception as e:
        fail("Update non-existent credential raises error", str(e))

    # Rename to existing service/label raises error
    try:
        v.update_credential("twitter", new_service_name="github")
        fail("Rename to existing service/label rejected", "No error raised")
    except ValueError:
        ok("Rename to existing service/label rejected")
    except Exception as e:
        fail("Rename to existing service/label rejected", str(e))


def test_delete_credential():
    section("9. Delete Credential")

    v = get_vault()
    v.auth.verify_master(MASTER_PASSWORD)

    # Add credential to delete
    v.add_credential("reddit", "redditor", "redditpass")

    # Delete existing
    try:
        v.delete_credential("reddit")
        c = v.get_credential("reddit")
        if c is None:
            ok("Delete existing credential works")
        else:
            fail(
                "Delete existing credential works",
                "Credential still exists after delete",
            )
    except Exception as e:
        fail("Delete existing credential works", str(e))

    # Delete non-existent raises error
    try:
        v.delete_credential("nonexistentservice")
        fail("Delete non-existent credential raises error", "No error raised")
    except ValueError:
        ok("Delete non-existent credential raises error")
    except Exception as e:
        fail("Delete non-existent credential raises error", str(e))


def test_persistence():
    section("10. Persistence — Data Survives Across Instances")

    # Write with one instance
    v1 = get_vault()
    v1.auth.verify_master(MASTER_PASSWORD)
    v1.add_credential("spotify", "music_lover", "spotifypass")

    # Read with a completely new instance
    v2 = get_vault()
    v2.auth.verify_master(MASTER_PASSWORD)

    try:
        c = v2.get_credential("spotify")
        if c and c.username == "music_lover":
            ok("Data persists across separate Vault instances")
        else:
            fail("Data persists across separate Vault instances", f"Got: {c}")
    except Exception as e:
        fail("Data persists across separate Vault instances", str(e))


# ─── Run All Tests ───────────────────────────────────────────────────────────


def run():
    print("\n" + "═" * 50)
    print("  PASSWORD MANAGER — TEST SUITE")
    print("═" * 50)

    try:
        test_setup_master()
        test_login()
        test_lockout()
        test_require_authenticated()
        test_add_credential()
        test_list_services()
        test_get_credential()
        test_update_credential()
        test_delete_credential()
        test_persistence()

    finally:
        # Always clean up — even if tests crash midway
        cleanup()
        print(f"\n{'═' * 50}")
        print(f"  Tests complete. Test files deleted.")
        print(f"{'═' * 50}")
        print(f"\n  Passed : {passed}")
        print(f"  Failed : {failed}")
        total = passed + failed
        print(f"  Total  : {total}")
        if failed == 0:
            print("\n  All tests passed. ✓")
        else:
            print(f"\n  {failed} test(s) failed. Check output above.")
        print()


if __name__ == "__main__":
    run()
