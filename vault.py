"""
vault.py — Core vault operations

The Vault class is the main interface for all credential management.
It sits between the CLI layer and the storage layer, enforcing
authentication on every operation and applying business rules such as
uniqueness constraints and conflict checks.

Authentication is delegated entirely to AuthService. Vault never
verifies identity itself — it only demands that AuthService confirms
the session is active before any operation proceeds.

Typical usage:
    vault = Vault()
    vault.auth.verify_master("masterpassword")
    vault.add_credential("github", "john@example.com", "ghpass123")
"""

from datetime import datetime
from shield_db import VaultData
from pwd_entity import Credential
from authservice import AuthService


class Vault:
    """
    Central interface for all vault credential operations.

    Vault owns one AuthService instance and one VaultData instance.
    Every public method begins by calling require_authenticated() —
    meaning no operation is reachable without a valid session.

    The uniqueness constraint is: service_name + label must be unique
    across all records. This allows multiple accounts per service
    (e.g. 'instagram/personal' and 'instagram/work') while preventing
    accidental duplicates.

    All string comparisons (service_name, label) are case-insensitive.
    Records are stored in their original casing but matched in lowercase.

    Attributes:
        vd   (VaultData):   Storage handler for credential records.
        auth (AuthService): Authentication and session manager.
    """

    def __init__(
        self,
        meta_file="vault_meta.json",
        data_file="vauld_data.json",
        attempts_file="attempts.json",
    ):
        """
        Initialise the Vault with its storage and auth dependencies.

        File name parameters exist primarily to support isolated test
        environments — in normal usage the defaults are used. All three
        files are created automatically if they do not exist.

        Args:
            meta_file     (str): JSON file storing the master password hash.
            data_file     (str): JSON file storing credential records.
            attempts_file (str): JSON file storing lockout state.
        """

        self.vd = VaultData(data_file)
        self.auth = AuthService(meta_file, attempts_file)

    def add_credential(self, service_name, username, password, label="default"):
        """
        Add a new credential record to the vault.

        Enforces uniqueness on the service_name + label combination.
        Comparison is case-insensitive, so 'GitHub/Default' and
        'github/default' are treated as the same record.

        Args:
            service_name (str):           Name of the service (e.g. 'github').
            username     (str):           Account username or email.
            password     (str):           Plain text password for this service.
            label        (str, optional): Account label for multiple accounts
                                          under the same service. Defaults to 'default'.

        Raises:
            PermissionError: If the session is not authenticated.
            ValueError:      If a credential with the same service_name/label already exists.
            ValueError:      If service_name, username, or password are empty.
        """

        self.auth.require_authenticated()

        # Case-insensitive duplicate check before inserting
        existing = [
            c
            for c in self.vd.get_all()
            if c.service_name.lower() == service_name.lower()
            and c.label.lower() == label.lower()
        ]

        if existing:
            raise ValueError(f"'{service_name}/{label}' already exists")

        credential_obj = Credential(service_name, username, password, label=label)

        self.vd.add(credential_obj)

    def list_services(self):
        """
        Return a list of all stored service/label pairs.

        Returned as a list of [service_name, label] pairs in lowercase,
        preserving insertion order. Used by the CLI to display what
        services are stored without exposing usernames or passwords.

        Returns:
            list[list[str]]: Each inner list is [service_name, label].
                             e.g. [['github', 'default'], ['instagram', 'work']]

        Raises:
            PermissionError: If the session is not authenticated.
        """

        self.auth.require_authenticated()

        credentials = self.vd.get_all()
        services = [[c.service_name.lower(), c.label.lower()] for c in credentials]

        return services

    def get_credential(self, service_name, label="default"):
        """
        Retrieve a single credential by service name and label.

        Matching is case-insensitive on both fields. Returns None if
        no matching record is found — callers are responsible for
        handling the None case explicitly.

        Args:
            service_name (str):           Name of the service to look up.
            label        (str, optional): Account label. Defaults to 'default'.

        Returns:
            Credential | None: The matching credential, or None if not found.

        Raises:
            PermissionError: If the session is not authenticated.
        """

        self.auth.require_authenticated()

        credentials = self.vd.get_all()

        for c in credentials:
            if (
                c.service_name.lower() == service_name.lower()
                and c.label.lower() == label.lower()
            ):
                return c
        return None

    def get_credential_by_service_name(self, service_name):
        """
        Retrieve all credentials stored under a given service name.

        Used when a service has multiple accounts (different labels)
        and the caller needs to present all options to the user before
        asking which label they want.

        Args:
            service_name (str): Name of the service to look up.

        Returns:
            list[Credential]: All matching credentials. Empty list if none found.

        Raises:
            PermissionError: If the session is not authenticated.
        """

        self.auth.require_authenticated()
        all_credentials = self.vd.get_all()

        credentials = [
            c for c in all_credentials if c.service_name.lower() == service_name.lower()
        ]

        return credentials

    def update_credential(
        self,
        service_name,
        label="default",
        new_service_name=None,
        new_label=None,
        new_username=None,
        new_password=None,
    ):
        """
        Update one or more fields of an existing credential.

        Only fields passed as non-None are updated. Fields left as None
        retain their current values. updated_at is always refreshed to
        the current time when any change is made.

        When renaming service_name or label, a conflict check runs first
        to ensure the new service_name/label combination does not already
        exist in the vault.

        Args:
            service_name     (str):           Current service name to identify the record.
            label            (str, optional): Current label to identify the record. Defaults to 'default'.
            new_service_name (str, optional): New service name. None keeps current.
            new_label        (str, optional): New label. None keeps current.
            new_username     (str, optional): New username. None keeps current.
            new_password     (str, optional): New password. None keeps current.

        Raises:
            PermissionError: If the session is not authenticated.
            ValueError:      If no credential exists with the given service_name/label.
            ValueError:      If renaming would create a duplicate service_name/label.
        """

        self.auth.require_authenticated()
        credential = self.get_credential(service_name, label)

        if not credential:
            raise ValueError(f"No credential with service '{service_name}' found")

        if new_service_name is not None:
            # Check the target name doesn't conflict with an existing record
            target_label = new_label if new_label else label
            conflict = self.get_credential(new_service_name, target_label)
            if conflict:
                raise ValueError(f"'{new_service_name}/{new_label}' already exists")
            credential.service_name = new_service_name

        if new_username is not None:
            credential.username = new_username
        if new_password is not None:
            credential.password = new_password
        if new_label is not None:
            credential.label = new_label

        # Always stamp the update time regardless of which fields changed
        credential.updated_at = datetime.now()

        self.vd.update(credential)

    def delete_credential(self, service_name, label="default"):
        """
        Permanently delete a credential from the vault.

        This operation is irreversible. The CLI is responsible for
        presenting a confirmation prompt before calling this method.

        Args:
            service_name (str):           Name of the service to delete.
            label        (str, optional): Label of the account to delete. Defaults to 'default'.

        Raises:
            PermissionError: If the session is not authenticated.
            ValueError:      If no credential exists with the given service_name/label.
        """

        self.auth.require_authenticated()

        credential = self.get_credential(service_name, label)

        if not credential:
            raise ValueError(
                f"No credential with service '{service_name}/{label}' found"
            )

        self.vd.delete(credential)


if __name__ == "__main__":
    pass
