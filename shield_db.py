"""
shield_db.py — Storage layer for vault data

This module is the lowest layer in the system. It handles all reading
and writing to disk and exposes three domain-specific storage classes
that the rest of the system interacts with. Nothing above this layer
touches the filesystem directly.

Architecture:
    JSONFile    — generic file I/O. No domain knowledge.
    VaultMeta   — master password hash storage. One record only.
    VaultData   — credential record storage. List of Credential objects.
    Attempts    — failed login attempt and lockout state storage.

All data is persisted as JSON inside a 'database/' subdirectory relative
to this file. The directory is created automatically on import if it does
not exist.

Storage files:
    vault_meta.json  — {"master_password_hash": "<sha256_hex>"}
    vault_data.json  — [{"credential_id": ..., "service_name": ..., ...}, ...]
    attempts.json    — {"failed_count": 0, "locked_until": null}
"""

from pathlib import Path
import json

from pwd_entity import Credential

BASE_DIR = Path(__file__).parent

# Ensure the database directory exists before any file operations run
DB_DIR = BASE_DIR / "database/"
DB_DIR.mkdir(exist_ok=True)


class JSONFile:
    """
    Generic JSON file handler. Reads and writes arbitrary JSON data.

    This class has no knowledge of what the data means — it only deals
    with serialization and file I/O. All domain logic lives in the
    higher-level classes that use it.

    A new file is initialized with JSON null on creation. Each higher-level
    class is responsible for detecting null and writing its own valid
    empty structure during initialization.

    Attributes:
        file_path (Path): Absolute path to the managed JSON file.
    """

    def __init__(self, file_name):
        """
        Initialise the handler and ensure the backing file exists.

        Args:
            file_name (str): Name of the JSON file (e.g. 'vault_meta.json').
                             Created inside the 'database/' directory.
        """

        self.file_path = self.create(file_name)

    def create(self, file_name):
        """
        Create the JSON file if it does not already exist.

        Writes JSON null as the initial content so the file is always
        valid JSON. Higher-level initialize() methods handle replacing
        null with their own empty structure on first use.

        Args:
            file_name (str): Name of the JSON file to create.

        Returns:
            Path: Absolute path to the file.
        """

        path = BASE_DIR / "database" / file_name
        if not path.exists():
            with open(path, "w") as f:
                json.dump(None, f, indent=4)
        return path

    def read_all(self) -> list | dict:
        """
        Read and deserialize the entire JSON file contents.

        Returns whatever structure is stored — could be a list, dict,
        or None if the file contains JSON null. Callers are responsible
        for handling None.

        Returns:
            list | dict | None: Deserialized JSON contents.

        Raises:
            json.JSONDecodeError: If the file contains malformed JSON.
            OSError:              If the file cannot be read.
        """

        with open(self.file_path, "r") as f:
            data = json.load(f)
            return data

    def write_all(self, data):
        """
        Serialize and overwrite the entire JSON file with new data.

        This is a full overwrite — partial updates are not supported
        at this level. Higher-level classes read, modify, then write back.

        Args:
            data (list | dict | None): Data to serialize and write.

        Raises:
            OSError: If the file cannot be written.
        """

        with open(self.file_path, "w") as f:
            json.dump(data, f, indent=4)


class VaultMeta:
    """
    Storage handler for the master password hash.

    Manages a single JSON file containing one field: the SHA-256 hash
    of the master password. This file is the lock mechanism for the
    entire vault — if it is missing or corrupted, the vault is treated
    as uninitialized and all stored credentials become inaccessible.

    The raw password is never stored here or anywhere else. Only the
    hash is written, and only once during setup.

    Attributes:
        json_handler (JSONFile): File I/O handler for the meta file.
    """

    def __init__(self, file_name="vault_meta.json"):
        """
        Initialise VaultMeta with its backing file.

        Args:
            file_name (str): JSON file for storing the master password hash.
                             Defaults to 'vault_meta.json'.
        """

        self.json_handler = JSONFile(file_name)

    def is_initialized(self):
        """
        Check whether the master password has been set up.

        Attempts to read the master password hash — if it succeeds,
        the vault is initialized. Used by AuthService to block re-setup
        and by the CLI to route first-run vs returning-user flow.

        Returns:
            bool: True if a master password hash exists, False otherwise.
        """

        try:
            self.get_master_password_hash()
            return True
        except:
            return False

    def setup(self, master_password_hash):
        """
        Write the master password hash to storage.

        Called once during first-time vault setup. Overwrites the entire
        file — only the hash is stored, nothing else.

        Args:
            master_password_hash (str): SHA-256 hex digest of the master password.
        """

        data = {"master_password_hash": master_password_hash}
        self.json_handler.write_all(data)

    def get_master_password_hash(self):
        """
        Retrieve the stored master password hash.

        Returns:
            str: The SHA-256 hex digest stored during setup.

        Raises:
            KeyError:   If the file exists but does not contain the expected field.
            TypeError:  If the file contains null (vault not initialized).
            OSError:    If the file cannot be read.
        """

        data = self.json_handler.read_all()
        return data["master_password_hash"]


class VaultData:
    """
    Storage handler for credential records.

    Manages a JSON file containing a list of credential dictionaries.
    Converts between raw dicts and Credential objects on every read/write
    so that higher layers always work with typed Credential instances.

    The file is initialized to an empty list on first use. Operations
    are read-modify-write — the entire list is loaded, changed in memory,
    then written back.

    Attributes:
        json_handler (JSONFile): File I/O handler for the vault data file.
    """

    def __init__(self, file_name="vault_data.json"):
        """
        Initialise VaultData and ensure the file contains a valid list.

        Args:
            file_name (str): JSON file for storing credential records.
                             Defaults to 'vault_data.json'.
        """

        self.json_handler = JSONFile(file_name)
        self.initialize()

    def initialize(self):
        """
        Ensure the vault data file contains a valid empty list.

        Handles two failure cases: JSON null (file just created) and
        malformed JSON (corrupted file). In both cases the file is reset
        to an empty list rather than crashing — a corrupted vault data
        file is treated as an empty vault.
        """

        try:
            data = self.json_handler.read_all()
            # New files contain null — replace with empty list
            if data is None:
                self.json_handler.write_all([])
        except (json.JSONDecodeError, ValueError):
            self.json_handler.write_all([])

    def add(self, credential: Credential):
        """
        Append a new credential record to the vault.

        Serializes the Credential to a dict and appends it to the stored
        list. No uniqueness check is performed here — that is enforced
        by the Vault layer before this method is called.

        Args:
            credential (Credential): The credential object to persist.
        """

        credential_dict = credential.to_dict()
        data = self.json_handler.read_all()
        data.append(credential_dict)
        self.json_handler.write_all(data)

    def get_all(self):
        """
        Load and deserialize all stored credential records.

        Reads the raw list from disk and converts every dict back into
        a Credential object. Always reflects the current state of the
        file — there is no in-memory cache.

        Returns:
            list[Credential]: All stored credentials. Empty list if none exist.
        """

        raw_data = self.json_handler.read_all()
        vault_data = [Credential.from_dict(c) for c in raw_data]
        return vault_data

    def update(self, credential: Credential):
        """
        Replace an existing credential record in storage.

        Finds the record matching credential.credential_id and replaces
        it in place. Operates on raw dicts to avoid an unnecessary
        deserialization round-trip. If no matching ID is found, the
        file is written back unchanged.

        Args:
            credential (Credential): The updated credential to persist.
                                     Matched by credential_id.
        """

        data = self.json_handler.read_all()

        for i, c in enumerate(data):
            if c["credential_id"] == credential.credential_id:
                data[i] = credential.to_dict()
                break

        self.json_handler.write_all(data)

    def delete(self, credential: Credential):
        """
        Remove a credential record from storage permanently.

        Filters out the record matching credential.credential_id and
        writes the remaining records back. This operation is irreversible.

        Args:
            credential (Credential): The credential to remove.
                                     Matched by credential_id.
        """

        data = self.get_all()

        filtered_data = [
            c.to_dict() for c in data if c.credential_id != credential.credential_id
        ]

        self.json_handler.write_all(filtered_data)


class Attempts:
    """
    Storage handler for failed login attempt and lockout state.

    Manages a JSON file with two fields: failed_count (int) and
    locked_until (str | null). This file persists across program
    restarts so that lockout cannot be bypassed by simply closing
    and reopening the program.

    State is reset automatically when a successful login occurs or
    when a lockout period expires.

    Stored structure:
        {"failed_count": 0, "locked_until": null}
        {"failed_count": 3, "locked_until": "08-03-2026T14:32:10"}

    Attributes:
        json_handler (JSONFile): File I/O handler for the attempts file.
    """

    def __init__(self, file_name="attempts.json"):
        """
        Initialise Attempts and ensure the file contains valid state.

        Args:
            file_name (str): JSON file for storing attempt and lockout state.
                             Defaults to 'attempts.json'.
        """

        self.json_handler = JSONFile(file_name)
        self.initialize()

    def initialize(self):
        """
        Ensure the attempts file contains valid initial state.

        Handles null (new file) and malformed JSON (corruption) by
        resetting to the default clean state. Unlike VaultData, a
        corrupted attempts file is reset rather than crashing — losing
        lockout state is preferable to blocking all login attempts.
        """

        try:
            data = self.json_handler.read_all()
            if data is None:
                self.reset()
        except (json.JSONDecodeError, ValueError):
            self.reset()

    def reset(self):
        """
        Reset attempt state to clean defaults.

        Sets failed_count to 0 and locked_until to null. Called on
        successful login, on lockout expiry, and during initialization
        of a corrupt or missing file.
        """

        data = {"failed_count": 0, "locked_until": None}
        self.json_handler.write_all(data)

    def update(self, failed_count=None, locked_until=None):
        """
        Update one or both fields of the attempts state.

        Only fields passed as non-None are written. This means passing
        locked_until=None does NOT clear the lockout — use reset() for
        that. To set locked_until to null explicitly, use reset() instead
        of update().

        Args:
            failed_count (int, optional):  New failed attempt count.
            locked_until (str, optional):  Lockout expiry datetime string
                                           in DD-MM-YYYYTHH:MM:SS format.
                                           Pass None to leave unchanged.
        """

        data = self.json_handler.read_all()
        if failed_count is not None:
            data["failed_count"] = failed_count
        if locked_until is not None:
            data["locked_until"] = locked_until

        self.json_handler.write_all(data)

    def get_data(self):
        """
        Retrieve the current attempt state as a raw dictionary.

        Returns the dict directly — callers access fields by key.
        Always reads from disk to reflect the most current state.

        Returns:
            dict: {"failed_count": int, "locked_until": str | None}
        """

        data = self.json_handler.read_all()
        return data


if __name__ == "__main__":
    pass
