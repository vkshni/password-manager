"""
pwd_entity.py — Credential data model

Defines the Credential class which represents a single stored credential
record in the vault. Handles serialization, deserialization, and field
validation. All datetime values use the format: DD-MM-YYYYTHH:MM:SS.
"""

from uuid import uuid4
from datetime import datetime

DATETIME_FORMAT = "%d-%m-%YT%H:%M:%S"


class Credential:
    """
    Represents a single credential record stored in the vault.

    Each credential belongs to a service (e.g. 'github') and optionally
    carries a label to distinguish multiple accounts under the same service
    (e.g. 'personal', 'work'). The combination of service_name and label
    must be unique across the vault.

    Passwords are stored as plain text — security is enforced at the vault
    layer via master password authentication, not at the record level.

    Attributes:
        credential_id (str): UUID uniquely identifying this record. Immutable after creation.
        service_name  (str): Name of the service (e.g. 'github', 'gmail').
        username      (str): Account username or email for this service.
        password      (str): Plain text password for this service.
        label         (str): Distinguishes multiple accounts per service. Defaults to 'default'.
        created_at    (datetime): Timestamp of when this record was first created.
        updated_at    (datetime | None): Timestamp of last update. None if never updated.
    """

    def __init__(
        self,
        service_name,
        username,
        password,
        created_at=None,
        updated_at=None,
        credential_id=None,
        label="default",
    ):
        """
        Initialise a Credential instance.

        When creating a new credential, only service_name, username, and
        password are required. All other fields are either auto-generated
        or optional.

        When loading an existing credential from storage, all fields should
        be passed explicitly — use from_dict() for this purpose.

        Args:
            service_name  (str):            Name of the service.
            username      (str):            Account username or email.
            password      (str):            Plain text password.
            created_at    (str, optional):  Datetime string in DATETIME_FORMAT.
                                            Defaults to current time if not provided.
            updated_at    (str, optional):  Datetime string in DATETIME_FORMAT.
                                            Defaults to None if not provided.
            credential_id (str, optional):  Existing UUID string. Auto-generated if not provided.
            label         (str, optional):  Account label. Defaults to 'default'.

        Raises:
            ValueError: If service_name, username, or password are empty or whitespace.
        """

        # Use provided ID when loading from storage, generate new UUID for fresh records
        self.credential_id = str(credential_id) if credential_id else str(uuid4())

        self.service_name = service_name
        self.username = username
        self.password = password
        self.label = label

        # Parse datetime strings when loading from storage, default to now for new records
        self.created_at = (
            datetime.strptime(created_at, DATETIME_FORMAT)
            if created_at
            else datetime.now()
        )

        # updated_at stays None until the record is first modified
        self.updated_at = (
            datetime.strptime(updated_at, DATETIME_FORMAT) if updated_at else None
        )

        self.validate_fields()

    def to_dict(self):
        """
        Serialize this credential to a plain dictionary for JSON storage.

        Datetime objects are converted to strings using DATETIME_FORMAT.
        updated_at is stored as None if the record has never been updated.

        Returns:
            dict: All credential fields in JSON-serializable form.
        """

        return {
            "credential_id": self.credential_id,
            "service_name": self.service_name,
            "label": self.label,
            "username": self.username,
            "password": self.password,
            "created_at": self.created_at.strftime(DATETIME_FORMAT),
            # None is stored as JSON null — avoids empty string breaking strptime on load
            "updated_at": (
                self.updated_at.strftime(DATETIME_FORMAT) if self.updated_at else None
            ),
        }

    @classmethod
    def from_dict(cls, credential_dict):
        """
        Deserialize a credential from a dictionary loaded from JSON storage.

        This is the intended way to reconstruct a Credential from persisted
        data. All fields are passed as keyword arguments to avoid positional
        ordering bugs if __init__ parameters ever change.

        Args:
            credential_dict (dict): A dictionary matching the structure produced by to_dict().

        Returns:
            Credential: A fully initialised Credential instance.
        """

        return cls(
            service_name=credential_dict["service_name"],
            username=credential_dict["username"],
            password=credential_dict["password"],
            created_at=credential_dict["created_at"],
            updated_at=credential_dict["updated_at"],
            credential_id=credential_dict["credential_id"],
            label=credential_dict["label"],
        )

    def validate_fields(self):
        """
        Validate that required fields are non-empty and not purely whitespace.

        Called at the end of __init__ so every Credential instance is
        guaranteed to be valid on creation. Raises immediately on the
        first invalid field found.

        Raises:
            ValueError: If service_name, username, or password are empty or whitespace.
        """

        if not self.service_name or self.service_name.isspace():
            raise ValueError("Empty field: 'service name'")
        if not self.username or self.username.isspace():
            raise ValueError("Empty field: 'username'")
        if not self.password or self.password.isspace():
            raise ValueError("Empty field: 'password'")
