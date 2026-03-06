from uuid import uuid4
from datetime import datetime

# Credential Entity


class Credential:

    def __init__(
        self,
        service_name,
        username,
        password,
        created_at=None,
        updated_at=None,
        id=None,
        label="default",
    ):

        self.id = str(id) if id else str(uuid4())
        self.service_name = service_name
        self.username = username
        self.password = password
        self.label = label

        self.validate_fields()

        self.created_at = (
            datetime.strptime(created_at, "%d-%m-%YT%H:%M:%S")
            if created_at
            else datetime.now()
        )
        self.updated_at = (
            datetime.strptime(updated_at, "%d-%m-%YT%H:%M:%S") if updated_at else None
        )

    def to_dict(self):

        return {
            "id": self.id,
            "service_name": self.service_name,
            "label": self.label,
            "username": self.username,
            "password": self.password,
            "created_at": self.created_at.strftime("%d-%m-%YT%H:%M:%S"),
            "updated_at": (
                self.updated_at.strftime("%d-%m-%YT%H:%M:%S") if self.updated_at else ""
            ),
        }

    @classmethod
    def from_dict(cls, credential_dict):

        return cls(
            credential_dict["service_name"],
            credential_dict["username"],
            credential_dict["password"],
            credential_dict["created_at"],
            credential_dict["updated_at"],
            credential_dict["id"],
            credential_dict["label"],
        )

    def validate_fields(self):

        if not self.service_name:
            raise ValueError(f"Empty field: 'service name'")
        if not self.username:
            raise ValueError(f"Empty field: 'username'")
        if not self.password:
            raise ValueError(f"Empty field: 'password'")
