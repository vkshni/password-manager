from datetime import datetime
from shield_db import VaultData
from pwd_entity import Credential
from authservice import AuthService


# Main Vault
class Vault:

    def __init__(
        self,
        meta_file="vault_meta.json",
        data_file="vauld_data.json",
        attempts_file="attempts.json",
    ):
        self.vd = VaultData(data_file)
        self.auth = AuthService(meta_file, attempts_file)

    def add_credential(self, service_name, username, password, label="default"):

        self.auth.require_authenticated()

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
        self.auth.require_authenticated()

        credentials = self.vd.get_all()
        services = [[c.service_name.lower(), c.label.lower()] for c in credentials]

        return services

    def get_credential(self, service_name, label="default"):
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

        self.auth.require_authenticated()
        credential = self.get_credential(service_name, label)

        if not credential:
            raise ValueError(f"No credential with service '{service_name}' found")

        if new_service_name is not None:
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

        credential.updated_at = datetime.now()

        self.vd.update(credential)

    def delete_credential(self, service_name, label="default"):
        self.auth.require_authenticated()

        credential = self.get_credential(service_name, label)

        if not credential:
            raise ValueError(
                f"No credential with service '{service_name}/{label}' found"
            )

        self.vd.delete(credential)


if __name__ == "__main__":
    pass
