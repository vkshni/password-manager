from datetime import datetime
<<<<<<< HEAD
from shield_db import VaultData
from pwd_entity import Credential
from authservice import AuthService

=======
from db import VaultData
from entity import Credential
from authservice import AuthService

import hmac

>>>>>>> e9452142554433022d613e14b342e62a4257cd8c

# Main Vault
class Vault:

<<<<<<< HEAD
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
=======
    def __init__(self):
        self.vd = VaultData()
        self.auth = AuthService()

    def add_credential(self, service_name, username, password):

        self.auth.require_authenticated()

        credential_obj = Credential(service_name, username, password)
>>>>>>> e9452142554433022d613e14b342e62a4257cd8c

        self.vd.add(credential_obj)

    def list_services(self):
        self.auth.require_authenticated()

        credentials = self.vd.get_all()
<<<<<<< HEAD
        services = [[c.service_name.lower(), c.label.lower()] for c in credentials]

        return services

    def get_credential(self, service_name, label="default"):
=======
        services = [[i, c.service_name] for i, c in enumerate(credentials)]

        return services

    def get_credential(self, service_name):
>>>>>>> e9452142554433022d613e14b342e62a4257cd8c
        self.auth.require_authenticated()

        credentials = self.vd.get_all()

<<<<<<< HEAD
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
=======
        filtered = [
            c for c in credentials if c.service_name.lower() == service_name.lower()
        ]

        return filtered

    def update_credential(
        self, service_name, new_service_name=None, new_username=None, new_password=None
    ):

        self.auth.require_authenticated()
        credentials = self.get_credential(service_name)

        if not credentials:
            raise ValueError(f"No credential with service '{service_name}' found")

        if len(credentials) > 1:
            raise ValueError("More than one credentials found")

        for c in credentials:
            if new_service_name is not None:
                c.service_name = new_service_name
            if new_username is not None:
                c.username = new_username
            if new_password is not None:
                c.password = new_password

            c.updated_at = datetime.now()

            self.vd.update(c)

    def delete_credential(self, service_name, force=False):
        self.auth.require_authenticated()

        credentials = self.get_credential(service_name)

        if not credentials:
            raise ValueError(f"No credential with service '{service_name}' found")

        if len(credentials) > 1 and not force:
            raise ValueError("More than one credentials found")

        for c in credentials:
            self.vd.delete(c)


if __name__ == "__main__":

    v = Vault()
    # v.delete_credential("instagram")
    # cs = v.get_credential("Instagra")
    # print(cs)
    # for c in cs:
    #     print(c.username, c.password)

    # v.update_credential("github", new_username="vijayksahani")
    # print(v.list_services())
    # v.auth.verify_master("v1s")
    # v.add_credential("GitHub", "vkshn", "vks@giti")
>>>>>>> e9452142554433022d613e14b342e62a4257cd8c
