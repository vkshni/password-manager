from datetime import datetime
from db import VaultData
from entity import Credential
from authservice import AuthService

import hmac


# Main Vault
class Vault:

    def __init__(self):
        self.vd = VaultData()
        self.auth = AuthService()

    def add_credential(self, service_name, username, password):

        self.auth.require_authenticated()

        credential_obj = Credential(service_name, username, password)

        self.vd.add(credential_obj)

    def list_services(self):
        self.auth.require_authenticated()

        credentials = self.vd.get_all()
        services = [[i, c.service_name] for i, c in enumerate(credentials)]

        return services

    def get_credential(self, service_name):
        self.auth.require_authenticated()

        credentials = self.vd.get_all()

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
