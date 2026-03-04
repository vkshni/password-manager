from db import VaultData
from entity import Credential

import hashlib


# Main Vault
class Vault:

    def __init__(self):
        self.vd = VaultData()

    def add_credential(self, service_name, username, password):

        credential_obj = Credential(service_name, username, password)

        self.vd.add_data(credential_obj)


if __name__ == "__main__":

    v = Vault()
    # v.add_credential("GitHub", "vkshnii", "vks_GIT")
