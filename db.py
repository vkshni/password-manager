from pathlib import Path
import json
from os import mkdir

from entity import Credential

BASE_DIR = Path(__file__).parent

# Creating database directory
pass


# Low levels
class JSONFile:

    def __init__(self, file_name):
        self.file_path = self.create(file_name)

    def create(self, file_name):

        path = BASE_DIR / "database" / file_name
        if not path.exists():
            with open(path, "x") as f:
                pass
        return path

    def read_all(self) -> list | dict:

        with open(self.file_path, "r") as f:

            data = json.load(f)
            return data

    def write_all(self, data):

        with open(self.file_path, "w") as f:

            json.dump(data, f, indent=4)


class VaultMeta:

    def __init__(self):
        self.json_handler = JSONFile("vault_meta.json")
        self.initialize()

    def initialize(self):

        try:
            self.json_handler.read_all()
        except:
            data = {"master_password_hash": None}
            self.json_handler.write_all(data)


class VaultData:

    def __init__(self):
        self.json_handler = JSONFile("vault_data.json")
        self.initialize()

    def initialize(self):

        try:
            self.json_handler.read_all()
        except:
            self.json_handler.write_all([])

    def add(self, credential: Credential):

        credential_dict = credential.to_dict()

        data = self.json_handler.read_all()

        data.append(credential_dict)

        self.json_handler.write_all(data)

    def get_all(self):

        raw_data = self.json_handler.read_all()

        vault_data = [Credential.from_dict(c) for c in raw_data]

        return vault_data

    def update(self, credential: Credential):

        data = self.get_all()

        new_data = []
        for c in data:
            if c.id == credential.id:
                c = credential
            new_data.append(c.to_dict())

        self.json_handler.write_all(new_data)

    def delete(self, credential: Credential):

        data = self.get_all()

        filtered_data = [c.to_dict() for c in data if c.id != credential.id]

        self.json_handler.write_all(filtered_data)


class Attempts:

    def __init__(self):
        self.json_handler = JSONFile("attempts.json")
        self.initialize()

    def initialize(self):

        try:
            self.json_handler.read_all()
        except:
            data = {"failed_count": 0, "locked_until": 0}
            self.json_handler.write_all(data)

    def reset(self):

        data = {"failed_count": 0, "locked_until": 0}
        self.json_handler.write_all(data)

    def update(self, failed_count, locked_until):

        data = self.json_handler.read_all()
        data["failed_count"] = failed_count
        data["locked_until"] = locked_until

        self.json_handler.write_all(data)


if __name__ == "__main__":
    attempts = Attempts()
    vd = VaultData()
    vm = VaultMeta()

    # attempts.update(1, 2)
    # attempts.reset_attempts()

    # c = Credential("Facebook", "vkshni", "sdfkldl")
    # vd.add_data(c)
    # cs = vd.get_all()
    # for c in cs:
    #     print(c.service_name, c.username)
