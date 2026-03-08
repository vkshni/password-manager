from pathlib import Path
import json

from pwd_entity import Credential

BASE_DIR = Path(__file__).parent

# Creating database directory
DB_DIR = BASE_DIR / "database/"
DB_DIR.mkdir(exist_ok=True)


# Low levels
class JSONFile:

    def __init__(self, file_name):
        self.file_path = self.create(file_name)

    def create(self, file_name):

        path = BASE_DIR / "database" / file_name
        if not path.exists():
            with open(path, "w") as f:
                json.dump(None, f, indent=4)
        return path

    def read_all(self) -> list | dict:

        with open(self.file_path, "r") as f:

            data = json.load(f)
            return data

    def write_all(self, data):

        with open(self.file_path, "w") as f:

            json.dump(data, f, indent=4)


class VaultMeta:

    def __init__(self, file_name="vault_meta.json"):
        self.json_handler = JSONFile(file_name)

    def is_initialized(self):

        try:
            self.get_master_password_hash()
            return True
        except:
            return False

    def setup(self, master_password_hash):

        data = {"master_password_hash": master_password_hash}

        self.json_handler.write_all(data)

    def get_master_password_hash(self):

        data = self.json_handler.read_all()
        return data["master_password_hash"]


class VaultData:

    def __init__(self, file_name="vault_data.json"):
        self.json_handler = JSONFile(file_name)
        self.initialize()

    def initialize(self):

        try:
            data = self.json_handler.read_all()
            if data is None:  # handles the null case
                self.json_handler.write_all([])
        except (json.JSONDecodeError, ValueError):
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

        data = self.json_handler.read_all()

        for i, c in enumerate(data):
            if c["credential_id"] == credential.credential_id:
                data[i] = credential.to_dict()
                break

        self.json_handler.write_all(data)

    def delete(self, credential: Credential):

        data = self.get_all()

        filtered_data = [
            c.to_dict() for c in data if c.credential_id != credential.credential_id
        ]

        self.json_handler.write_all(filtered_data)


class Attempts:

    def __init__(self, file_name="attempts.json"):
        self.json_handler = JSONFile(file_name)
        self.initialize()

    def initialize(self):

        try:
            data = self.json_handler.read_all()
            if data is None:
                self.reset()
        except (json.JSONDecodeError, ValueError):
            self.reset()

    def reset(self):

        data = {"failed_count": 0, "locked_until": None}
        self.json_handler.write_all(data)

    def update(self, failed_count=None, locked_until=None):

        data = self.json_handler.read_all()
        if failed_count is not None:
            data["failed_count"] = failed_count
        if locked_until is not None:
            data["locked_until"] = locked_until

        self.json_handler.write_all(data)

    def get_data(self):

        data = self.json_handler.read_all()
        return data


if __name__ == "__main__":
    pass
