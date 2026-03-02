from pathlib import Path
from os import mkdir

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


class VaultMeta:

    def __init__(self):
        pass


class Attempts:

    def __init__(self):
        self.json_handler = JSONFile("attempts.json")


if __name__ == "__main__":
    pass
