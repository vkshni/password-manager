# All the authorization
from db import VaultMeta, Attempts
from hmac import compare_digest
from datetime import datetime, timedelta
import hashlib


class AuthService:

    def __init__(self):
        self.vm = VaultMeta()
        self.attempt = Attempts()
        self.is_authenticated = False

    def require_authenticated(self):

        if not self.is_authenticated:
            raise PermissionError("Access denied. Please login first")

    def setup_master(self, master_password):

        master_password_hash = self.generate_hash(master_password)
        self.vm.setup(master_password_hash)

    def verify_master(self, user_password):

        if self.is_locked_out():
            raise ValueError("Locked out! Try after 30 seconds")

        if not self.verify(user_password):
            self.record_failed_attempt()
            return False

        self.is_authenticated = True
        self.attempt.reset()
        return True

    def record_failed_attempt(self):

        failed_count = self.attempt.get_data()["failed_count"]
        allowed_attempts = 3
        if failed_count >= allowed_attempts:
            locked_until = (datetime.now() + timedelta(seconds=30)).strftime(
                "%d-%m-%YT%H:%M:%S"
            )
            self.attempt.update(locked_until=locked_until)
            return

        failed_attempts = failed_count + 1

        self.attempt.update(failed_count=failed_attempts)

    def is_locked_out(self):

        locked_until = self.attempt.get_data()["locked_until"]
        if not locked_until:
            return False

        expiry = datetime.strptime(locked_until, "%d-%m-%YT%H:%M:%S")
        if datetime.now() > expiry:
            self.attempt.reset()
            return False

        return True

    def generate_hash(self, password_string):

        password_hash = hashlib.sha256(password_string.encode()).hexdigest()

        return str(password_hash)

    def verify(self, password):

        input_hash = self.generate_hash(password)
        master_password_hash = self.vm.get_master_password_hash()
        return compare_digest(input_hash, master_password_hash)


if __name__ == "__main__":

    auth = AuthService()
    # auth.setup_master("vks")
    print(auth.verify_master("vks"))
