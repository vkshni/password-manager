# All the authorization
from shield_db import VaultMeta, Attempts
from hmac import compare_digest
from datetime import datetime, timedelta
import hashlib


class AuthService:

    def __init__(self, meta_file="vault_meta.json", attempts_file="attempts.json"):
        self.vm = VaultMeta(meta_file)
        self.attempt = Attempts(attempts_file)
        self.is_authenticated = False

    def require_authenticated(self):

        if not self.is_authenticated:
            raise PermissionError("Access denied. Please login first")

    def setup_master(self, master_password):

        if self.vm.is_initialized():
            raise PermissionError("Vault already initialized")

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
        failed_count += 1  # increment first
        self.attempt.update(failed_count=failed_count)

        allowed_attempts = 3
        if failed_count >= allowed_attempts:  # then check
            locked_until = (datetime.now() + timedelta(seconds=30)).strftime(
                "%d-%m-%YT%H:%M:%S"
            )
            self.attempt.update(locked_until=locked_until)

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

        return password_hash

    def verify(self, password):

        input_hash = self.generate_hash(password)
        master_password_hash = self.vm.get_master_password_hash()
        return compare_digest(input_hash, master_password_hash)

    def confirm_identity(self, password):
        return self.verify(password)


if __name__ == "__main__":
    pass
