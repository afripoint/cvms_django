import secrets
import string



def generate_default_password(length=12):
        # Generate a secure random password
        characters = string.ascii_letters + string.digits + string.punctuation
        return "".join(secrets.choice(characters) for _ in range(length))


example = generate_default_password()

print(example)