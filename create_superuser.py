import os
import django
from django.contrib.auth import get_user_model

os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE", "api.settings"
)  # Replace 'your_project' with your project name
django.setup()

User = get_user_model()

# username = os.getenv("DJANGO_SUPERUSER_USERNAME", "afripoint")
email = os.getenv("DJANGO_SUPERUSER_EMAIL", "devteam@afripointgroup.com")
password = os.getenv("DJANGO_SUPERUSER_PASSWORD", "afri2024")

if not User.objects.filter(email_address=email).exists():
    User.objects.create_superuser(email_address=email, password=password)
    print(f"Superuser {email} created.")
else:
    print(f"Superuser {email} already exists.")
