import threading
from django.core.mail import send_mail, mail_admins
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from decouple import config
from django.core.mail import get_connection
from django.core.mail import EmailMessage
from django.conf import settings


# custom token geneerator that expires
class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{timestamp}{user.is_active}"


# this makes the email delivery very fast
class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        try:
            self.email_message.send()
        except Exception as e:
            # Log the error for better debugging
            print(f"Error sending email: {e}")


def send_html_email(subject, body, from_email=None, to_email=None, **kwargs):
    if kwargs:
        fields_values = "<br>".join(
            [f"{field}: {value}" for field, value in kwargs.items()]
        )
        body += "<br><br>" + fields_values

    try:
        connection = get_connection(
            host=settings.RESEND_SMTP_HOST,
            port=587,
            username=settings.RESEND_SMTP_USERNAME,
            password=settings.RESEND_SMTP_PASSWORD,
            use_tls=True,
        )
        email = EmailMessage(subject, body, from_email, to_email, connection=connection)
        email.content_subtype = "html"
        EmailThread(email).start()
    except Exception as e:
        print(f"Error setting up email connection or sending email: {e}")

