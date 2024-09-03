import threading
from django.core.mail import send_mail, mail_admins


# this makes the email delivery very fast
class EmailThread(threading.Thread):
    def __init__(self, subject, message, recipient_list, from_email=None):
        self.subject = subject
        self.message = message
        self.recipient_list = recipient_list
        self.from_email = from_email
        threading.Thread.__init__(self)

    def run(self):
        if self.from_email:
            send_mail(
                subject=self.subject,
                message=self.message,
                from_email=self.from_email,
                recipient_list=self.recipient_list,
            )
        else:
            mail_admins(
                subject=self.subject,
                message=self.message,
            )


def send_admin_email(subject, message):
    EmailThread(subject, message, None).start()

def send_user_email(subject, message, recipient_list, from_email):
    EmailThread(subject, message, recipient_list, from_email).start()