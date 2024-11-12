import logging
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings


class CustomEmailHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
         # Prepare the log message
        subject = f"Critical Error: {record.message[:50]}..."
        message = self.format(record)  # Formats the log message
        context = {
            'message': message,
            'record': record,
        }

        # Render the HTML and plain text email content using Django templates
        html_content = render_to_string('error_email_template.html', context)
        text_content = render_to_string('error_email_template.txt', context)

        # Send the email
        email = EmailMessage(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[admin[1] for admin in settings.ADMINS],
        )
        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=True)
    