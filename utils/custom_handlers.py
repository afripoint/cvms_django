from django.template.loader import render_to_string
from django.conf import settings
from accounts.utils import send_html_email


def send_critical_email(error, user_action, user_id, description, error_code):
    subject = "Critical Logs Email"
    message = render_to_string(
        "critical_logs_email/error_email_template.html",
        {
            "error": error,
            "error_code": error_code,
            "user_action": user_action,
            "user_id": user_id,
            "description": description,
        },
    )

    try:
        send_html_email(
            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to_email=[admin[1] for admin in settings.ADMINS],
        )
    except Exception as e:
        print(f"Error sending custom error email: {e}")
