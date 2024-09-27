from accounts.models import CVMSAuthLog
from accounts.signals import get_client_ip


def password_updated_log(request, user, reason):
    CVMSAuthLog.objects.create(
        user=user,
        event_type="PASSWORD UPDATED",
        ip_address=get_client_ip(request),
        device_details=request.META.get("HTTP_USER_AGENT"),
        reason=reason,
    )


def login_failed_log(request, user, reason):
    CVMSAuthLog.objects.create(
        user=user,
        event_type="LOGIN_FAILED",
        ip_address=get_client_ip(request),
        device_details=request.META.get("HTTP_USER_AGENT"),
        reason=reason,
    )

def login_successful_log(request, user):
    CVMSAuthLog.objects.create(
            user=user,
            event_type="LOGIN_SUCCESS",
            ip_address=get_client_ip(request),
            device_details=request.META.get("HTTP_USER_AGENT"),
            reason="Successful Login of user",
        )


def locked_account_log(request, user):
    CVMSAuthLog.objects.create(
        user=user,
        event_type="ACCOUNT LOCKED",
        ip_address=get_client_ip(request),
        device_details=request.META.get("HTTP_USER_AGENT"),
        reason="Multiple login trials",
    )
