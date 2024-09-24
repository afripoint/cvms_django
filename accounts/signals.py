from django.db.models.signals import post_save
from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver
from .models import CVMSAuthLog, CustomUser, Profile


@receiver(post_save, sender=CustomUser)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            user=instance,
        )
        # print(f"Profile created for {instance.email_address}")
        CVMSAuthLog.objects.create(
            user=instance,
            event_type="USER_CREATION",
            ip_address=None,
            device_details=None,
            location=None,
            additional_info={"new_user_id": instance.slug, "role": instance.role},
        )

    elif not created and not hasattr(instance, "profile"):
        Profile.objects.create(user=instance)
        print(f"Profile created for existing user {instance.email_address}")


@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    CVMSAuthLog.objects.create(
        user=user,
        event_type="LOGIN_SUCCESS",
        ip_address=get_client_ip(request),
        device_details=request.META.get("HTTP_USER_AGENT"),
        location=get_user_location(request),
    )


@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    CVMSAuthLog.objects.create(
        user=user,
        event_type="LOGOUT",
        ip_address=get_client_ip(request),
        device_details=request.META.get("HTTP_USER_AGENT"),
        location=get_user_location(request),
    )


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    CVMSAuthLog.objects.create(
        event_type="LOGIN_FAILED",
        ip_address=get_client_ip(request),
        device_details=request.META.get("HTTP_USER_AGENT"),
        location=get_user_location(request),
        reason="Incorrect password or locked account",
        username=credentials.get("username"),
    )

    # Other handlers to be created for different events as per the project requirements


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def get_user_location(request):
    # Implement your logic to determine location based on IP address
    return "Location Info"
