from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser, Profile


@receiver(post_save, sender=CustomUser)
def create_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(
            user=instance,
        )
        print(f"Profile created for {instance.email_address}")

    elif not created and not hasattr(instance, 'profile'):
        Profile.objects.create(user=instance)
        print(f"Profile created for existing user {instance.email_address}")
