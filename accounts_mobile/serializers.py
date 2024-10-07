from rest_framework import serializers

from accounts.models import CustomUser


class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)


class ForgetPasswordMobileEmailRequestSerializer(serializers.Serializer):
    email_address = serializers.EmailField(min_length=8)
    message_choice = serializers.ChoiceField(choices=CustomUser.MESSAGE_CHOICES, default='sms')

    class Meta:
        model = CustomUser
        fields = ["email_address", "message_choice"]
