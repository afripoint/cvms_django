from rest_framework import serializers
from django.core.exceptions import ValidationError
import re
from accounts.models import CustomUser


class OTPVerificationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)


class ForgetPasswordMobileEmailRequestSerializer(serializers.Serializer):
    email_address = serializers.EmailField(min_length=8)
    message_choice = serializers.ChoiceField(choices=CustomUser.MESSAGE_CHOICES, default='sms')

    class Meta:
        model = CustomUser
        fields = ["email_address", "message_choice"]

    

class SetNewPasswordMobileSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, write_only=True, required=True)
    confirm_password = serializers.CharField(
        min_length=8, write_only=True, required=True
    )


    def validate_password(self, value):
        if not re.search(r"[A-Z]", value):
            raise ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[0-9]", value):
            raise ValidationError("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*()\-_=+{};:,<.>]", value):
            raise ValidationError(
                "Password must contain at least one special character."
            )
        return value

    def validate(self, attrs):
        password = attrs.get("password", "").strip()
        confirm_password = attrs.get("confirm_password", "").strip()

        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")

        return attrs


    
