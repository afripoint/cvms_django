from rest_framework import serializers
from accounts.models import CustomUser
from django.core.exceptions import ValidationError
import re


class CustomUserSerializer(serializers.ModelSerializer):
    email_address = serializers.CharField(required=True)
    phone_number = serializers.CharField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = CustomUser
        fields = [
            "first_name",
            "last_name",
            "email_address",
            "phone_number",
            "role",
            "password",
        ]

    def validate_email_address(self, value):
        if CustomUser.objects.filter(email_address=value).exists():
            raise serializers.ValidationError(
                "A user with this email address already exists."
            )
        return value

    def validate_phone_number(self, value):
        if CustomUser.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError(
                "A user with this phone number already exists."
            )
        return value

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email_address=validated_data["email_address"],
            password=validated_data["password"],
            phone_number=validated_data["phone_number"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            role=validated_data["role"],
        )
        return user


class ChangeDefaultPassword(serializers.ModelSerializer):
    password = serializers.CharField(required=True, min_length=8, write_only=True)
    confirm_password = serializers.CharField(
        required=True, min_length=8, write_only=True
    )
    token = serializers.CharField(required=True, min_length=5, write_only=True)
    uidb64 = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = CustomUser
        fields = (
            "password",
            "confirm_password",
            "token",
            "uidb64",
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
        confirm_password = attrs.pop("confirm_password", "")

        if password != confirm_password:
            raise ValidationError("Password do not match")
        return attrs
    

    def save(self):
        # The save method will just return the validated data
        return self.validated_data


# Login serializer
class LoginSerializer(serializers.ModelSerializer):
    email_address = serializers.CharField(required=True)

    class Meta:
        model = CustomUser
        fields = (
            "email_address",
            "password",
        )


# two factor serializer
class TwoFASerializer(serializers.Serializer):
    token = serializers.CharField(max_length=6, min_length=6)

    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("The 2FA token must be a 6-digit number.")
        return value


class Verify2FASerializer(serializers.Serializer):
    token = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_token(self, value):
        if len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError("Invalid token format")
        return value
