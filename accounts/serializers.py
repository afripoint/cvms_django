from rest_framework import serializers
from accounts.models import CustomUser
from django.core.exceptions import ValidationError
import re


class CustomUserSerializer(serializers.ModelSerializer):
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
    password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(min_length=8, write_only=True)
    token = serializers.CharField(min_length=5, write_only=True)
    uidb64 = serializers.CharField(min_length=5, write_only=True)

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


# Login serializer
class LoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField(required=True)

    class Meta:
        model = CustomUser
        fields = (
            "email",
            "password",
        )
