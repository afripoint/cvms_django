from rest_framework import serializers
from accounts.models import CustomUser
from django.utils.http import urlsafe_base64_decode
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
import re

from departments.models import Command, Department, Rank, Zone
from roles.models import Role


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
    default_password = serializers.CharField(
        required=True, min_length=8, write_only=True
    )
    password = serializers.CharField(required=True, min_length=8, write_only=True)
    confirm_password = serializers.CharField(
        required=True, min_length=8, write_only=True
    )
    token = serializers.CharField(required=True, min_length=5, write_only=True)
    uidb64 = serializers.CharField(required=True, write_only=True)

    class Meta:
        model = CustomUser
        fields = (
            "default_password",
            "password",
            "confirm_password",
            "token",
            "uidb64",
        )

    def validate_default_password(self, value):

        if len(value) == 0:
            raise ValidationError("Provide default password.")

        # Get uidb64 from the validated data
        uidb64 = self.initial_data.get("uidb64")
        try:
            # Decode the user ID from uidb64
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            raise ValidationError("Invalid user ID.")

        # Check if the provided default_password matches the stored one
        if user.default_password != value:
            raise ValidationError("Default password does not match our records.")

        return value

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


class ResetPasswordSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, min_length=8, write_only=True)
    confirm_new_password = serializers.CharField(
        required=True, min_length=8, write_only=True
    )

    class Meta:
        model = CustomUser
        fields = ("old_password", "new_password", "confirm_new_password")

    def validate_old_password(self, value):
        user = self.context["request"].user

        if not user.check_password(value):
            raise serializers.ValidationError("Your old password is incorrect.")
        return value

    def validate_new_password(self, value):
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )
        if not re.search(r"[0-9]", value):
            raise serializers.ValidationError(
                "Password must contain at least one digit."
            )
        if not re.search(r"[!@#$%^&*()\-_=+{};:,<.>]", value):
            raise serializers.ValidationError(
                "Password must contain at least one special character."
            )
        return value

    def validate(self, attrs):
        new_password = attrs.get("new_password", "").strip()
        confirm_new_password = attrs.get("confirm_new_password", "").strip()

        if new_password != confirm_new_password:
            raise serializers.ValidationError("Password do not match")
        return attrs

    def save(self):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save()
        return user


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


class ForgetPasswordEmailRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(min_length=8)

    class Meta:
        model = CustomUser
        fields = ("email",)


class DeactivateAdminUserSerializer(serializers.ModelSerializer):
    is_active = serializers.BooleanField()

    class Meta:
        model = CustomUser
        fields = ("is_active",)

    def validate_is_active(self, value):
        if value:
            raise ValidationError("User is successfully deactivated")
        else:
            raise ValidationError("Deactivation successfully")


class UserCreationRequestSerializer(serializers.ModelSerializer):
    command = serializers.SlugRelatedField(
        queryset=Command.objects.all(),
        slug_field="command_name",  # Field used for string representation
    )
    department = serializers.SlugRelatedField(
        queryset=Department.objects.all(),
        slug_field="department_name",  # Field used for string representation
    )
    rank = serializers.SlugRelatedField(
        queryset=Rank.objects.all(),
        slug_field="rank_level",  # Field used for string representation
    )
    role = serializers.SlugRelatedField(
        queryset=Role.objects.all(),
        slug_field="role",  # Adjust this to the correct field in the Role model
    )
    zone = serializers.SlugRelatedField(
        queryset=Zone.objects.all(),
        slug_field="zone",  # Field used for string representation
    )
    # Include staff_id as a field in the serializer
    staff_id = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(
        write_only=True, required=False, allow_blank=True, min_length=0
    )

    class Meta:
        model = CustomUser
        fields = [
            "first_name",
            "last_name",
            "staff_id",
            "email_address",
            "command",
            "department",
            "role",
            "rank",
            "zone",
            "phone_number",
            "password",
        ]

    def validate_email_address(self, value):
        if CustomUser.objects.filter(email_address=value).exists():
            raise serializers.ValidationError(
                "A user with this email address already exists."
            )
        return value

    def validate(self, attrs):
        # Handle case where password might be blank
        if not attrs.get("password"):
            # Generate a default password if none is provided
            attrs["password"] = CustomUser.generate_default_password()
        return attrs

    def create(self, validated_data):
        # extract the related forien key data
        command = validated_data.pop("command")
        department = validated_data.pop("department")
        rank = validated_data.pop("rank")
        zone = validated_data.pop("zone")
        staff_id = validated_data.pop("staff_id", None)

        # Retrieve or generate the password
        password = validated_data.pop("password")

        # Create a user with is_active=False initially
        user = CustomUser.objects.create(
            **validated_data,
            is_active=False,  # User is not active until verified
            is_verified=False
        )

        # Set the default password
        user.set_password(password)
        user.default_password = password
        user.command = command
        user.department = department
        user.rank = rank
        user.zone = zone
        user.staff_id = staff_id
        user.save()

        return user


class GrantAccessSerializer(serializers.ModelSerializer):
    is_verified = serializers.BooleanField()

    class Meta:
        model = CustomUser
        fields = ("is_verified",)


class CustomUsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = (
            "phone_number",
            "first_name",
            "last_name",
            "email_address",
            "gender",
            "role",
            "is_active",
            "is_verified",
        )
