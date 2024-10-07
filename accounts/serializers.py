from rest_framework import serializers
from accounts.models import CVMSAuthLog, CustomUser, Profile
from django.utils.http import urlsafe_base64_decode
from django.core.exceptions import ValidationError
import re
from departments.models import Command, Department, Rank, Zone
from permissions.models import Permission
# from permissions.serializers import PermissionSerializer
from permissions.serializers import PermissionSerializer
from roles.models import Role


# user profile
class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()

    class Meta:
        model = Profile
        fields = (
            "user",
            "rank",
            "staff_id",
            "command",
            "department",
            "zone",
            "slug",
        )
        read_only_fields = ("slug", "user")


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True)

    class Meta:
        model = Role
        fields = ['role', 'permissions']



class CustomUserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    role = RoleSerializer(read_only=True)

    class Meta:
        model = CustomUser
        fields = (
            "first_name",
            "last_name",
            "phone_number",
            "email_address",
            "gender",
            "request_status",
            "is_2fa_enabled",
            "role",
            "slug",
            "is_active",
            "is_verified",
            "created_at",
            "profile",
        )


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
class LoginSerializer(serializers.Serializer):
    email_address = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)

    # No business logic needed here, just ensure the fields are present and valid
    def validate(self, data):
        email_address = data.get("email_address")
        password = data.get("password")

        # Ensure both email and password are provided
        if not email_address or not password:
            raise serializers.ValidationError("Email and password are required.")

        return data


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


class ForgetPasswordEmailRequestSerializer(serializers.Serializer):
    email_address = serializers.EmailField(min_length=8)

    # class Meta:
    #     model = CustomUser
    #     fields = ("email_address",)


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


class UserCreationRequestSerializer(serializers.Serializer):
    first_name = serializers.CharField(max_length=50, min_length=2, required=True)
    last_name = serializers.CharField(max_length=50, min_length=2, required=True)
    email_address = serializers.CharField(max_length=50, min_length=2, required=True)
    command = serializers.CharField(max_length=50, min_length=2, required=True)
    department = serializers.CharField(max_length=50, min_length=2, required=True)
    rank = serializers.CharField(max_length=50, min_length=2, required=True)
    zone = serializers.CharField(max_length=50, min_length=2, required=True)
    phone_number = serializers.CharField(max_length=50, min_length=2, required=True)
    role = serializers.SlugRelatedField(
        queryset=Role.objects.all(),
        slug_field='role',
        required=True
    )

    staff_id = serializers.CharField(write_only=True, required=False)
    password = serializers.CharField(
        write_only=True, required=False, allow_blank=True, min_length=0
    )

    def validate_phone_number(self, value):
        """
        Custom method to validate phone number format
        """
        if not value:
            raise serializers.ValidationError("Phone number is required.")

        if (
            len(value) != 11
            and not value.startswith("080")
            and not value.startswith("+234")
        ):
            raise serializers.ValidationError(
                "Phone number must start with '+234' or '080' and be 11 digits long."
            )

        if len(value) == 11:
            value = "+234" + value[1:]
        elif len(value) == 13:
            value = "+" + value

        return value


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
        command = validated_data.pop("command").strip()
        department = validated_data.pop("department")
        rank = validated_data.pop("rank")
        zone = validated_data.pop("zone")
        staff_id = validated_data.pop("staff_id", None)
        role = validated_data.pop("role")

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

        user.role = role


        user.save()

        # Update the profile with the provided data (Profile should already exist due to the signal)
        profile = Profile.objects.get(user=user)
        profile.command = command
        profile.department = department
        profile.rank = rank
        profile.zone = zone
        profile.staff_id = staff_id

        profile.save()

        return user

class GrantAccessSerializer(serializers.ModelSerializer):
    is_verified = serializers.BooleanField()

    class Meta:
        model = CustomUser
        fields = ("is_verified",)

    def update(self, instance, validated_data):
        # update is verified
        instance.is_verified = validated_data.get("is_verified", instance.is_verified)

        # automatically set the request_status based on verification status

        if instance.is_verified:
            instance.request_status = "approved"

        else:
            instance.request_status = "declined"

        instance.save()
        return instance


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, write_only=True, required=True)
    confirm_password = serializers.CharField(
        min_length=8, write_only=True, required=True
    )
    token = serializers.CharField(write_only=True, required=True)
    uidb64 = serializers.CharField(write_only=True, required=True)

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

        # Assuming token and uidb64 validation is handled in the view
        return attrs


class CVMSAuthLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = CVMSAuthLog
        fields = "__all__"


