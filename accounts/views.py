from django.http import HttpResponseRedirect
from django.shortcuts import render
import pyotp
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from drf_yasg.utils import swagger_auto_schema
from django.contrib.auth.hashers import check_password
from accounts.tokens import create_jwt_pair_for_user
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate
from django.urls import reverse
from datetime import timedelta
from rest_framework import status
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from logs.models import Log
from .serializers import (
    ChangeDefaultPassword,
    CustomUserSerializer,
    LoginSerializer,
    TwoFASerializer,
    Verify2FASerializer,
)
from .models import ActivationToken, CustomUser
from rest_framework.permissions import IsAuthenticated


class CreateUserAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This is responsible for creating a sub-admin",
        operation_description="This endpoint creates sub-admin",
        request_body=CustomUserSerializer,
    )
    def post(self, request, *args, **kwargs):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate activation token
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Construct activation link
            activation_link = request.build_absolute_uri(
                reverse("activate-account", kwargs={"uidb64": uid, "token": token})
            )

            # send activation link
            subject = "Activate your account"
            message = f"Please click on the link to change your password from the default one: {activation_link}"
            recipient_email = serializer.validated_data["email"]
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient_email])

            ActivationToken.objects.create(user=user, token=token)

            response = {
                "data": serializer.data,
                "activation_link": activation_link,
                "uid": uid,
                "token": token,
            }

            return Response(data=response, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUser(APIView):
    @swagger_auto_schema(
        operation_summary="This is verifying if the token is valid for a user",
        operation_description="This endpoint checked the validity of the token.",
    )
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)

            # check if the token has been used
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                return HttpResponseRedirect(
                    "https://cvms-admin.com/change-password?status=invalid"
                )
            return HttpResponseRedirect(
                f"https://cvms-admin.com/change-password?uidb64={uidb64}&token={token}&status=valid"
            )

        except Exception as e:
            return HttpResponseRedirect(
                "https://cvms-admin.com/change-password?status=invalid"
            )


class ChangePasswordAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This is responsible for changing the default password",
        operation_description="This endpoint change the default password",
        request_body=ChangeDefaultPassword,
    )
    def patch(self, request):
        serializer = ChangeDefaultPassword(data=request.POST)
        if serializer.is_valid():
            serializer.save()
            try:
                token = serializer.validated_data.get("token")
                uidb64 = serializer.validated_data.get("uidb64")

                uid = urlsafe_base64_decode(uidb64).decode()
                user = CustomUser.objects.get(pk=uid)

                # check if the token has been used
                token_generator = PasswordResetTokenGenerator()

                if not token_generator.check_token(user, token):
                    return Response({"error": "Token has been used"})

                # Update user's password and save
                password = serializer.validated_data.get("password")
                user.set_password(password)
                # Activate the user
                user.is_verified = True
                user.is_active = True
                user.save()

            except:
                return Response(
                    {"success": "Password updated successfully"},
                    status=status.HTTP_200_OK,
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for logging in an admin user",
        operation_description="This endpoint logs in an admin",
        request_body=LoginSerializer,
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ip_address = request.META.get("REMOTE_ADDR")

        # get the email and password
        email_address = serializer.validated_data.get("email_address", "")
        password = serializer.validated_data.get("password", "")

        try:
            user = CustomUser.objects.get(email_address=email_address, is_verified=True)

            # Check if the user is locked out
            if user.login_attempts <= 3 and not user.is_active:
                if user.last_login_attempt:
                    lockout_time = user.last_login_attempt + timedelta(hours=2)
                    if timezone.now() < lockout_time:
                        return Response(
                            data={
                                "Messsage": "User account is locked. try again after two hours"
                            },
                            status=status.HTTP_403_FORBIDDEN,
                        )
                    else:
                        # Reactivate the user after 2 hours
                        user.is_active = True
                        user.login_attempts = 0
                        user.last_login_attempt = None
                        user.save()

            # Authenticate the user
            new_user = authenticate(
                request, email_address=email_address, password=password
            )

            if new_user is not None:
                user.successful_login_attempt()

                if not user.is_active:
                    return Response(
                        data={
                            "message": "User account is not active. activate acccount"
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )

                # Check if 2FA is enabled
                if user.is_2fa_enabled:
                    # If 2FA is enabled, require a valid token
                    # This should navigate to a screen where the user will have to input the OTP and done by the frontend
                    # If 2FA is enabled, send a response indicating that the 2FA token is required
                    return Response(
                        {"message": "2FA required", "requires_2fa": True},
                        status=status.HTTP_200_OK,
                    )
                else:

                    # Generate JWT tokens and return response if 2FA is not enabled
                    tokens = create_jwt_pair_for_user(new_user)
                    response = {
                        "message": "Login Successfully",
                        "token": tokens,
                        "user": {
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                        },
                    }
                    return Response(data=response, status=status.HTTP_200_OK)
            else:
                user.unsuccessful_login_attempt()
                # log the event
                Log.objects.create(
                    log_type=Log.LOGIN_ATTEMPT,
                    message="Unsuccessful login attempt - Invalid credentials",
                    user=user.email_address,
                    ip_address=ip_address,
                )
                return Response(
                    data={"message": "Invalid credentials"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except CustomUser.DoesNotExist:
            Log.objects.create(
                log_type=Log.LOGIN_ATTEMPT,
                message="Unsuccessful login attempt - User does not exist",
                user=email_address,
                ip_address=ip_address,
            )
            return Response(
                data={"message": "User does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Two factor verification and login
class TwoFALoginAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for logging in an admin user using 2FA",
        operation_description="This endpoint logs in an admin using 2FA",
        request_body=TwoFASerializer,
    )
    def post(self, request):
        serializer = TwoFASerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.data
        token = serializer.validated_data.get("token", "")

        try:
            user = CustomUser.objects.get(
                email_address=user.email_address, is_verified=True
            )

            if user.is_2fa_enabled:
                # Verify the 2FA token
                if user.verify_totp(token):
                    # Generate JWT tokens and return response
                    tokens = create_jwt_pair_for_user(user)
                    response = {
                        "message": "Login Successful",
                        "token": tokens,
                        "user": {
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                        },
                    }
                    return Response(data=response, status=status.HTTP_200_OK)
                else:
                    return Response(
                        data={"message": "Invalid 2FA token."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return Response(
                    data={"message": "2FA not enabled for this user."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except CustomUser.DoesNotExist:
            return Response(
                data={"message": "User does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Generate TOTP and anable 2FA
class Enable2FAAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        user.generate_totp_secret()
        totp = pyotp.TOTP(user.totp_secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email_address, issuer_name="cvms"
        )
        user.is_2fa_enabled = True
        user.save()
        return Response({"provisioning_uri": provisioning_uri})


# Create an endpoint to verify the 2FA token during login or sensitive actions
class Verify2FAAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for verifying a TOTP secret",
        operation_description="This endpoint verify a TOTP secret",
        request_body=Verify2FASerializer,
    )
    def post(self, request):
        token = request.data.get("token")
        user = request.user
        if user.verify_totp(token):
            response = {"detail": "2FA verified successfully"}
            return Response(data=response, status=status.HTTP_200_OK)
        response = {"detail": "Invalid 2FA token"}

        return Response(data=response, status=status.HTTP_400_BAD_REQUEST)



# Reset Password 