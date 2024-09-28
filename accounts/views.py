from django.http import HttpResponseRedirect, HttpResponse
from smtplib import SMTPException
from django.core.mail import BadHeaderError
from django.db.models import DateField
from django.core.exceptions import ValidationError
from django.db.models.functions import Cast
from django.template.loader import render_to_string
import logging
from rest_framework import generics
from django.utils.dateparse import parse_date
from rest_framework import filters
from drf_yasg import openapi
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.generics import GenericAPIView
import pyotp
from django.contrib.auth.hashers import check_password
from django.utils.encoding import DjangoUnicodeDecodeError
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.filters import SearchFilter, OrderingFilter
from django.core.mail import send_mail
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.auth_logs import (
    locked_account_log,
    login_failed_log,
    login_successful_log,
    password_updated_log,
)
from accounts.filters import CustomUserFilter
from accounts.signals import get_client_ip
from accounts.tokens import create_jwt_pair_for_user
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth import authenticate
from django.urls import reverse
from datetime import timedelta
from rest_framework import status
from django.conf import settings
from accounts.utils import TokenGenerator, send_html_email
from data_uploads.pagination import (
    AllUsersPagination,
    ProfilesPegination,
)
from django_filters.rest_framework import DjangoFilterBackend
from logs.models import Log
from .serializers import (
    ChangeDefaultPassword,
    CustomUserSerializer,
    # CustomUsersSerializer,
    DeactivateAdminUserSerializer,
    ForgetPasswordEmailRequestSerializer,
    GrantAccessSerializer,
    LoginSerializer,
    ProfileSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    TwoFASerializer,
    UserCreationRequestSerializer,
    Verify2FASerializer,
)
from .models import (
    ActivationToken,
    CVMSAuthLog,
    CustomUser,
    PasswordResetToken,
    Profile,
)
from rest_framework.permissions import IsAuthenticated


class UserCreationRequestAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint allows a user to request access to the admin - user creation account",
        operation_description="Allow user have access to the admin user creation request",
        request_body=UserCreationRequestSerializer,
    )
    def post(self, request):
        try:
            serializer = UserCreationRequestSerializer(data=request.data)

            if serializer.is_valid():
                user = serializer.save()

                # Get user details for email notification
                first_name = serializer.validated_data["first_name"]
                last_name = serializer.validated_data["last_name"]
                recipient_email = serializer.validated_data["email_address"]

                # Email content
                subject = "Request for access request"
                # message = f"A CVMS user - {first_name} {last_name} is requesting access to the dashboard. Kindly login to the dashboard and grant access"
                # message_user = "You have requested access to the CVMS admin dashboard. You will be notified when granted access."

                message_user = render_to_string(
                    "accounts/request_email.html",
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                    },
                )
                message_admin = render_to_string(
                    "accounts/approval_request_email.html",
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                    },
                )
                send_html_email(
                    subject=subject,
                    body=message_user,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_email=[recipient_email],
                )

                send_html_email(
                    subject=subject,
                    body=message_admin,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_email=["dennisthegenius036@gmail.com"],
                )

                return Response(
                    {"message": "Request for access sent"},
                    status=status.HTTP_200_OK,
                )

        except serializers.ValidationError as e:
            return Response(
                {"error": "Validation failed", "details": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        except Exception as e:
            # Handle email sending error
            return Response(
                {"error": "Failed to send email notifications", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# approve request view
class GrantAccessAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint verifies users - admin",
        operation_description="Verify and grant access to users - admin",
        request_body=GrantAccessSerializer,
    )
    def post(self, request, slug):
        # Step 1: Get the user by slug
        try:
            user = CustomUser.objects.get(slug=slug)
        except ObjectDoesNotExist:
            return Response(
                {"error": "User not found with the provided slug."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {
                    "error": "An error occurred while retrieving the user.",
                    "details": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Step 2: Validate serializer data
        serializer = GrantAccessSerializer(user, data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid data", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Step 3: Save user and generate token
        try:
            user = serializer.save()
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            activation_link = request.build_absolute_uri(
                reverse("verify-account", kwargs={"uidb64": uid, "token": token})
            )
        except Exception as e:
            return Response(
                {
                    "error": "An error occurred during user save or token generation.",
                    "details": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        first_name = user.first_name
        last_name = user.last_name
        role = user.role
        default_password = user.default_password
        approved_subject = "Activate your account"
        declined_subject = "Request access - declined"
        email_address = user.email_address

        # Step 4: Email logic
        try:
            if user.is_verified:
                message_approval = render_to_string(
                    "accounts/approval_email.html",
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                        "role": role,
                        "activation_link": activation_link,
                        "default_password": default_password,
                    },
                )
                send_html_email(
                    subject=approved_subject,
                    body=message_approval,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_email=[email_address],
                )
                response = {
                    "message": f"Access granted to {first_name} {last_name} with the role of {role}."
                }
                return Response(response, status=status.HTTP_200_OK)
            else:
                message_decline = render_to_string(
                    "accounts/decline_email.html",
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                        "role": role,
                        "activation_link": activation_link,
                        "default_password": default_password,
                    },
                )
                send_html_email(
                    subject=declined_subject,
                    body=message_decline,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_email=[user.email_address],
                )
                response = {
                    "message": f"Access for {first_name} {last_name} has been declined."
                }
                return Response(response, status=status.HTTP_200_OK)
        except BadHeaderError:
            return Response(
                {"error": "Invalid header found in the email."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except SMTPException as e:
            return Response(
                {"error": "SMTP error while sending email.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception as e:
            return Response(
                {
                    "error": "An unexpected error occurred while sending email.",
                    "details": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class VerifyUser(APIView):
    @swagger_auto_schema(
        operation_summary="This is verifying if the token is valid for a new admin user",
        operation_description="This endpoint checked the validity of the token for an admin user.",
    )
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)

            # check if the token has been used
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                # return HttpResponse("Invalid Token")
                return HttpResponseRedirect(
                    "https://cvms-admin.vercel.app/#/auth/update-user-password?status=invalid",
                    status=400,
                )
            # return HttpResponse(
            #     "Token Valid and successful, redirecting to the change password page"
            # )
            return HttpResponseRedirect(
                f"https://cvms-admin.vercel.app/#/auth/update-user-password?uidb64={uidb64}&token={token}&status=valid"
            )

        except Exception as e:
            return HttpResponse(
                "https://cvms-admin.vercel.app/#/auth/update-user-password?status=invalid",
                status=400,
            )
            # return HttpResponseRedirect(
            #     "https://cvms-admin.com/change-password?status=invalid"
            # )


class ChangeDefaultPasswordAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This is responsible for changing the default password",
        operation_description="This endpoint change the default password",
        request_body=ChangeDefaultPassword,
    )
    def patch(self, request):
        data = request.data
        serializer = ChangeDefaultPassword(data=request.data)

        if serializer.is_valid():
            validated_data = serializer.save()

            try:
                token = validated_data.get("token")
                uidb64 = validated_data.get("uidb64")

                uid = urlsafe_base64_decode(uidb64).decode()
                user = CustomUser.objects.get(pk=uid)

                # check if the token has been used
                token_generator = PasswordResetTokenGenerator()

                if not token_generator.check_token(user, token):
                    return Response(
                        {"error": "Token has been used"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Update user's password and save
                password = serializer.validated_data.get("password")
                user.set_password(password)
                # Activate the user
                user.is_verified = True
                user.is_active = True
                user.save()

                return Response(
                    {"message": "Password updated successfully"},
                    status=status.HTTP_200_OK,
                )

            except CustomUser.DoesNotExist:
                return Response(
                    {"error": "User not found"},
                    status=status.HTTP_404_NOT_FOUND,
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

        email_address = serializer.validated_data.get("email_address")
        password = serializer.validated_data.get("password")

        try:
            # Fetch the user by email
            user = CustomUser.objects.get(email_address=email_address, is_verified=True)
        except CustomUser.DoesNotExist:
            return Response(
                {"message": "User with this email does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if the user is locked out
        if user.login_attempts >= 3 and not user.is_active:
            if user.last_login_attempt:
                locked_account_log(request, user)
                return Response(
                    {
                        "message": "User account is locked. click on forgot password to unlock account"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            # else:
            # Reset user lockout after 2 hours
            # user.is_active = True
            # user.login_attempts = 0
            # user.last_login_attempt = None
            # user.save()

        # Validate the password
        if not user.check_password(password):
            user.unsuccessful_login_attempt()
            login_failed_log(request, user, reason="Invalid password")
            return Response(
                {"message": "Incorrect password"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Check if the account is inactive
        if not user.is_active:
            login_failed_log(
                request,
                user,
                reason="Inactive user trying to logging without activation",
            )
            return Response(
                {
                    "message": "User account is not active. Click on the link in your email to activate your account."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if 2FA is enabled: frontend should take note to redirect to the 2FV page
        if user.is_2fa_enabled:
            return Response(
                {"message": "2FA required", "requires_2fa": True},
                status=status.HTTP_200_OK,
            )

        # Authenticate the user
        authenticated_user = authenticate(
            request=request,
            username=email_address,
            password=password,
        )

        if authenticated_user is None:
            user.unsuccessful_login_attempt()
            login_failed_log(request, user, reason="unauthenticated user or invalid credentials")
            return Response(
                {"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Generate tokens and return user info
        tokens = create_jwt_pair_for_user(authenticated_user)
        user.successful_login_attempt()
        login_successful_log(request, user)
        return Response(
            {
                "message": "Login successfully",
                "token": tokens,
                "user": {
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
            },
            status=status.HTTP_200_OK,
        )


# Two factor verification and login
class TwoFALoginAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for logging in an admin user using 2FA",
        operation_description="This endpoint logs in an admin using 2FA",
        request_body=TwoFASerializer,
    )
    def post(self, request):
        serializer = TwoFASerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data.get("token", "")

        # Retrieve the email address from the session
        email_address = request.session.get("email_address", None)

        try:
            user = CustomUser.objects.get(email_address=email_address, is_verified=True)

            # Verify the 2FA token
            if user.verify_totp(token) or user.verify_totp(token, tolerance=1):
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

        except CustomUser.DoesNotExist:
            return Response(
                data={"message": "User does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Generate TOTP and anable 2FA
class Enable2FAAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

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
    authentication_classes = [JWTAuthentication]

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


# forget Password
class ForgetPasswordAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for getting users email to reset their password.",
        operation_description="This endpoint collects user email for password reset.",
        request_body=ForgetPasswordEmailRequestSerializer,
    )
    def post(self, request):
        serializer = ForgetPasswordEmailRequestSerializer(data=request.data)
        if serializer.is_valid():
            email_address = serializer.validated_data["email_address"]
            try:
                user = CustomUser.objects.get(email_address=email_address)
            except ObjectDoesNotExist:
                response = {
                    "message": "User with this email does not exist.",
                }
                return Response(data=response, status=status.HTTP_404_NOT_FOUND)

            # Generate activation token
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            generate_token = TokenGenerator()
            token = generate_token.make_token(user)
            expired_at = timezone.now() + timezone.timedelta(hours=1)
            first_name = user.first_name

            # create the token
            PasswordResetToken.objects.create(
                user=user,
                token=token,
                expired_at=expired_at,
            )

            # Construct activation link
            activation_link = request.build_absolute_uri(
                reverse(
                    "reset-password-token-check",
                    kwargs={"uidb64": uid, "token": token},
                )
            )
            # Send reset password email
            subject = "Reset Your Pasword"

            message = render_to_string(
                "accounts/reset_password_email.html",
                {"first_name": first_name, "activation_link": activation_link},
            )

            try:
                send_html_email(
                    subject=subject,
                    body=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_email=[user.email_address],
                )
                response = {
                    "message": "Reset email successfully sent. Please check your email.",
                    "uidb64": uid,
                    "token": token,
                }
                return Response(data=response, status=status.HTTP_200_OK)

            except SMTPException as e:
                response = {
                    "message": "There was an error sending the reset email. Please try again later.",
                    "error": str(e),
                }
                return Response(
                    data=response, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            except ConnectionRefusedError as e:
                response = {
                    "message": "Could not connect to the email server. Please check your email settings.",
                    "error": str(e),
                }
                return Response(
                    data=response, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            except TimeoutError as e:
                response = {
                    "message": "Email server timeout. Please try again later.",
                    "error": str(e),
                }
                return Response(
                    data=response, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordTokenCheck(APIView):
    def get(self, request, uidb64, token):

        try:
            uid = urlsafe_base64_decode(uidb64).decode()

            user = CustomUser.objects.get(pk=uid)

            # check if the token has been used
            # token_generator = PasswordResetTokenGenerator()

            token_generator = TokenGenerator()

            if not token_generator.check_token(user, token):
                # Redirect to the frontend URL with an invalid token status
                # return Response(
                #     {"error": "Token has been used"}, status=status.HTTP_400_BAD_REQUEST
                # )
                return HttpResponseRedirect(
                    "https://cvms-admin.vercel.app/#/auth/reset-password?status=invalid",
                    status=400,
                )

            # if user.expired_at < timezone.now():
            #     response = {"message": "Token has expired, please generate another one"}
            #     return (
            #         Response(data=response, status=status.HTTP_404_NOT_FOUND),
            #     )

            # return Response(
            #     {
            #         "message": True,
            #         "messge": "Credentials valid",
            #         "uidb64": uidb64,
            #         "token": token,
            #     },
            #     status=status.HTTP_200_OK,
            # )

            # return HttpResponse(
            #     "Token Valid and successful, redirecting to the change password page"
            # )
            return HttpResponseRedirect(
                f"https://cvms-admin.vercel.app/#/auth/reset-password?uidb64={uidb64}&token={token}&status=valid"
            )

        # except DjangoUnicodeDecodeError as e:
        #     return Response({"error": "Tokeen is not valid, please request a new one"})
        except DjangoUnicodeDecodeError as e:
            # Redirect to the frontend URL with an invalid token status
            # return HttpResponse(
            #     "Token invalid, please cheeck tokeen; redirect to login screen"
            # )
            return HttpResponseRedirect(
                "https://cvms-admin.vercel.app/#/auth/reset-password?status=invalid",
                status=400,
            )


class SetNewPasswordAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for resetting the user's password if he forgets",
        operation_description="""
    This endpoint validates and updates the user's password. The password must meet the following requirements:
    
    - **At least one uppercase letter** (A-Z)
    - **At least one digit** (0-9)
    - **At least one special character** from the set: `!@#$%^&*()-_=+{};:,<.>`
    
    If these conditions are not met, an error message will be returned. 
    """,
        request_body=SetNewPasswordSerializer,
    )
    def patch(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data["password"]
            token = serializer.validated_data["token"]
            uidb64 = serializer.validated_data["uidb64"]

            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = CustomUser.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
                return Response(
                    {"error": "Invalid UID or user not found."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                reset_token = PasswordResetToken.objects.get(user=user, token=token)
                if reset_token.is_expired():
                    return Response(
                        {"error": "Token has expired."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                if reset_token.used:
                    return Response(
                        {"error": "Token has already been used."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Validate token
                token_generator = TokenGenerator()
                if not token_generator.check_token(user, token):
                    return Response(
                        {"error": "Invalid token for this user."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                # Set new password and mark token as used
                user.set_password(password)
                user.is_active = True
                user.save()
                reset_token.used = True
                reset_token.save()

                # pasword upddated logs
                password_updated_log(
                    request,
                    user,
                    reason="user updated his/her password",
                )

                return Response(
                    {"message": "Password updated successfully."},
                    status=status.HTTP_200_OK,
                )

            except PasswordResetToken.DoesNotExist:
                return Response(
                    {"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Reset password feature
class ResetPasswordAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for resetting the user password",
        operation_description="Resets the users password - must be an authenticated user",
        request_body=ResetPasswordSerializer,
    )
    def patch(self, request):
        user = request.user
        serializer = ResetPasswordSerializer(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            serializer.save()
            response = {"message": "Password updated successfully"}
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Logout APIView
class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    # authentication_classes = [CustomJWTAuthentication]

    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for logging the user out of the application",
        operation_description="Logs out the user from the application by blacklisting their refresh JWT token.",
    )
    def post(self, request):
        try:
            # Obtain the user's refresh token from the request
            refresh_token = request.data.get("refresh")
            token = RefreshToken(refresh_token)
            # Blacklist the refresh token
            token.blacklist()
            return Response(
                {"message": "You have been logged out"}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# deactivating a user
class DeactivateUerPAIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @swagger_auto_schema(
        operation_summary="This endpoint deactivates an admin user",
        operation_description="Deactivate an admin user from the application.",
    )
    def patch(self, request, slug):
        user = get_object_or_404(CustomUser, slug=slug)
        serializer = DeactivateAdminUserSerializer(
            user, data=request.data, partial=True
        )

        if serializer.is_valid():
            serializer.save()

            # call the deactivation logs here

            return Response({"message": True}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# unveried users list
class AllUsersList(generics.ListAPIView):
    queryset = CustomUser.objects.all().select_related("profile")
    serializer_class = CustomUserSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["=first_name", "=last_name", "=email_address", "phone_number"]
    pagination_class = AllUsersPagination

    @swagger_auto_schema(
        operation_summary="List all users with optional date, first_name, email_address and phone_number  filters",
        operation_description="""
        This endpoint retrieves all users. 
        Optionally, you can filter users by their registration date by providing the following query parameters:

        - **first_name**: Filters users with their first name.
        - **email_address**: Filters users with their email_address.
        - **phone_number**: Filters users with their phone_number.
        - **start_date**: Filters users registered on or after this date (YYYY-MM-DD).
        - **end_date**: Filters users registered on or before this date (YYYY-MM-DD).
         - **request_status**: Filters users by request status (pending, approved, or declined).

        Example usage:
        ```
        GET /api/all-users/?start_date=2023-01-01&end_date=2023-03-01
        ```
        """,
        manual_parameters=[
            openapi.Parameter(
                "start_date",
                openapi.IN_QUERY,
                description="Filter users from this date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_DATE,
            ),
            openapi.Parameter(
                "end_date",
                openapi.IN_QUERY,
                description="Filter users up to this date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_DATE,
            ),
            openapi.Parameter(
                "request_status",
                openapi.IN_QUERY,
                description="Filter users by request status (pending, approved, or declined)",
                type=openapi.TYPE_STRING,
            ),
        ],
    )
    def get_queryset(self):
        queryset = super().get_queryset()

        # Cast created_at to a date to ignore time when filtering
        queryset = queryset.annotate(created_date=Cast("created_at", DateField()))

        # Get the start and end dates from the query parameters
        start_date = self.request.query_params.get("start_date")
        end_date = self.request.query_params.get("end_date")
        request_status = self.request.query_params.get("request_status")

        # If start_date is provided, filter the queryset from that date onwards
        if start_date:
            start_date_parsed = parse_date(start_date)
            if start_date_parsed:
                queryset = queryset.filter(created_date__gte=start_date_parsed)

        # If end_date is provided, filter the queryset up to that date
        if end_date:
            end_date_parsed = parse_date(end_date)
            if end_date_parsed:
                queryset = queryset.filter(created_date__lte=end_date_parsed)

        # Filter by request_status if provided
        if request_status:
            queryset = queryset.filter(request_status=request_status)

        return queryset


# User-details
class UserDetailView(GenericAPIView):
    queryset = CustomUser.objects.all().select_related("profile")
    serializer_class = CustomUserSerializer
    lookup_field = "slug"

    def get(self, request, slug):
        try:
            all_user = self.get_object()
            serializer = self.get_serializer(all_user)
            response = {
                "message": "Successfully fetched user details",
                "data": serializer.data,
            }
            return Response(data=response, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )


# all user profile
class AllProfileView(GenericAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["rank", "department", "staff_id", "command", "zone"]
    pagination_class = ProfilesPegination

    @swagger_auto_schema(
        operation_summary="List all profile with optional search filters",
        operation_description="""
        This endpoint retrieves all users. 
        Optionally, you can filter search by their rank, zone, department, by the following query parameters:

        - **rank**: Filters users with their rank.
        - **department**: Filters users with their department.
        - **zone**: Filters users with their zone.
        - **command**: Filters users with their command.
        - **staff_d**: Filters users with their staff_id.
.

        Example usage:
        ```
        GET /api/unverified-users/?department=HR/
        ```
        """,
    )
    def get(self, request, *args, **kwargs):
        profiles = self.get_queryset()

        # Paginate the queryset
        page = self.paginate_queryset(profiles)
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)


class AllProfileDetailAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="profile detail API enpoint",
        operation_description="""
        This endpoint retrieves a single user profile.
        """,
    )
    def get(self, request, slug):
        user_profile = get_object_or_404(Profile, slug=slug)
        serializer = ProfileSerializer(user_profile)
        response = {
            "message": "successfully fetch user profile",
            "data": serializer.data,
        }

        return Response(data=response, status=status.HTTP_200_OK)


class UserProfileUpdateAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="profile update API enpoint",
        operation_description="""
        This endpoint retrieves and update a user profile.
        """,
        request_body=ProfileSerializer,
    )
    def patch(self, request, slug):
        user_profile = get_object_or_404(Profile, slug=slug)
        serializer = ProfileSerializer(user_profile, data=request.data)

        if serializer.is_valid():
            serializer.save()
            response = {
                "message": "profile successfully updated",
                "data": serializer.data,
            }
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
