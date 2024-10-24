from django.conf import settings
from drf_yasg import openapi
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from django.template.loader import render_to_string
from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist
from drf_yasg.utils import swagger_auto_schema
from accounts.auth_logs import (
    locked_account_log,
    login_failed_log,
    login_successful_log,
    password_updated_log,
)
from accounts.models import CVMSAuthLog, CustomUser
from accounts.serializers import LoginSerializer
from accounts.signals import get_client_ip
from accounts.tokens import create_jwt_pair_for_user
from django.contrib.auth import authenticate
from rest_framework import status
from datetime import timedelta
from django.utils import timezone

from accounts.utils import send_html_email
from accounts_mobile.send import send_OTP_whatsapp, send_otp
from accounts_mobile.serializers import (
    ForgetPasswordMobileEmailRequestSerializer,
    OTPVerificationSerializer,
    SetNewPasswordMobileSerializer,
)
from accounts_mobile.utils import generateRandomOTP


class LoginMobileAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Login an Enforcement Officer",
        operation_description="""
        This endpoint allows an Enforcement Officer to log in using their registered email and password.

        ### Workflow:
        1. **Email Verification:** The system checks if the user exists with the provided email and if the email is verified.
        2. **Role Check:** Only users with the role of "Enforcement Officer" are allowed to log in.
        3. **Account Lock Check:** If the user has made 3 failed login attempts and is locked, they are prevented from logging in until the account is unlocked.
        4. **Password Validation:** The provided password is validated against the stored password.
        5. **Account Status:** The system checks if the user's account is active. If the account is inactive, the user is prompted to activate their account.
        6. **2FA Check:** If 2FA is enabled, the user will be notified, and further authentication steps are required.
        7. **JWT Token Generation:** Upon successful login, JWT tokens are generated and returned, along with basic user info.

        ### Request Fields:
        - **email_address** (string): The registered email address of the user.
        - **password** (string): The user's password.

        ### Responses:
        - **200 OK**: Login is successful, tokens and user details are returned.
        - **403 Forbidden**: If the user does not have the "Enforcement Officer" role.
        - **400 Bad Request**: If the user does not exist, the account is locked, the account is inactive, or the credentials are incorrect.
        - **200 OK (2FA Required)**: If the user has 2FA enabled, prompting for further verification.

        ### Example Usage:
        ```
        POST /api/login/
        {
            "email_address": "officer@example.com",
            "password": "password123"
        }
        ```

        ### Example Response (Success):
        ```
        HTTP 200 OK
        {
            "message": "Login successful",
            "token": {
                "access": "access-token-string",
                "refresh": "refresh-token-string"
            },
            "user": {
                "first_name": "John",
                "last_name": "Doe"
            }
        }
        ```

        ### Example Response (2FA Required):
        ```
        HTTP 200 OK
        {
            "message": "2FA required",
            "requires_2fa": true
        }
        ```

        ### Example Response (Role Mismatch):
        ```
        HTTP 403 Forbidden
        {
            "message": "You are not authorized to log in here."
        }
        ```

        ### Example Response (Locked Account):
        ```
        HTTP 400 Bad Request
        {
            "message": "User account is locked. click on forgot password to unlock account"
        }
        ```

        ### Example Response (Incorrect Password):
        ```
        HTTP 400 Bad Request
        {
            "message": "Incorrect password"
        }
        ```

        ### Example Response (Inactive Account):
        ```
        HTTP 400 Bad Request
        {
            "message": "User account is not active. Click on the link in your email to activate your account."
        }
        ```
        """,
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

        # Check if the user's role is "Enforcement Officer" and block their login attempt
        if not (user.role.role == "Enforcement Officer"):
            return Response(
                {"message": "You are not authorized to log in here."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Check if the user is locked out
        if user.login_attempts >= 3 and not user.is_active:
            if user.last_login_attempt:
                locked_account_log(request, user)
                # create a an audit log here
                CVMSAuthLog.objects.create(
                    user=user,
                    event_type="lock account",
                    device_details=request.META.get("HTTP_USER_AGENT"),
                    status_code=400,
                    ip_address=get_client_ip(request),
                    reason="Account has been locked",
                    additional_info=None,
                )
                return Response(
                    {
                        "message": "User account is locked. click on forgot password to unlock account"
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        # Validate the password
        if not user.check_password(password):
            user.unsuccessful_login_attempt()
            login_failed_log(request, user, reason="Invalid password")
            CVMSAuthLog.objects.create(
                    user=user,
                    event_type="invalid password",
                    device_details=request.META.get("HTTP_USER_AGENT"),
                    status_code=400,
                    ip_address=get_client_ip(request),
                    reason="Invalid or incorrect passord",
                    additional_info=None,
                )
            return Response(
                {"message": "Incorrect password"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Check if the account is inactive
        if not user.is_active:
            CVMSAuthLog.objects.create(
                    user=user,
                    event_type="inactive user",
                    device_details=request.META.get("HTTP_USER_AGENT"),
                    status_code=400,
                    ip_address=get_client_ip(request),
                    reason="Inactive user trying to logging without activation",
                    additional_info=None,
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
            login_failed_log(
                request, user, reason="unauthenticated user or invalid credentials"
            )
            CVMSAuthLog.objects.create(
                    user=user,
                    event_type="invalid password",
                    device_details=request.META.get("HTTP_USER_AGENT"),
                    status_code=400,
                    ip_address=get_client_ip(request),
                    reason="invalid credentials or password",
                    additional_info=None,
                )
            return Response(
                {"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Generate tokens and return user info
        tokens = create_jwt_pair_for_user(authenticated_user)
        user.successful_login_attempt()
        CVMSAuthLog.objects.create(
                    user=user,
                    event_type="login success",
                    device_details=request.META.get("HTTP_USER_AGENT"),
                    status_code=200,
                    ip_address=get_client_ip(request),
                    reason="User logged in successfully",
                    additional_info=None,
                )
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


# Forgot password
class ForgetPasswordAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Request password reset via email or phone",
        operation_description="""
        This endpoint allows users to request a password reset by providing their registered email address and selecting the mode of OTP delivery (email, SMS, or WhatsApp).

        ### Workflow:
        1. The user submits their email address and the preferred OTP delivery method (SMS, email, or WhatsApp).
        2. The system checks if a user exists with the provided email.
        3. If the user is found, an OTP (One-Time Password) is generated and sent to the user via the selected method.
        4. The OTP is valid for 1 minutes, and the user can use the OTP to reset their password.
        5. If the user is not found, an appropriate error message is returned.

        ### Request Fields:
        - **email_address** (string): The email address registered with the user's account.
        - **message_choice** (string): The preferred method to receive the OTP. It can be one of the following:
            - **sms**: OTP will be sent to the user's registered phone number via SMS.
            - **email**: OTP will be sent to the user's email address.
            - **whatsapp**: OTP will be sent via WhatsApp.

        ### Responses:
        - **200 OK**: The OTP was successfully sent to the user via the selected method.
        - **404 Not Found**: If the email address does not match any user in the system.
        - **400 Bad Request**: Validation errors if the input is incorrect.

        ### Example Usage:
        ``` 
        POST auth_mobile/forget_password/
        {
            "email_address": "user@example.com",
            "message_choice": "email"
        }
        ```

        ### Example Response (Success via SMS):
        ```
        HTTP 200 OK
        {
            "message": "OTP has been sent to your phone via sms",
            "slug": "user-slug"
        }
        ```

        ### Example Response (Success via Email):
        ```
        HTTP 200 OK
        {
            "message": "OTP has been sent to your email account",
            "slug": "user-slug"
        }
        ```

        ### Example Response (Success via WhatsApp):
        ```
        HTTP 200 OK
        {
            "message": "OTP has been sent to your WhatsApp",
            "slug": "user-slug"
        }
        ```

        ### Example Response (Failure - User Not Found):
        ```
        HTTP 404 Not Found
        {
            "message": "User with this email does not exist."
        }
        ```

        ### Example Response (Failure - Validation Error):
        ```
        HTTP 400 Bad Request
        {
            "email_address": [
                "This field is required."
            ]
        }
        ```
        """,
        request_body=ForgetPasswordMobileEmailRequestSerializer,
    )
    def post(self, request):
        serializer = ForgetPasswordMobileEmailRequestSerializer(data=request.data)
        if serializer.is_valid():
            email_address = serializer.validated_data["email_address"]
            message_choice = serializer.validated_data["message_choice"]
            otp_expire = timezone.now() + timedelta(minutes=1)
            otp_code = generateRandomOTP(111111, 999999)

            try:
                user = CustomUser.objects.get(email_address=email_address)
                phone_number = user.phone_number
                first_name = user.first_name
            except ObjectDoesNotExist:
                response = {
                    "message": "User with this email does not exist.",
                }
                return Response(data=response, status=status.HTTP_404_NOT_FOUND)

            if message_choice == "sms":
                send_otp(phone_number=phone_number, first_name=first_name)
                otp_sent = send_otp(phone_number=phone_number, first_name=first_name)
                otp = otp_sent.get("data", {}).get("token")
                user.otp = otp
                user.save()
                response = {
                    "message": "OTP has been sent to your phone via sms",
                    "slug": user.slug,
                }
                return Response(data=response, status=status.HTTP_200_OK)

            if message_choice == "email":
                # Get user details for email notification
                recipient_email = serializer.validated_data["email_address"]

                # Email content
                subject = "Request for OTP"

                message_user = render_to_string(
                    "accounts_mobile/accounts-mobile-otp.html",
                    {
                        "otp_code": otp_code,
                    },
                )

                send_html_email(
                    subject=subject,
                    body=message_user,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to_email=[recipient_email],
                )
                user.otp_expire = otp_expire
                user.otp = otp_code
                user.save()
                response = {
                    "message": "OTP has been sent to your email account",
                    "slug": user.slug,
                }
                return Response(data=response, status=status.HTTP_200_OK)

            if message_choice == "whatsapp":
                send_OTP_whatsapp(
                    phone_number=phone_number,
                    otp_code=otp_code,
                    expiration_minutes=otp_expire,
                )
                user.otp_expire = otp_expire
                user.otp = otp_code
                user.save()
                response = {
                    "message": "OTP has been sent to your whatsapp",
                    "slug": user.slug,
                }
                return Response(data=response, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# VERIFY OTP
class OTPVerificationView(APIView):
    @swagger_auto_schema(
        operation_summary="Verify a user using OTP (One-Time Password)",
        operation_description="""
        This endpoint is responsible for verifying a user by their phone number and OTP.

        ### Workflow:
        1. The user submits their OTP and phone number slug.
        2. The system checks if the OTP is valid and matches the user associated with the provided slug.
        3. If the OTP is correct and not expired (OTP expires after 10 minutes), the user is marked as verified and active.
        4. If the OTP is incorrect or has expired, appropriate error messages are returned.

        ### Request Fields:
        - **otp** (string): The one-time password sent to the user.

        ### URL Parameters:
        - **slug** (string): The unique identifier (slug) of the user to verify.

        ### Responses:
        - **200 OK**: Verification successful. The user is now marked as active and verified.
        - **400 Bad Request**: 
            - Incorrect OTP: If the provided OTP is wrong.
            - Expired OTP: If the OTP has expired (after 10 minutes).

        ### Example Usage:
        ```
        POST auth_mobile/verify/<slug>/
        {
            "otp": "123456"
        }
        ```

        ### Example Response (Success):
        ```
        HTTP 200 OK
        "Verification successful"
        ```

        ### Example Response (Failure - Wrong OTP):
        ```
        HTTP 400 Bad Request
        "Wrong OTP, please enter the correct OTP"
        ```

        ### Example Response (Failure - Expired OTP):
        ```
        HTTP 400 Bad Request
        {
            "message": "OTP has expired"
        }
        ```
        """,
        request_body=OTPVerificationSerializer,
    )
    def post(self, request, slug):
        otp = request.data.get("otp", None)
        try:
            user = CustomUser.objects.get(slug=slug, otp=otp)

        except CustomUser.DoesNotExist:
            return Response(
                "Wrong OTP, please enter the correct OTP",
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.is_verified = True
        user.is_active = True
        user.otp_expire = None
        user.otp = None

        user.save()

        response = {
            "message": "Verification successful",
            "slug": user.slug,
        }

        return Response(data=response, status=status.HTTP_200_OK)


# reset  password
class SetNewPasswordMobileAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="Reset User's Password",
        operation_description="""
        This endpoint allows the user to reset their password after verifying their slug. The new password must meet the following security criteria:

        ### Password Requirements:
        - **At least one uppercase letter** (A-Z)
        - **At least one digit** (0-9)
        - **At least one special character** from the set: `!@#$%^&*()-_=+{};:,<.>`

        ### Workflow:
        2. **Password Update:** If the slug is valid and the user is authorized, the user's password is updated with the new password.
        3. **Authorization:** The user must have the role of "Enforcement Officer" to proceed with password reset.


        ### Example Usage:
        ```
        PATCH /api/set-new-password/
        {
            "password": "NewPassword@123",
            "confirm_password": "NewPassword@123",
        }
        ```

        ### Example Responses:
        - **Success (200 OK)**:
        ```
        {
            "message": "Password updated successfully."
        }
        ```

        - **User Not Found (400 Bad Request)**:
        ```
        {
            "error": "user not found."
        }
        ```

        - **Unauthorized Role (403 Forbidden)**:
        ```
        {
            "message": "You are not authorized to use this app."
        }
        ```

        - **Password Validation Failure (400 Bad Request)**:
        ```
        {
            "password": ["Password must contain at least one uppercase letter, one digit, and one special character."]
        }
        ```

        - **Other Validation Failures (400 Bad Request)**:
        ```json
        {
            "slug": ["This field is required."]
        }
        ```
        """,
        request_body=SetNewPasswordMobileSerializer,
        responses={
            200: "Password updated successfully.",
            400: "Invalid request data or user not found.",
            403: "User not authorized to reset the password.",
        },
    )
    def patch(self, request, slug):
        serializer = SetNewPasswordMobileSerializer(data=request.data)
        if serializer.is_valid():
            password = serializer.validated_data["password"]

            try:
                user = CustomUser.objects.get(slug=slug)
            except (TypeError, ValueError, CustomUser.DoesNotExist):
                return Response(
                    {"error": "user not found."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Set new password and mark token as used
            user.set_password(password)
            user.is_active = True
            user.login_attempts = 0
            user.last_login_attempt = None
            user.save()

            # pasword updated logs
            password_updated_log(
                request,
                user,
                reason="user updated his/her password",
            )

            return Response(
                {"message": "Password updated successfully."},
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
