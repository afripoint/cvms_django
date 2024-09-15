from django.http import HttpResponseRedirect, HttpResponse
from smtplib import SMTPException
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
from django.core.mail import send_mail
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.tokens import RefreshToken
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
from accounts.utils import send_admin_email, send_user_email
from data_uploads.pagination import AllUnverifiedUsersPegination, AllUsersPegination
from logs.models import Log
from .serializers import (
    ChangeDefaultPassword,
    CustomUserSerializer,
    CustomUsersSerializer,
    DeactivateAdminUserSerializer,
    ForgetPasswordEmailRequestSerializer,
    GrantAccessSerializer,
    LoginSerializer,
    ResetPasswordSerializer,
    SetNewPasswordSerializer,
    TwoFASerializer,
    UserCreationRequestSerializer,
    Verify2FASerializer,
)
from .models import ActivationToken, CustomUser
from rest_framework.permissions import IsAuthenticated


# class CreateUserAPIView(APIView):
#     @swagger_auto_schema(
#         operation_summary="This is responsible for creating a sub-admin",
#         operation_description="This endpoint creates sub-admin",
#         request_body=CustomUserSerializer,
#     )
#     def post(self, request, *args, **kwargs):
#         serializer = CustomUserSerializer(data=request.data)
#         if serializer.is_valid():
#             user = serializer.save()

#             # Generate activation token
#             uid = urlsafe_base64_encode(force_bytes(user.pk))
#             token = default_token_generator.make_token(user)

#             # Construct activation link
#             activation_link = request.build_absolute_uri(
#                 reverse("verify-account", kwargs={"uidb64": uid, "token": token})
#             )

#             # send activation link
#             subject = "Activate your account"
#             message = f"Please click on the link to change your password from the default one: {activation_link}"
#             recipient_email = serializer.validated_data["email_address"]
#             send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [recipient_email])

#             ActivationToken.objects.create(user=user, token=token)

#             response = {
#                 "activation_link": activation_link,
#                 "uid": uid,
#                 "token": token,
#             }

#             return Response(data=response, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
                subject = "Access request"
                message_admin = f"A CVMS user - {first_name} {last_name} is requesting access to the dashboard. Kindly login to the dashboard and grant access"
                message_user = "You have requested access to the CVMS admin dashboard. You will be notified when granted access."

                send_admin_email(subject=subject, message=message_admin)

                # Send email to the user
                send_user_email(
                    subject=subject,
                    message=message_user,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[recipient_email],
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
        operation_summary="This endpoint verify users - admin",
        operation_description="Verify and grant access to users - admin",
        request_body=GrantAccessSerializer,
    )
    def post(self, request, slug):
        # get the user to verify
        user = get_object_or_404(CustomUser, slug=slug)
        serializer = GrantAccessSerializer(user, data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Generate activation token
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            first_name = user.first_name
            last_name = user.last_name
            role = user.role

            # Construct activation link
            activation_link = request.build_absolute_uri(
                reverse("verify-account", kwargs={"uidb64": uid, "token": token})
            )

            # Access the user's default password
            default_password = user.default_password

            # send activation link
            subject = "Activate your account"
            message = f"Please click on the link to change your password from the default one: {activation_link}. Your default password is: {default_password}"
            recipient_email = recipient_email = user.email_address

            if user.is_verified:
                # Email content for approved users
                subject = "Activate your account"
                message = (
                    f"Dear {first_name} {last_name},\n\n"
                    f"Your account has been verified and granted access as {role}. "
                    f"Please click on the link to change your password from the default one: {activation_link}. "
                    f"Your default password is: {default_password}."
                )
            else:
                # Email content for declined users
                subject = "Account Verification Declined"
                message = (
                    f"Dear {first_name} {last_name},\n\n"
                    f"Unfortunately, your account verification has been declined. "
                    f"If you believe this is a mistake, please contact support for assistance."
                )

            try:
                send_user_email(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[recipient_email],
                )

                # Save activation token (only for approved users)

                if user.is_verified:
                    ActivationToken.objects.create(user=user, token=token)

                    # Success response based on verification status

                status_message = (
                    f"You have successfully granted {first_name} {last_name} access with the role of {role}"
                    if user.is_verified
                    else f"Access for {first_name} {last_name} has been declined."
                )
                response = {
                    "message": status_message,
                }
                return Response(data=response, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response(
                    {"error": "Failed to send email notifications", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
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
                return HttpResponse("Invalid Token")
                # return HttpResponseRedirect(
                #     "https://cvms-admin.com/change-password?status=invalid"
                # )
            return HttpResponse(
                "Token Valid and successful, redirecting to the change password page"
            )
            # return HttpResponseRedirect(
            #     f"https://cvms-admin.com/change-password?uidb64={uidb64}&token={token}&status=valid"
            # )

        except Exception as e:
            return HttpResponse("Invalid token")
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

        # import pdb; pdb.set_trace()
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
                    {"success": "Password updated successfully"},
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
            if (
                user.last_login_attempt
                and timezone.now() < user.last_login_attempt + timedelta(hours=2)
            ):
                return Response(
                    {"message": "User account is locked. Try again after two hours."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            else:
                # Reset user lockout after 2 hours
                user.is_active = True
                user.login_attempts = 0
                user.last_login_attempt = None
                user.save()

        # Validate the password
        if not user.check_password(password):
            user.unsuccessful_login_attempt()
            return Response(
                {"message": "Incorrect password"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Reactivate account if successful login
        user.successful_login_attempt()

        # Check if the account is inactive
        if not user.is_active:
            return Response(
                {"message": "User account is not active. Please activate the account."},
                status=status.HTTP_403_FORBIDDEN,
            )

        # Check if 2FA is enabled
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
            return Response(
                {"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Generate tokens and return user info
        tokens = create_jwt_pair_for_user(authenticated_user)

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
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)

            # Construct activation link
            activation_link = request.build_absolute_uri(
                reverse(
                    "reset-password-token-check",
                    kwargs={"uidb64": uid, "token": token},
                )
            )
            # Send reset password email
            subject = "Reset Your Pasword"
            message = f"Please click the following link to reset your password: {activation_link}"
            recipient_email = email_address

            try:
                send_mail(
                    subject, message, settings.DEFAULT_FROM_EMAIL, [recipient_email]
                )
                response = {
                    "message": "Reset email successfully sent. Please check your email.",
                    "uidb64": uid,
                    "token": token,
                }

                return Response(data=response, status=status.HTTP_200_OK)

            except SMTPException as e:
                logging.error(f"SMTPException occurred: {str(e)}")
                response = {
                    "message": "There was an error sending the reset email. Please try again later.",
                    "error": str(e),
                }
                return Response(
                    data=response, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            except ConnectionRefusedError as e:
                logging.error(f"Connection error: {str(e)}")
                response = {
                    "message": "Could not connect to the email server. Please check your email settings.",
                }
                return Response(
                    data=response, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            except TimeoutError as e:
                logging.error(f"Timeout occurred: {str(e)}")
                response = {
                    "message": "Email server timeout. Please try again later.",
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
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                # Redirect to the frontend URL with an invalid token status
                # return Response({"error": "Token has been used"})
                return HttpResponseRedirect(
                    "https://parts-demo.vercel.app/new-password?status=invalid"
                )
            # return Response(
            #     {
            #         "success": True,
            #         "messge": "Credentials valid",
            #         "uidb64": uidb64,
            #         "token": token,
            #     },
            #     status=status.HTTP_200_OK,
            # )

            return HttpResponse(
                "Token Valid and successful, redirecting to the change password page"
            )
            # return HttpResponseRedirect(
            #     f"https://parts-demo.vercel.app/new-password?uidb64={uidb64}&token={token}&status=valid"
            # )

        # except DjangoUnicodeDecodeError as e:
        #     return Response({"error": "Tokeen is not valid, please request a new one"})
        except DjangoUnicodeDecodeError as e:
            # Redirect to the frontend URL with an invalid token status
            return HttpResponse(
                "Token invalid, please cheeck tokeen; redirect to login screen"
            )
            # return HttpResponseRedirect(
            #     "https://parts-demo.vercel.app/new-password?status=invalid"
            # )


class SetNewPasswordAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This is responsible for setting new password when password is forgotten",
        operation_description="This endpoint set new password when password is forgotten.",
        request_body=SetNewPasswordSerializer,
    )
    def patch(self, request):
        serializer = SetNewPasswordSerializer(data=request.POST)
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

                # Update user's password
                password = serializer.validated_data.get("password")
                user.set_password(password)
                user.save()
            except:
                return Response(
                    {"success": "Password updated successfully"},
                    status=status.HTTP_200_OK,
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
            response = {"success": "Password updated successfully"}
            return Response(data=response, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Logout APIView
class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

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

            return Response({"success": True}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# unveried users list
class UnVerifiedUsersList(GenericAPIView):
    queryset = CustomUser.objects.filter(is_verified=False)
    serializer_class = CustomUsersSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["first_name", "email_address", "phone_number"]
    pagination_class = AllUnverifiedUsersPegination

    @swagger_auto_schema(
        operation_summary="List all unverified users with optional date, first_name, email_address and phone_number  filters",
        operation_description="""
        This endpoint retrieves all unverified users. 
        Optionally, you can filter users by their registration date by providing the following query parameters:

        - **first_name**: Filters users with their first name.
        - **email_address**: Filters users with their email_address.
        - **phone_number**: Filters users with their phone_number.
        - **start_date**: Filters users registered on or after this date (YYYY-MM-DD).
        - **end_date**: Filters users registered on or before this date (YYYY-MM-DD).

        Example usage:
        ```
        GET /api/unverified-users/?start_date=2023-01-01&end_date=2023-03-01
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
        ],
    )
    def get(self, request, *args, **kwargs):
        verified_users = self.get_queryset()

        # Paginate the queryset
        page = self.paginate_queryset(verified_users)
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def get_queryset(self):
        queryset = super().get_queryset()

        # Get the start and end dates from the query parameters
        start_date = self.request.query_params.get("start_date")
        end_date = self.request.query_params.get("end_date")

        # If start_date is provided, filter the queryset from that date onwards
        if start_date:
            start_date_parsed = parse_date(start_date)
            if start_date_parsed:
                queryset = queryset.filter(created_at__gte=start_date_parsed)

        # If end_date is provided, filter the queryset up to that date
        if end_date:
            end_date_parsed = parse_date(end_date)
            if end_date_parsed:
                queryset = queryset.filter(created_at__lte=end_date_parsed)

        return queryset


class UnverifiedUserDetailView(GenericAPIView):
    queryset = CustomUser.objects.filter(is_verified=False)
    serializer_class = CustomUsersSerializer
    lookup_field = "slug"

    def get(self, request, slug):
        try:
            unverified_user = self.get_object()
            serializer = self.get_serializer(unverified_user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )


# throathing meaning 



class AllUsersList(GenericAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUsersSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["first_name", "email_address", "phone_number"]
    pagination_class = AllUsersPegination

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

        Example usage:
        ```
        GET /api/unverified-users/?start_date=2023-01-01&end_date=2023-03-01
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
        ],
    )
    def get(self, request, *args, **kwargs):
        all_users = self.get_queryset()

        # Paginate the queryset
        page = self.paginate_queryset(all_users)
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    def get_queryset(self):
        queryset = super().get_queryset()

        # Get the start and end dates from the query parameters
        start_date = self.request.query_params.get("start_date")
        end_date = self.request.query_params.get("end_date")

        # If start_date is provided, filter the queryset from that date onwards
        if start_date:
            start_date_parsed = parse_date(start_date)
            if start_date_parsed:
                queryset = queryset.filter(created_at__gte=start_date_parsed)

        # If end_date is provided, filter the queryset up to that date
        if end_date:
            end_date_parsed = parse_date(end_date)
            if end_date_parsed:
                queryset = queryset.filter(created_at__lte=end_date_parsed)

        return queryset



# User-details

class UserDetailView(GenericAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUsersSerializer
    lookup_field = "slug"

    def get(self, request, slug):
        try:
            all_user = self.get_object()
            serializer = self.get_serializer(all_user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except CustomUser.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )
