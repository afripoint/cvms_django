from django.http import HttpResponseRedirect
from django.shortcuts import render
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
from .serializers import ChangeDefaultPassword, CustomUserSerializer, LoginSerializer
from .models import ActivationToken, CustomUser


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

        # get the email and password
        email = serializer.validated_data.get("email", "")
        password = serializer.validated_data.get("password", "")

        try:
            user = CustomUser.objects.get(email=email, is_verified=True)

            # check if the user is active
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
            # Check password
            if check_password(password, user.password):
                user.successful_login_attempt()

                if not user.is_active:
                    return Response(
                        data={
                            "message": "User account is not active. activate acccount"
                        },
                        status=status.HTTP_403_FORBIDDEN,
                    )
                # Generate JWT tokens and return response
                new_user = authenticate(request, email=email, password=password)

                if new_user is not None:
                    # Generate JWT tokens
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
                Log.objects.create(
                    log_type="login_attempt",
                    message="Unsuccessful login attempt",
                    user=user.email_address,
                )
                return Response(
                    data={"message": "Wrong password"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except CustomUser.DoesNotExist:
            return Response(
                data={"message": "User does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            data={"message": "Invalid email or password"},
            status=status.HTTP_400_BAD_REQUEST,
        )
