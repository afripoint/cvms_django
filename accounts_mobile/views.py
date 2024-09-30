from drf_yasg import openapi
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from accounts.auth_logs import locked_account_log, login_failed_log, login_successful_log
from accounts.models import CustomUser
from accounts.serializers import LoginSerializer
from accounts.tokens import create_jwt_pair_for_user
from django.contrib.auth import authenticate
from rest_framework import status



class LoginMobileAPIView(APIView):
    @swagger_auto_schema(
        operation_summary="This endpoint is responsible for signing in an enforcement officer user",
        operation_description="This endpoint signs in an enforcement officer",
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
        if not(user.role.role == "Enforcement Officer"):
                return Response(
                    {"message": "You are not authorized to log in here."},
                    status=status.HTTP_403_FORBIDDEN,
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
            login_failed_log(
                request, user, reason="unauthenticated user or invalid credentials"
            )
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

