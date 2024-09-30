# from rest_framework_simplejwt.authentication import JWTAuthentication
# from rest_framework_simplejwt.exceptions import InvalidToken
# from rest_framework.exceptions import AuthenticationFailed
# from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
# from rest_framework.exceptions import AuthenticationFailed as DRFAuthenticationFailed
# import logging

# from rest_framework_simplejwt.authentication import JWTAuthentication
# from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
# from rest_framework.exceptions import AuthenticationFailed as DRFAuthenticationFailed
# from datetime import datetime
# from .models import JWTExpirationLog
# import logging

# logger = logging.getLogger(__name__)

# class CustomJWTAuthentication(JWTAuthentication):
#     def get_raw_token(self, request):
#         """
#         Extracts and returns the raw JWT token from the Authorization header.
#         """
#         header = self.get_header(request)

#         if header is None:
#             logger.info(f"Missing Authorization header from IP: {self.get_client_ip(request)}")
#             return None

#         try:
#             header = header.decode('utf-8')  # If it's in bytes format
#         except AttributeError:
#             pass  # Already a string

#         parts = header.split()

#         if len(parts) == 2 and parts[0] == 'Bearer':
#             return parts[1]

#         logger.warning(f"Invalid Authorization header format from IP: {self.get_client_ip(request)}")
#         return None

#     def authenticate(self, request):
#         """
#         Authenticate the user using the JWT token from the request.
#         Logs failed authentication attempts or token expirations.
#         """
#         raw_token = self.get_raw_token(request)

#         if raw_token is None:
#             logger.warning(f"Authentication failed - missing token from IP: {self.get_client_ip(request)}")
#             return None

#         try:
#             validated_token = self.get_validated_token(raw_token)
#             user = self.get_user(validated_token)
#             return user, validated_token

#         except InvalidToken as e:
#             # Log invalid token or token expiration
#             self.log_jwt_expiration(request, raw_token, reason="Invalid or Expired Token")
#             logger.error(f"Invalid token provided from IP: {self.get_client_ip(request)}")
#             raise AuthenticationFailed('Invalid or expired token')

#         except Exception as e:
#             logger.error(f"Error during authentication: {str(e)} from IP: {self.get_client_ip(request)}")
#             raise DRFAuthenticationFailed('Authentication failed')

#     def get_header(self, request):
#         """
#         Returns the Authorization header from the request, if present.
#         """
#         return request.headers.get('Authorization')

#     def get_client_ip(self, request):
#         """
#         Get the client IP address from the request.
#         """
#         x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
#         if x_forwarded_for:
#             ip = x_forwarded_for.split(',')[0]
#         else:
#             ip = request.META.get('REMOTE_ADDR')
#         return ip

#     def get_user_agent(self, request):
#         """
#         Get the user agent from the request headers.
#         """
#         return request.headers.get('User-Agent', 'unknown')

#     def log_jwt_expiration(self, request, raw_token, reason="Expired Token"):
#         """
#         Logs JWT expiration or invalid token details to the JWTExpirationLog model.
#         """
#         try:
#             # Assuming you have a way to extract user information or use request.user
#             user = getattr(request, 'user', None)

#             JWTExpirationLog.objects.create(
#                 user=user,  # Can be None if the user is not authenticated
#                 expiration_time=datetime.now(),
#                 ip_address=self.get_client_ip(request),
#                 token=raw_token,
#                 user_agent=self.get_user_agent(request)
#             )
#             logger.info(f"JWT expiration logged for {user} with reason: {reason}")

#         except Exception as log_error:
#             logger.error(f"Failed to log JWT expiration: {str(log_error)}")
