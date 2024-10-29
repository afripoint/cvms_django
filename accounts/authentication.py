from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings


class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        api_key = request.headers.get("X-API-Key")  # set the expeeected header key
        if not api_key:
            raise AuthenticationFailed("API key required")

        if api_key != settings.API_KEY:
            raise AuthenticationFailed("Invalid API Key")

        return None  # Return None for a successful authentication
