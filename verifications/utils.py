import requests
from django.conf import settings


def get_payment_status(x_secret_key=None):
    url = 'https://cvmsnigeria.com/api/v1/vehicle/search-history/'

    headers = {
        'x-secret-key': x_secret_key or settings.X_SECRET_KEY, 
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises an error for HTTP codes 
        return response.json()  # Return JSON response if successful
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return None
    except Exception as err:
        print(f"An error occurred: {err}")
        return None