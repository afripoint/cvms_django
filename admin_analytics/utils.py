import requests
from django.conf import settings


EXTERNAL_API_BASE_URL = "https://cvmsnigeria.com/api/v1/admin/analytics"
EXTERNAL_API_TIMEOUT = 10  # Optional


def make_external_api_request(endpoint, params=None):
    """
    Utility function to make external API requests.
    - `endpoint`: the specific API endpoint to call (e.g., 'accounts-search-rates')
    - `params`: query parameters for the API request
    """
    url = f"{EXTERNAL_API_BASE_URL}/{endpoint}"

    try:
        response = requests.get(
            url, params=params, timeout=EXTERNAL_API_TIMEOUT, verify=False
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
