import requests
from django.conf import settings

from utils.custom_handlers import send_critical_email


def get_payment_status(cert_num, x_secret_key=None):
    url = "https://backend.afridev.com.ng/api/v1/vehicle/search-history/"

    headers = {
        "x-secret-key": x_secret_key,
    }

    try:
        response = requests.get(
            f"{url}?cert_num={cert_num}", headers=headers, verify=False
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        send_critical_email(
            error=str(http_err),
            description="HTTP error while verifying certificate payment status",
            user_action="check payment status",
            user_id=None,
            error_code=response.status_code,
        )
        return None
    except requests.exceptions.RequestException as req_err:
        send_critical_email(
            error=str(req_err),
            description="Request exception while verifying certificate payment status",
            user_action="check payment status",
            user_id=None,
            error_code=response.status_code,
        )
        return None
