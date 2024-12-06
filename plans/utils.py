import requests

from utils.custom_handlers import send_critical_email


WALLET_PLANS_API = "https://backend.afridev.com.ng/api/v1/wallet-plan"
WALLET_SUBSCRIPTION_API = "https://backend.afridev.com.ng/api/v1/wallet-plan/subscriptions"

# SECRET_KEY = "rbAZcgfSXQLiHHCzYk8pDU9svNpnoFNZ"

def retrieve_wallet_plans():
    headers = {
         'x-secret-key': None,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.get(WALLET_PLANS_API, headers=headers)
        response.raise_for_status()  
        return response.json()
    except requests.exceptions.RequestException as e:
        send_critical_email(
            error=str(e),
            description="Failed to connect to external API to retrieve wallet plans",
            error_code=getattr(e.response, 'status_code', None),
            user_action="Check external API availability and connection settings",
            user_id=None
        )
        return {"error": str(e)}, 503
    
def retrieve_wallet_subscription(params):
    headers = {
         'x-secret-key': None,
        'Content-Type': 'application/json'
    }

    url = f"{WALLET_SUBSCRIPTION_API}?duration_type={params}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        send_critical_email(
            error=str(e),
            description="Failed to connect to external API to retrieve wallet subscription",
            error_code=getattr(e.response, 'status_code', None),
            user_action="Check external API availability and connection settings",
            user_id=None
        )
        return {"error": str(e)}, 503
    



