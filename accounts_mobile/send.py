import requests

SENDCHAMP_BASE_URL = "https://api.sendchamp.com/api/v1"
SENDCHAMP_SECRET_KEY = "sendchamp_live_$2a$10$NEwcSejAanfdBotl3Y4sfO3GfEyMWCJ2B5e0Oc3WjyjPfSgMmlL6S"

def send_otp(phone_number, first_name):
    """
    Send OTP to a phone number using Sendchamp API.
    """
    url = f"{SENDCHAMP_BASE_URL}/verification/create"
    payload = {
        "channel": "sms",
        "token_type": "numeric",
        "sender": "Sendchamp",
        "token_length": "6",
        "expiration_time": 10,
        "customer_mobile_number": phone_number,
        "meta_data": {
            "first_name": first_name
        }
    }
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {SENDCHAMP_SECRET_KEY}'
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response_data = response.json()
        if response.status_code == 200:
            return response_data  # OTP sent successfully
        else:
            return {"error": response_data.get("message", "Failed to send OTP")}
    except requests.RequestException as e:
        return {"error": str(e)}



