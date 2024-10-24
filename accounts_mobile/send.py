import requests

SENDCHAMP_BASE_URL = "https://api.sendchamp.com/api/v1"
SENDCHAMP_SECRET_KEY = (
    "sendchamp_live_$2a$10$NEwcSejAanfdBotl3Y4sfO3GfEyMWCJ2B5e0Oc3WjyjPfSgMmlL6S"
)


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
        "expiration_time": 1,
        "customer_mobile_number": phone_number,
        "meta_data": {"first_name": first_name},
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {SENDCHAMP_SECRET_KEY}",
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


# Sending OTP with whatsapp


def send_OTP_whatsapp(phone_number, otp_code, expiration_minutes):
    """
    Send OTP to a phone number via whatsapp using Sendchamp API.
    """
    url = f"{SENDCHAMP_BASE_URL}/whatsapp/message/send"

    payload = {
        "sender": "2347067959173",
        "recipient": phone_number,
        "template_code": "c05fc422-23c5-4d28-9199-76dbae2c46e2",
        "type": "template",
        "custom_data": {
            "body": {"1": phone_number, "2": otp_code, "3": str(expiration_minutes)}
        },
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {SENDCHAMP_SECRET_KEY}",
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response_data = response.json()
        # print(f"Status Code: {response.status_code}, Response Data: {response_data}")
        if response.status_code == 200:
            return response_data  # OTP sent successfully
        else:
            return {"error": response_data.get("message", "Failed to send OTP")}
    except requests.RequestException as e:
        return {"error": str(e)}


def send_message(phone_number, message):
    """
    Send message to a phone number via SMS through sendchamp API.
    """
    url = f"{SENDCHAMP_BASE_URL}/sms/send"

    payload = {
        "to": [phone_number],
        "message": message,
        "sender_name": "DAlert",
        "route": "international",
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {SENDCHAMP_SECRET_KEY}",
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response_data = response.json()
        print(f"Status Code: {response.status_code}, Response: {response_data}")
        if response.status_code == 200:
            return response_data
        else:
            return {"error": response_data.get("message", "Failed to send message")}
    except requests.RequestException as e:
        return {"error": str(e)}
