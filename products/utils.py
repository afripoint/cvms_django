import requests

from utils.custom_handlers import send_critical_email


EXTERNAL_API_URL_LIST = "https://backend.afridev.com.ng/api/v1/product/products"
EXTERNAL_API_URL = "https://backend.afridev.com.ng/api/v1/product/product/create"
EXTERNAL_UPDATE_API_URL = "https://backend.afridev.com.ng/api/v1/product/product/update"
EXTERNAL_DELETE_API_URL = "https://backend.afridev.com.ng/api/v1/product/product/delete"
EXTERNAL_CHANGE_STATUS_API_URL = "https://backend.afridev.com.ng/api/v1/product/product/"
SECRET_KEY = "rbAZcgfSXQLiHHCzYk8pDU9svNpnoFNZ"

def create_product_in_external(data):
    headers = {
         'x-secret-key': SECRET_KEY,
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(EXTERNAL_API_URL, json=data, headers=headers)
        response.raise_for_status()  
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        send_critical_email(
            error=str(e),
            description="Failed to connect to external API to create product",
            error_code=getattr(e.response, 'status_code', None),
            user_action="Check external API availability and connection settings",
            user_id=None
        )
        return {"error": str(e)}, 503
    



def update_product_in_external(product_id, data):
    headers = {
        'x-secret-key': SECRET_KEY,
        'Content-Type': 'application/json'
    }

    url = f"{EXTERNAL_UPDATE_API_URL}/{product_id}"

    try:
        response = requests.put(url, json=data, headers=headers)
        response.raise_for_status()  
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        send_critical_email(
            error=str(e),
            description=f"Failed to connect to external API to update product with ID {product_id}",
            error_code=getattr(e.response, 'status_code', None),
            user_action="Check external API availability and connection settings",
            user_id=None
        )
        return {"error": str(e)}, 503
    
def remove_product_in_external(product_id):
    headers = {
        'x-secret-key': SECRET_KEY,
        'Content-Type': 'application/json'
    }

    url = f"{EXTERNAL_DELETE_API_URL}/{product_id}"

    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()  
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        send_critical_email(
            error=str(e),
            description=f"Failed to connect to external API to delete product with ID {product_id}",
            error_code=getattr(e.response, 'status_code', None),
            user_action="Check external API availability and connection settings",
            user_id=None
        )
        return {"error": str(e)}, 503
    
def change_status_product_in_external(product_id):
    headers = {
        'x-secret-key': SECRET_KEY,
        'Content-Type': 'application/json'
    }

    url = f"{EXTERNAL_CHANGE_STATUS_API_URL}/{product_id}/status"

    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()  
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        send_critical_email(
            error=str(e),
            description=f"Failed to connect to external API to change status with product_id {product_id}",
            error_code=getattr(e.response, 'status_code', None),
            user_action="Check external API availability and connection settings",
            user_id=None
        )
        return {"error": str(e)}, 503
    
# get_product_products
def list_product_external_api():
    headers = {
        'x-secret-key': SECRET_KEY,
        'Content-Type': 'application/json'
    }

    url = EXTERNAL_API_URL_LIST

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        return response.json()

    except requests.exceptions.RequestException as e:
        send_critical_email(
            error=str(e),
            description=f"Failed to connect to external API to list product",
            error_code=getattr(e.response, 'status_code', None),
            user_action="Check external API availability and connection settings",
            user_id=None
        )
        return {"error": str(e)}, 503