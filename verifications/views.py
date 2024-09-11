from django.shortcuts import render

# import requests
# from rest_framework.views import APIView
# from rest_framework.response import Response
# from rest_framework import status
# from .serializers import PaymentVerificationSerializer

# class VerifyPaymentAPIView(APIView):
#     """
#     API view to verify payment using payment_id extracted from a QR code.
#     """


#     EXTERNAL_API_URL = "https://external-api-url.com/payments"  # Replace with the actual external API endpoint

#     def post(self, request):
#         # Deserialize the incoming data
#         serializer = PaymentVerificationSerializer(data=request.data)
#         if serializer.is_valid():
#             payment_id = serializer.validated_data['payment_id']
            
#             # Make a request to the external API to fetch users and payment IDs
#             try:
#                 external_response = requests.get(self.EXTERNAL_API_URL)
                
#                 # Check if the external API call was successful
#                 if external_response.status_code == 200:
#                     payments_data = external_response.json()
                    
#                     # Verify if payment ID exists in the data received from the external API
#                     if any(payment['payment_id'] == payment_id for payment in payments_data):
#                         return Response({"status": "valid", "message": "Payment ID is valid."}, status=status.HTTP_200_OK)
#                     else:
#                         return Response({"status": "invalid", "message": "Payment ID is not found."}, status=status.HTTP_404_NOT_FOUND)
#                 else:
#                     # Handle cases where the external API call failed
#                     return Response({"status": "error", "message": "Failed to retrieve data from the external service."},
#                                     status=status.HTTP_502_BAD_GATEWAY)
#             except requests.exceptions.RequestException as e:
#                 # Handle exceptions that occur during the request to the external API
#                 return Response({"status": "error", "message": f"Error fetching data: {str(e)}"},
#                                 status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         else:
#             # If the incoming request data is invalid
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
