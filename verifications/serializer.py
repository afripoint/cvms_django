from rest_framework import serializers

class PaymentVerificationSerializer(serializers.Serializer):
    cert_num = serializers.CharField(max_length=255)