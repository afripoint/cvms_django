from rest_framework import serializers


class ProductCreateSerializer(serializers.Serializer):
    product_id = serializers.CharField(max_length=255)
    product_name = serializers.CharField(max_length=255)
    description = serializers.CharField()
    price = serializers.FloatField()
    active = serializers.BooleanField()
    downloadable = serializers.BooleanField()
    duration = serializers.IntegerField()
class ProductUpdateSerializer(serializers.Serializer):
    active = serializers.BooleanField()

