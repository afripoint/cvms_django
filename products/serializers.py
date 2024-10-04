from rest_framework import serializers
from .models import Product


class ProductSerilizer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = (
            "product_name",
            "product_description",
            "product_price",
            "is_removed",
            "created_at",
            "created_at",
        )
        read_only_fields = (
            "created_at",
            "created_at",
            "is_removed",
        )


class ProductRemoveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ("is_removed",)
