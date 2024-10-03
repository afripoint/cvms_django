from rest_framework import serializers
from .models import Product



class ProductSerilizer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ('product_name', 'product_description', 'product_price', )