import django_filters
from .models import CustomUser


class CustomUserFilter(django_filters.FilterSet):
    first_name = django_filters.CharFilter(field_name="first_name")
    email_address = django_filters.CharFilter(field_name="email_address")
    phone_number = django_filters.CharFilter(field_name="phone_number")

    class Meta:
        model = CustomUser
        fields = ['first_name', 'email_address', 'phone_number']