from rest_framework import serializers
from .models import Consignment


class ConsignmentRegisterSeriliazer(serializers.ModelSerializer):
    importer_phone = serializers.CharField(max_length=50, min_length=2, required=True)
    shipping_status = serializers.ChoiceField(
        choices=Consignment.SHIPMENT_STATUS, default="in transit"
    )

    class Meta:
        model = Consignment
        fields = (
            "bill_of_ladding",
            "registration_officer",
            "shipping_company",
            "importer_phone",
            "consignee",
            "shipping_status",
            "shipper",
            "terminal",
            "bonded_terminal",
            "description_of_goods",
            "gross_weight",
            "eta",
            "vessel_voyage",
            "hs_code",
            "port_of_landing",
            "port_of_discharge",
        )

    def validate_importer_phone(self, value):
        """
        Custom method to validate phone number format
        """
        if not value:
            raise serializers.ValidationError("Phone number is required.")

        if (
            len(value) != 11
            and not value.startswith("080")
            and not value.startswith("+234")
        ):
            raise serializers.ValidationError(
                "Phone number must start with '+234' or '080' and be 11 digits long."
            )

        if len(value) == 11:
            value = "+234" + value[1:]
        elif len(value) == 13:
            value = "+" + value

        return value


class ConsignmentUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Consignment
        fields = ("registration_officer", "shipping_status")