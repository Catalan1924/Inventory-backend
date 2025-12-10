# inventory/serializers.py
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import Product, Supplier, Order


class SupplierSerializer(serializers.ModelSerializer):
    class Meta:
        model = Supplier
        fields = "__all__"


class ProductSerializer(serializers.ModelSerializer):
    supplier = SupplierSerializer(read_only=True)
    supplier_id = serializers.PrimaryKeyRelatedField(
        queryset=Supplier.objects.all(),
        source="supplier",
        write_only=True,
        required=False,
        allow_null=True,
    )

    class Meta:
        model = Product
        fields = [
            "id",
            "name",
            "sku",
            "stock",
            "reorder_level",
            "supplier",
            "supplier_id",
        ]


class OrderSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_id = serializers.PrimaryKeyRelatedField(
        queryset=Product.objects.all(),
        source="product",
        write_only=True,
    )

    class Meta:
        model = Order
        fields = [
            "id",
            "order_number",
            "product",
            "product_id",
            "quantity",
            "status",
            "created_at",
        ]


class UserSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "is_staff",
            "is_superuser",
            "date_joined",
            "role",
        ]

    def get_role(self, obj):
        if obj.is_superuser:
            return "Admin"
        if obj.is_staff:
            return "Staff"
        return "User"
