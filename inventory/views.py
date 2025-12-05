# inventory/views.py
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from rest_framework import status, permissions, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from django.db import transaction

# Import your models and serializers
from .models import Product, Supplier, Order
from .serializers import (
    ProductSerializer,
    SupplierSerializer,
    OrderSerializer,
    UserSerializer,
)


# ------------------------
# AUTHENTICATION VIEWS
# ------------------------
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")

        if not username or not password:
            return Response(
                {"error": "Username and password are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if User.objects.filter(username=username).exists():
            return Response(
                {"error": "Username already exists"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create_user(username=username, email=email, password=password)
        token, _ = Token.objects.get_or_create(user=user)

        return Response(
            {"message": "User registered successfully", "token": token.key, "username": user.username},
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)

        if user is None:
            return Response(
                {"error": "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED
            )

        token, _ = Token.objects.get_or_create(user=user)

        return Response(
            {"message": "Login successful", "token": token.key, "username": user.username},
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)


# ------------------------
# PROFILE / PASSWORD
# ------------------------
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        user = request.user
        data = request.data
        # allow updating certain fields only
        user.email = data.get("email", user.email)
        user.first_name = data.get("first_name", user.first_name)
        user.last_name = data.get("last_name", user.last_name)
        user.save()
        return Response({"message": "Profile updated"})


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        if not new_password or len(new_password) < 6:
            return Response({"error": "New password must be at least 6 characters"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        # revoke existing tokens to force re-login (optional)
        Token.objects.filter(user=user).delete()
        return Response({"message": "Password changed. Please login again."})


# ------------------------
# USER LIST (admin only)
# ------------------------
class UsersListView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


# ------------------------
# PRODUCT / SUPPLIER / ORDER VIEWSETS
# ------------------------
# Permissions policy:
# - Read (list/retrieve): authenticated users
# - Create/Update/Delete: staff (is_staff) or superuser
class IsStaffOrReadOnly(permissions.BasePermission):
    """
    Allows read-only for authenticated users; write for staff/superuser only.
    """

    def has_permission(self, request, view):
        # allow safe methods for any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        # write operations require staff or superuser
        return request.user and (request.user.is_staff or request.user.is_superuser)


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by("id")
    serializer_class = ProductSerializer
    permission_classes = [IsStaffOrReadOnly]

    # optional: add search by name/sku via query param ?q=
    def get_queryset(self):
        qs = super().get_queryset()
        q = self.request.query_params.get("q")
        if q:
            return qs.filter(name__icontains=q) | qs.filter(sku__icontains=q)
        return qs

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def low_stock(self, request):
        """Return products where stock <= reorder_level"""
        items = Product.objects.filter(stock__lte=models.F("reorder_level"))
        serializer = self.get_serializer(items, many=True)
        return Response(serializer.data)


class SupplierViewSet(viewsets.ModelViewSet):
    queryset = Supplier.objects.all().order_by("id")
    serializer_class = SupplierSerializer
    permission_classes = [IsStaffOrReadOnly]

    def get_queryset(self):
        qs = super().get_queryset()
        q = self.request.query_params.get("q")
        if q:
            return qs.filter(name__icontains=q)
        return qs


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all().order_by("-created_at")
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]  # require login to view/create orders

    def perform_create(self, serializer):
        # optional: wrap in transaction to keep stock consistent
        with transaction.atomic():
            order = serializer.save()
            # decrement product stock (basic example)
            prod = order.product
            prod.stock = max(0, prod.stock - order.quantity)
            prod.save()


# ------------------------
# Small health / test endpoint
# ------------------------
@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    return Response({"status": "ok", "service": "inventory-backend"})


# ------------------------
# Optional helper: return current user (simple)
# ------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def whoami(request):
    return Response({"username": request.user.username, "id": request.user.id})
