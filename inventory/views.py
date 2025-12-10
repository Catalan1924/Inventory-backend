# inventory/views.py

import os
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from rest_framework import status, permissions, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes

from .models import Product, Supplier, Order
from .serializers import (
    ProductSerializer,
    SupplierSerializer,
    OrderSerializer,
    UserSerializer,
)

# Use env var if set, otherwise a dev default (change this to your own secret!)
ADMIN_SIGNUP_KEY = os.environ.get("ADMIN_SIGNUP_KEY", "INVENTORY_ADMIN_DEV_KEY")


# ---------------- AUTH VIEWS ---------------- #

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")
        admin_key = request.data.get("admin_key", None)

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

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )

        admin_granted = False

        # Only grant admin privileges if admin_key matches the server-side secret
        if admin_key:
            if admin_key == ADMIN_SIGNUP_KEY:
                user.is_staff = True
                user.is_superuser = True
                user.save()
                admin_granted = True
            else:
                # We still create the account, but as a normal User
                admin_granted = False

        token, _ = Token.objects.get_or_create(user=user)
        role = "Admin" if user.is_superuser else "Staff" if user.is_staff else "User"

        return Response(
            {
                "message": "User registered successfully",
                "token": token.key,
                "username": user.username,
                "role": role,
                "admin_granted": admin_granted,
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)
        if user is None:
            return Response(
                {"error": "Invalid username or password"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        token, _ = Token.objects.get_or_create(user=user)
        role = "Admin" if user.is_superuser else "Staff" if user.is_staff else "User"

        return Response(
            {
                "message": "Login successful",
                "token": token.key,
                "username": user.username,
                "role": role,
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    """
    Simple token logout: deletes the auth token for the current user.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            # Delete the token used for this request
            request.auth.delete()
        except Exception:
            pass
        return Response({"message": "Logged out"}, status=status.HTTP_200_OK)


# ---------------- VIEWSETS ---------------- #

class IsAdminOrStaff(permissions.BasePermission):
    """
    Custom permission: only Admin or Staff can create/update/delete.
    Anyone authenticated can read.
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        return request.user and (request.user.is_staff or request.user.is_superuser)


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.select_related("supplier").all()
    serializer_class = ProductSerializer
    permission_classes = [IsAdminOrStaff]


class SupplierViewSet(viewsets.ModelViewSet):
    queryset = Supplier.objects.all()
    serializer_class = SupplierSerializer
    permission_classes = [IsAdminOrStaff]


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.select_related("product").all()
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]


# ---------------- PROFILE / USERS ---------------- #

class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        data = {
            "username": request.user.username,
            "email": request.user.email,
            "first_name": request.user.first_name,
            "last_name": request.user.last_name,
        }
        return Response(data)

    def put(self, request):
        user = request.user
        user.email = request.data.get("email", user.email)
        user.first_name = request.data.get("first_name", user.first_name)
        user.last_name = request.data.get("last_name", user.last_name)
        user.save()
        return Response({"message": "Profile updated"})


class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not old_password or not new_password:
            return Response(
                {"error": "old_password and new_password are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not request.user.check_password(old_password):
            return Response(
                {"error": "Old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password, user=request.user)
        except ValidationError as e:
            return Response(
                {"error": list(e.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.user.set_password(new_password)
        request.user.save()
        return Response({"message": "Password changed successfully"})


class UsersListView(APIView):
    """
    Admin-only: list all users.
    """
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        users = User.objects.all().order_by("-date_joined")
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


# ---------------- UTILITIES ---------------- #

@api_view(["GET"])
@permission_classes([permissions.AllowAny])
def health_check(request):
    return Response({"status": "ok"})


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def whoami(request):
    role = "Admin" if request.user.is_superuser else "Staff" if request.user.is_staff else "User"
    return Response(
        {
            "id": request.user.id,
            "username": request.user.username,
            "email": request.user.email,
            "role": role,
        }
    )
