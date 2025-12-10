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

ADMIN_SIGNUP_KEY = os.environ.get("ADMIN_SIGNUP_KEY")  # must be set on Render


def _get_role(user: User) -> str:
    if user.is_superuser:
        return "Admin"
    if user.is_staff:
        return "Staff"
    return "User"


# -------- AUTH VIEWS --------

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")
        # from frontend
        requested_role = request.data.get("role", "User")
        admin_key = request.data.get("admin_key", "")

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

        # basic password validation
        try:
            validate_password(password)
        except ValidationError as e:
            return Response(
                {"error": " ".join(e.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )

        # ---- ADMIN / STAFF HANDLING ----
        # We only grant admin if:
        #   - frontend asked for Admin AND
        #   - admin_key matches ADMIN_SIGNUP_KEY
        #
        # If ADMIN_SIGNUP_KEY is NOT set at all (e.g. in dev), then
        # any admin request will be accepted (for your convenience).
        if requested_role == "Admin":
            if ADMIN_SIGNUP_KEY:
                if admin_key and admin_key == ADMIN_SIGNUP_KEY:
                    user.is_staff = True
                    user.is_superuser = True
                    user.save()
                else:
                    # Wrong key → stay as normal user
                    # (but we still create the account)
                    pass
            else:
                # Dev fallback: no env var configured, so allow Admin
                user.is_staff = True
                user.is_superuser = True
                user.save()

        # (You could add a "Staff" path similarly if you want)

        token, _ = Token.objects.get_or_create(user=user)
        role = _get_role(user)

        return Response(
            {
                "message": "User registered successfully",
                "token": token.key,
                "username": user.username,
                "role": role,
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
        role = _get_role(user)

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
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Delete the current token
        try:
            request.auth.delete()
        except Exception:
            pass
        return Response({"message": "Logged out"}, status=status.HTTP_200_OK)


class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response(
            {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        )

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
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not user.check_password(old_password):
            return Response(
                {"error": "Old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            return Response(
                {"error": " ".join(e.messages)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(new_password)
        user.save()
        return Response({"message": "Password changed successfully"})


class UsersListView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        users = User.objects.all().order_by("-date_joined")
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


# -------- API HEALTH & WHOAMI --------

@api_view(["GET"])
@permission_classes([permissions.AllowAny])
def health_check(request):
    return Response({"status": "ok"})


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def whoami(request):
    user = request.user
    return Response(
        {"username": user.username, "email": user.email, "role": _get_role(user)}
    )


# -------- VIEWSETS FOR MODELS --------

class IsStaffOrAdmin(permissions.BasePermission):
    """
    Allow safe (GET/HEAD) for any authenticated user, but write only for staff/admin.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.is_staff or request.user.is_superuser


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by("name")
    serializer_class = ProductSerializer
    permission_classes = [IsStaffOrAdmin]


class SupplierViewSet(viewsets.ModelViewSet):
    queryset = Supplier.objects.all().order_by("name")
    serializer_class = SupplierSerializer
    permission_classes = [IsStaffOrAdmin]


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all().order_by("-created_at")
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAuthenticated]
