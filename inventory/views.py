# inventory/views.py
import os

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from rest_framework import status, permissions, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes

from .models import Product, Supplier, Order
from .serializers import (
    ProductSerializer,
    SupplierSerializer,
    OrderSerializer,
    UserSerializer,
)

User = get_user_model()

ADMIN_SIGNUP_KEY = os.environ.get("ADMIN_SIGNUP_KEY")

# -------------------------
# AUTH VIEWS
# -------------------------


class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")
        admin_key = request.data.get("admin_key", None)
        requested_role = request.data.get("role", "User")

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

        # Create basic user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
        )

        # Decide role
        # Default = normal user
        final_role = "User"

        # If client requested Admin AND correct admin_key matches ENV, upgrade to admin
        if requested_role == "Admin":
            if ADMIN_SIGNUP_KEY and admin_key == ADMIN_SIGNUP_KEY:
                user.is_staff = True
                user.is_superuser = True
                user.save()
                final_role = "Admin"
            else:
                # Admin key wrong or missing -> keep as normal user
                # (Frontend will show a warning message already)
                final_role = "User"
        else:
            # You could optionally support "Staff" here if you want
            final_role = "User"

        token, _ = Token.objects.get_or_create(user=user)
        role = "Admin" if user.is_superuser else "Staff" if user.is_staff else "User"

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
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Delete current token - simple token-based logout
        Token.objects.filter(user=request.user).delete()
        return Response({"message": "Logged out"}, status=status.HTTP_200_OK)


class ProfileView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def put(self, request):
        user = request.user
        serializer = UserSerializer(
            user, data=request.data, partial=True
        )  # allow partial updates
        if serializer.is_valid():
            # Only allow updating non-sensitive fields
            for field in ["email", "first_name", "last_name"]:
                if field in serializer.validated_data:
                    setattr(user, field, serializer.validated_data[field])
            user.save()
            return Response({"message": "Profile updated"})
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not old_password or not new_password:
            return Response(
                {"error": "Old and new password are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not request.user.check_password(old_password):
            return Response(
                {"error": "Old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            validate_password(new_password, request.user)
        except ValidationError as e:
            return Response(
                {"error": list(e.messages)}, status=status.HTTP_400_BAD_REQUEST
            )

        request.user.set_password(new_password)
        request.user.save()
        # Optionally rotate token
        Token.objects.filter(user=request.user).delete()
        Token.objects.create(user=request.user)

        return Response({"message": "Password changed successfully"})


class UsersListView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        users = User.objects.all().order_by("date_joined")
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)


@api_view(["GET"])
@permission_classes([permissions.AllowAny])
def health_check(request):
    return Response({"status": "ok"})


@api_view(["GET"])
@permission_classes([permissions.IsAuthenticated])
def whoami(request):
    user = request.user
    role = "Admin" if user.is_superuser else "Staff" if user.is_staff else "User"
    return Response(
        {
            "username": user.username,
            "email": user.email,
            "role": role,
        }
    )


# -------------------------
# VIEWSETS (API)
# -------------------------


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all().order_by("name")
    serializer_class = ProductSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]


class SupplierViewSet(viewsets.ModelViewSet):
    queryset = Supplier.objects.all().order_by("name")
    serializer_class = SupplierSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all().order_by("-created_at")
    serializer_class = OrderSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
