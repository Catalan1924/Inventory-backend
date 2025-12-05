# views.py (only the relevant parts shown)
import os
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token

ADMIN_SIGNUP_KEY = os.environ.get("ADMIN_SIGNUP_KEY")

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        email = request.data.get("email")
        password = request.data.get("password")
        admin_key = request.data.get("admin_key", None)

        if not username or not password:
            return Response({"error": "Username and password are required"},
                             status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"},
                             status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, email=email, password=password)

        # Only grant admin privileges if admin_key matches server-side secret
        if admin_key and ADMIN_SIGNUP_KEY and admin_key == ADMIN_SIGNUP_KEY:
            user.is_staff = True
            user.is_superuser = True
            user.save()

        token, _ = Token.objects.get_or_create(user=user)
        role = "Admin" if user.is_superuser else "Staff" if user.is_staff else "User"

        return Response({"message": "User registered successfully", "token": token.key, "username": user.username, "role": role}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password)
        if user is None:
            return Response({"error": "Invalid username or password"}, status=status.HTTP_401_UNAUTHORIZED)

        token, _ = Token.objects.get_or_create(user=user)
        role = "Admin" if user.is_superuser else "Staff" if user.is_staff else "User"

        return Response({"message": "Login successful", "token": token.key, "username": user.username, "role": role}, status=status.HTTP_200_OK)
