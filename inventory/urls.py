# inventory/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    ProductViewSet,
    SupplierViewSet,
    OrderViewSet,
    ProfileView,
    ChangePasswordView,
    UsersListView,
    health_check,
    whoami,
)

router = DefaultRouter()
router.register(r"products", ProductViewSet)
router.register(r"suppliers", SupplierViewSet)
router.register(r"orders", OrderViewSet)

urlpatterns = [
    path("auth/register/", RegisterView.as_view()),
    path("auth/login/", LoginView.as_view()),
    path("auth/logout/", LogoutView.as_view()),
    path("auth/profile/", ProfileView.as_view()),
    path("auth/change-password/", ChangePasswordView.as_view()),
    path("users/", UsersListView.as_view()),
    path("whoami/", whoami),
    path("health/", health_check),
    path("", include(router.urls)),
]
