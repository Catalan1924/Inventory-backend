# inventory/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"products", views.ProductViewSet, basename="product")
router.register(r"suppliers", views.SupplierViewSet, basename="supplier")
router.register(r"orders", views.OrderViewSet, basename="order")

urlpatterns = [
    path("auth/register/", views.RegisterView.as_view(), name="register"),
    path("auth/login/", views.LoginView.as_view(), name="login"),
    path("auth/logout/", views.LogoutView.as_view(), name="logout"),
    path("auth/profile/", views.ProfileView.as_view(), name="profile"),
    path("auth/change-password/", views.ChangePasswordView.as_view(), name="change-password"),
    path("users/", views.UsersListView.as_view(), name="users"),
    path("whoami/", views.whoami, name="whoami"),
    path("health/", views.health_check, name="health"),
    path("", include(router.urls)),
]
