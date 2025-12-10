# inventory/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"products", views.ProductViewSet)
router.register(r"suppliers", views.SupplierViewSet)
router.register(r"orders", views.OrderViewSet)

urlpatterns = [
    path("auth/register/", views.RegisterView.as_view()),
    path("auth/login/", views.LoginView.as_view()),
    path("auth/logout/", views.LogoutView.as_view()),
    path("auth/profile/", views.ProfileView.as_view()),
    path("auth/change-password/", views.ChangePasswordView.as_view()),
    path("users/", views.UsersListView.as_view()),
    path("whoami/", views.whoami),
    path("health/", views.health_check),
    path("", include(router.urls)),
]
