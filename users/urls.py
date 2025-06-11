from django.urls import path
from .views import (
    RegisterView, LoginView, Verify2FAView, LogoutView,
    RedirectToProfile, ProfilePageView, Resend2FACodeView, bind_telegram, Toggle2FAView, unlink_telegram
)
urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-2fa/', Verify2FAView.as_view(), name='verify-2fa'),
    path('resend-2fa/', Resend2FACodeView.as_view(), name='resend-2fa'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('redirect/', RedirectToProfile.as_view(), name='redirect-profile'),
    path('profile/<int:pk>/', ProfilePageView.as_view(), name='profile'),
    path('bind-telegram/', bind_telegram, name='bind-telegram'),
    path('toggle-2fa/', Toggle2FAView.as_view(), name='toggle-2fa'),
    path('unlink-telegram/', unlink_telegram, name='unlink-telegram'),
]
