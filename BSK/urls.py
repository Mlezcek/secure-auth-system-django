from django.urls import path

from .mfa import MFASetupView, MFAVerifyView
from .views import LoginView, dashboard_view, PasswordResetRequestView, PasswordResetConfirmView, BlockedUsersAdminView, \
    BlockedIPsAdminView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('admin/blocked_users/', BlockedUsersAdminView.as_view(), name='blocked_users'),
    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('reset/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    path('mfa/setup/', MFASetupView.as_view(), name='mfa_setup'),
    path('mfa/verify/', MFAVerifyView.as_view(), name='mfa_verify'),

    path('admin/blocked_ips/', BlockedIPsAdminView.as_view(), name='blocked_ips'),
]
