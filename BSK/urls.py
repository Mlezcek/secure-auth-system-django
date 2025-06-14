from django.urls import path

from .mfa import MFAVerifyView, MFASetupView
from .views import LoginView, dashboard_view, PasswordResetRequestView, PasswordResetConfirmView, BlockedUsersAdminView, \
    BlockedIPsAdminView, logout_view, toggle_mfa, remove_trusted_device, verify_backup_code_view, backup_codes_view, \
    download_backup_codes, generate_backup_codes_ajax

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('admin/blocked_users/', BlockedUsersAdminView.as_view(), name='blocked_users'),
    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('reset/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('admin/blocked_ips/', BlockedIPsAdminView.as_view(), name='blocked_ips'),
    path('mfa/setup/', MFASetupView.as_view(), name='mfa_setup'),
    path('mfa/verify/', MFAVerifyView.as_view(), name='mfa_verify'),

path('logout/', logout_view, name='logout'),
path('mfa/toggle/', toggle_mfa, name='toggle_mfa'),
path('trusted/remove/<str:device_id>/', remove_trusted_device, name='remove_trusted_device'),

path('mfa/verify_backup_code/', verify_backup_code_view, name='verify_backup_code'),

path('dashboard/backup_codes/', backup_codes_view, name='backup_codes'),
path('dashboard/backup_codes/generate/', generate_backup_codes_ajax, name='generate_backup_codes_ajax'),



]
