from django.urls import path

from .mfa import MFAVerifyView, MFASetupView
from .views import LoginView, dashboard_view, PasswordResetRequestView, PasswordResetConfirmView, BlockedUsersAdminView, \
    BlockedIPsAdminView, logout_view, toggle_mfa, remove_trusted_device, verify_backup_code_view, backup_codes_view, \
    download_backup_codes, generate_backup_codes_ajax, admin_audit_log_view, admin_dashboard_view, \
    admin_user_action_view, admin_block_ip_view, admin_unblock_ip_view, ajax_search_users, ajax_search_ips, \
    ajax_search_logs, test_geoip, reset_mfa_view, RegisterView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('admin/blocked_users/', BlockedUsersAdminView.as_view(), name='blocked_users'),
    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('reset/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('admin/blocked_ips/', BlockedIPsAdminView.as_view(), name='blocked_ips'),
    path('mfa/setup/', MFASetupView.as_view(), name='mfa_setup'),
    path('mfa/verify/', MFAVerifyView.as_view(), name='mfa_verify'),

    path('mfa/reset/', reset_mfa_view, name='reset_mfa'),
    
    path('register/', RegisterView.as_view(), name='register'),
path('logout/', logout_view, name='logout'),
path('mfa/toggle/', toggle_mfa, name='toggle_mfa'),
path('trusted/remove/<str:device_id>/', remove_trusted_device, name='remove_trusted_device'),

path('mfa/verify_backup_code/', verify_backup_code_view, name='verify_backup_code'),

path('dashboard/backup_codes/', backup_codes_view, name='backup_codes'),
path('dashboard/backup_codes/generate/', generate_backup_codes_ajax, name='generate_backup_codes_ajax'),
path('admin/audit_logs/', admin_audit_log_view, name='admin_audit_logs'),
path('admin/panel/', admin_dashboard_view, name='admin_dashboard'),
path('admin/user_action/', admin_user_action_view, name='admin_user_action'),

path('admin/block_ip/', admin_block_ip_view, name='admin_block_ip'),
path('admin/unblock_ip/', admin_unblock_ip_view, name='admin_unblock_ip'),
path('admin/ajax/search_users/', ajax_search_users, name='ajax_search_users'),
path('admin/ajax/search_ips/', ajax_search_ips, name='ajax_search_ips'),
path('admin/ajax/search_logs/', ajax_search_logs, name='ajax_search_logs'),

path('test_geoip/', test_geoip),

    path('faceid_login/', FaceIDLoginView.as_view(), name='faceid_login'),
    path('faceid/setup/', FaceIDSetupView.as_view(), name='faceid_setup'),
]
