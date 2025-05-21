from django.urls import path
from .views import LoginView, dashboard_view, PasswordResetRequestView, PasswordResetConfirmView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('reset/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
