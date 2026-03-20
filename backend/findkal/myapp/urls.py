from django.urls import path
from .views import (
    PasswordResetRequestView,
    PasswordResetResendView,
    PasswordResetVerifyCodeView,
    PasswordResetConfirmView,
)

urlpatterns = [
    path("password-reset/request/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password-reset/resend/", PasswordResetResendView.as_view(), name="password-reset-resend"),
    path("password-reset/verify-code/", PasswordResetVerifyCodeView.as_view(), name="password-reset-verify-code"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]
