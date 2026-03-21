from django.urls import path
from .views import (
    RegisterSendVerificationView,
    RegisterVerifyEmailView,
    RegisterView,
    PasswordResetRequestView,
    PasswordResetResendView,
    PasswordResetVerifyCodeView,
    PasswordResetConfirmView,
)

urlpatterns = [
    path("register/send-verification/", RegisterSendVerificationView.as_view(), name="register-send-verification"),
    path("register/verify-email/", RegisterVerifyEmailView.as_view(), name="register-verify-email"),
    path("register/", RegisterView.as_view(), name="register"),
    path("password-reset/request/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password-reset/resend/", PasswordResetResendView.as_view(), name="password-reset-resend"),
    path("password-reset/verify-code/", PasswordResetVerifyCodeView.as_view(), name="password-reset-verify-code"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]
