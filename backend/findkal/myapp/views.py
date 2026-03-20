from django.db.models import Q
from django.core.mail import send_mail
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import User, EmailVerification, PasswordResetToken


def _send_otp_email(email, code):
    """
    Placeholder for email delivery.
    Replace with your email provider config in settings.py (EMAIL_BACKEND, etc).
    """
    send_mail(
        subject="Kode Verifikasi FindKal",
        message=f"Kode verifikasi kamu adalah: {code}\nKode ini berlaku selama 10 menit.",
        from_email=None,  # uses DEFAULT_FROM_EMAIL from settings
        recipient_list=[email],
        fail_silently=True,
    )


# ---------------------------------------------------------------------------
# Step 1 — Find account
# POST /api/password-reset/request/
# Body: { "identifier": "<email_or_name>" }
# ---------------------------------------------------------------------------
class PasswordResetRequestView(APIView):
    def post(self, request):
        identifier = request.data.get("identifier", "").strip()
        if not identifier:
            return Response(
                {"error": "Masukkan username atau email."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Look up by email OR name (case-insensitive)
        user = User.objects.filter(
            Q(email__iexact=identifier) | Q(name__iexact=identifier)
        ).first()

        if not user:
            return Response(
                {"error": "Akun tidak ditemukan."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Invalidate any previous unused reset OTPs for this user
        EmailVerification.objects.filter(
            user=user,
            purpose=EmailVerification.Purpose.RESET_PASSWORD,
            is_used=False,
        ).update(is_used=True)

        code = EmailVerification.generate_code()
        EmailVerification.objects.create(
            user=user,
            code=code,
            purpose=EmailVerification.Purpose.RESET_PASSWORD,
        )
        _send_otp_email(user.email, code)

        return Response(
            {"email": user.email},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# Step 1b — Resend code
# POST /api/password-reset/resend/
# Body: { "email": "..." }
# ---------------------------------------------------------------------------
class PasswordResetResendView(APIView):
    def post(self, request):
        email = request.data.get("email", "").strip()
        user = User.objects.filter(email__iexact=email).first()
        if not user:
            return Response({"error": "Akun tidak ditemukan."}, status=status.HTTP_404_NOT_FOUND)

        # Invalidate old codes
        EmailVerification.objects.filter(
            user=user,
            purpose=EmailVerification.Purpose.RESET_PASSWORD,
            is_used=False,
        ).update(is_used=True)

        code = EmailVerification.generate_code()
        EmailVerification.objects.create(
            user=user,
            code=code,
            purpose=EmailVerification.Purpose.RESET_PASSWORD,
        )
        _send_otp_email(user.email, code)

        return Response(
            {"detail": "Kode baru sudah dikirim ulang melalui email. Segera cek inbox kamu."},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# Step 2 — Verify OTP code
# POST /api/password-reset/verify-code/
# Body: { "email": "...", "code": "123456" }
# Returns: { "reset_token": "<uuid>" }
# ---------------------------------------------------------------------------
class PasswordResetVerifyCodeView(APIView):
    def post(self, request):
        email = request.data.get("email", "").strip()
        code = request.data.get("code", "").strip()

        if not email or not code:
            return Response(
                {"error": "Email dan kode wajib diisi."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.filter(email__iexact=email).first()
        if not user:
            return Response({"error": "Akun tidak ditemukan."}, status=status.HTTP_404_NOT_FOUND)

        # Find the most recent unused reset OTP
        otp = (
            EmailVerification.objects.filter(
                user=user,
                purpose=EmailVerification.Purpose.RESET_PASSWORD,
                is_used=False,
            )
            .order_by("-created_at")
            .first()
        )

        if not otp or not otp.verify(code):
            return Response(
                {"error": "Kode tidak valid atau sudah kedaluwarsa."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Issue a short-lived reset token
        reset_token = PasswordResetToken.objects.create(user=user)

        return Response(
            {"reset_token": str(reset_token.token)},
            status=status.HTTP_200_OK,
        )


# ---------------------------------------------------------------------------
# Step 3 — Set new password
# POST /api/password-reset/confirm/
# Body: { "reset_token": "<uuid>", "new_password": "..." }
# ---------------------------------------------------------------------------
class PasswordResetConfirmView(APIView):
    def post(self, request):
        token_value = request.data.get("reset_token", "").strip()
        new_password = request.data.get("new_password", "")

        if not token_value or not new_password:
            return Response(
                {"error": "Token dan kata sandi baru wajib diisi."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            reset_token = PasswordResetToken.objects.select_related("user").get(
                token=token_value
            )
        except (PasswordResetToken.DoesNotExist, ValueError):
            return Response({"error": "Token tidak valid."}, status=status.HTTP_400_BAD_REQUEST)

        if not reset_token.is_valid():
            return Response(
                {"error": "Token sudah kedaluwarsa. Ulangi proses dari awal."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = reset_token.user
        try:
            validate_password(new_password, user=user)
        except ValidationError as e:
            return Response({"error": list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save(update_fields=["password"])

        reset_token.is_used = True
        reset_token.save(update_fields=["is_used"])

        return Response(
            {"detail": "Kata sandi berhasil diubah."},
            status=status.HTTP_200_OK,
        )
