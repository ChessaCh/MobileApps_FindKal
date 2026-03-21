import resend
from django.conf import settings
from django.db.models import Q
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .models import User, EmailVerification, PasswordResetToken, PendingEmailVerification


def _send_otp_email(email, code):
    resend.api_key = settings.RESEND_API_KEY
    resend.Emails.send({
        "from": "FindKal <onboarding@resend.dev>",
        "to": [email],
        "subject": "Kode Verifikasi FindKal",
        "text": f"Kode verifikasi kamu adalah: {code}\nKode ini berlaku selama 10 menit.",
    })


# ---------------------------------------------------------------------------
# Registration — Send email verification OTP
# POST /api/register/send-verification/
# Body: { "email": "..." }
# ---------------------------------------------------------------------------
class RegisterSendVerificationView(APIView):
    def post(self, request):
        email = request.data.get("email", "").strip()
        if not email:
            return Response({"error": "Email wajib diisi."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email__iexact=email, is_email_verified=True).exists():
            return Response(
                {"error": "Email sudah digunakan oleh akun lain."},
                status=status.HTTP_409_CONFLICT,
            )

        # Invalidate any previous unused OTPs for this email
        PendingEmailVerification.objects.filter(
            email__iexact=email, is_used=False
        ).update(is_used=True)

        code = EmailVerification.generate_code()
        PendingEmailVerification.objects.create(email=email, code=code)
        _send_otp_email(email, code)

        return Response({"detail": "Kode verifikasi dikirim ke email kamu."}, status=status.HTTP_200_OK)


# ---------------------------------------------------------------------------
# Registration — Verify email OTP
# POST /api/register/verify-email/
# Body: { "email": "...", "code": "123456" }
# ---------------------------------------------------------------------------
class RegisterVerifyEmailView(APIView):
    def post(self, request):
        email = request.data.get("email", "").strip()
        code = request.data.get("code", "").strip()

        if not email or not code:
            return Response({"error": "Email dan kode wajib diisi."}, status=status.HTTP_400_BAD_REQUEST)

        pending = (
            PendingEmailVerification.objects.filter(email__iexact=email, is_used=False)
            .order_by("-created_at")
            .first()
        )

        if not pending or not pending.verify(code):
            return Response(
                {"error": "Kode tidak valid atau sudah kedaluwarsa."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({"detail": "Email berhasil diverifikasi."}, status=status.HTTP_200_OK)


# ---------------------------------------------------------------------------
# Registration — Create account
# POST /api/register/
# Body: { name, username, password, email, negara, provinsi, kota, kecamatan, kelurahan }
# ---------------------------------------------------------------------------
class RegisterView(APIView):
    def post(self, request):
        name     = request.data.get("name", "").strip()
        username = request.data.get("username", "").strip()
        password = request.data.get("password", "")
        email    = request.data.get("email", "").strip()
        negara   = request.data.get("negara", "").strip()
        provinsi = request.data.get("provinsi", "").strip()
        kota     = request.data.get("kota", "").strip()
        kecamatan = request.data.get("kecamatan", "").strip()
        kelurahan = request.data.get("kelurahan", "").strip()

        if not all([name, username, password, email, provinsi, kota, kecamatan, kelurahan]):
            return Response(
                {"error": "Semua field wajib diisi."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Confirm email was OTP-verified
        if not PendingEmailVerification.objects.filter(
            email__iexact=email, is_verified=True
        ).exists():
            return Response(
                {"error": "Email belum diverifikasi. Silakan verifikasi email terlebih dahulu."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check email uniqueness
        if User.objects.filter(email__iexact=email).exists():
            return Response(
                {"error": "Email sudah digunakan oleh akun lain."},
                status=status.HTTP_409_CONFLICT,
            )

        # Check username uniqueness
        if User.objects.filter(username__iexact=username).exists():
            return Response(
                {"error": "Username sudah digunakan. Coba username lain."},
                status=status.HTTP_409_CONFLICT,
            )

        # Validate password strength
        try:
            validate_password(password)
        except ValidationError as e:
            return Response({"error": list(e.messages)}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            email=email,
            name=name,
            password=password,
            username=username,
            negara=negara or "Indonesia",
            provinsi=provinsi,
            kota=kota,
            kecamatan=kecamatan,
            kelurahan=kelurahan,
            is_email_verified=True,
        )

        # Clean up the pending verification record
        PendingEmailVerification.objects.filter(email__iexact=email).delete()

        return Response(
            {"detail": f"Akun {user.username} berhasil dibuat."},
            status=status.HTTP_201_CREATED,
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
