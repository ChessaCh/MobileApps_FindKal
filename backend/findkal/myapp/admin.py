from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, EmailVerification, PasswordResetToken, PendingEmailVerification


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ("email", "name", "role", "provinsi", "is_email_verified", "is_active", "is_staff")
    list_filter = ("role", "is_email_verified", "is_active", "is_staff")
    search_fields = ("email", "name", "nomortelepon")
    ordering = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal Info", {"fields": ("name", "nomortelepon")}),
        ("Role", {"fields": ("role",)}),
        ("Address", {"fields": ("negara", "provinsi", "kota", "kecamatan", "kelurahan")}),
        ("Verification", {"fields": ("is_email_verified",)}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "name", "password1", "password2", "role"),
        }),
    )


@admin.register(EmailVerification)
class EmailVerificationAdmin(admin.ModelAdmin):
    list_display = ("user", "code", "purpose", "created_at", "expires_at", "is_used")
    list_filter = ("purpose", "is_used")
    search_fields = ("user__email", "user__name")
    readonly_fields = ("code", "created_at", "expires_at")


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ("user", "token", "created_at", "expires_at", "is_used")
    list_filter = ("is_used",)
    search_fields = ("user__email", "user__name")
    readonly_fields = ("token", "created_at", "expires_at")


@admin.register(PendingEmailVerification)
class PendingEmailVerificationAdmin(admin.ModelAdmin):
    list_display = ("email", "code", "created_at", "expires_at", "is_used")
    list_filter = ("is_used",)
    search_fields = ("email",)
    readonly_fields = ("code", "created_at", "expires_at")
