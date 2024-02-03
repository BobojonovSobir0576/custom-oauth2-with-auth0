from django.urls import path
from authentification.views.reset_password import (
    RequestPasswordRestEmail,
    ResendCodeByEmailView,
    SetNewPasswordView,
    PasswordTokenCheckView,
)
from authentification.views.authentification import (
    LoginView,
    RegisterViews,
    VerificationSmsCodeView,
    LogoutView,
)
from authentification.views.profile import ProfileViews


urlpatterns = [
    path("login", LoginView.as_view(), name="login"),
    path("register", RegisterViews.as_view(), name="register"),
    path("profile", ProfileViews.as_view(), name="profile"),
    path("logout", LogoutView.as_view(), name="logout"),
    path("request-reset-password", RequestPasswordRestEmail.as_view(), name="request-reset-password"),
    path("reset-password", PasswordTokenCheckView.as_view(), name="reset-password"),
    path("resend-code", ResendCodeByEmailView.as_view(), name="resend-code"),
    path("set-new-password", SetNewPasswordView.as_view(), name="set-new-password"),
    path("verify-sms-code", VerificationSmsCodeView.as_view(), name="verify-sms-code"),
]
