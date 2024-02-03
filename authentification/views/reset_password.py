from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import (
    smart_str,
    smart_bytes,
    DjangoUnicodeDecodeError,
)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from authentification.models import CustomUser, SmsHistory
from authentification.serializers.serializers import PasswordResetSerializer, UserProfilesSerializer, \
    PasswordResetCompleteSerializer
from authentification.service.generate_code import generate_sms_code
from authentification.service.utils import Util
from main_services.expected_fields import check_required_key
from main_services.main import UserRenderers, get_token_for_user
from main_services.responses import (
    bad_request_response,
    success_response,
    user_not_found_response
)
from main_services.swaggers import swagger_extend_schema, swagger_schema


@swagger_extend_schema(fields={"email"}, description="Reset Password")
@swagger_schema(serializer=PasswordResetSerializer)
class RequestPasswordRestEmail(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        valid_fields = {"email"}
        unexpected_fields = check_required_key(request, valid_fields)
        if unexpected_fields:
            return bad_request_response(f"Unexpected fields: {', '.join(unexpected_fields)}")

        serializer = self.get_serializer(data=request.data)
        email = request.data.get("email")

        if self.user_exists(email):
            user = CustomUser.objects.get(email=email)
            self.send_reset_password_email(user)
            return success_response("Reset password link sent to your email")

        return user_not_found_response("User not found")

    def get_serializer(self, *args, **kwargs):
        return self.serializer_class(*args, **kwargs)

    def user_exists(self, email):
        return CustomUser.objects.filter(email=email).exists()

    def send_reset_password_email(self, user):
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        absurl = f"https://hrms.prounity.uz/reset-password/{uidb64}/{token}"
        email_body = f"Hi \n Use link below to reset password \n link: {absurl}"
        email_data = {
            "email_body": email_body,
            "to_email": user.email,
            "email_subject": "Reset your password",
        }
        Util.send(email_data)


@swagger_extend_schema(fields={}, description="Password Token Check")
@swagger_schema(serializer=UserProfilesSerializer)
class PasswordTokenCheckView(generics.GenericAPIView):
    serializer_class = UserProfilesSerializer
    def get(self, request, uidb64, token):
        try:
            user = self.get_user_from_uidb64(uidb64)
            self.validate_token(user, token)

            return success_response(uidb64, token)

        except DjangoUnicodeDecodeError:
            return self.invalid_token_response()

    def get_user_from_uidb64(self, uidb64):
        id = smart_str(urlsafe_base64_decode(uidb64))
        return CustomUser.objects.get(id=id)

    def validate_token(self, user, token):
        if not PasswordResetTokenGenerator().check_token(user, token):
            self.invalid_token_response()

    def success_response(self, uidb64, token):
        return success_response({"uidb64": uidb64, "token": token})

    def invalid_token_response(self):
        return Response(
            {"error": "Token is not valid, Please request a new one"},
            status=status.HTTP_401_UNAUTHORIZED,
        )


@swagger_extend_schema(fields={'password', 'uidb64', 'token'}, description="Set new password")
@swagger_schema(serializer=PasswordResetCompleteSerializer)
class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = PasswordResetCompleteSerializer

    def patch(self, request):
        valid_fields = {'password', 'uidb64', 'token'}
        unexpected_fields = check_required_key(request, valid_fields)
        if unexpected_fields:
            return bad_request_response(f"Unexpected fields: {', '.join(unexpected_fields)}")

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        return success_response()

    def get_serializer(self, *args, **kwargs):
        return self.serializer_class(*args, **kwargs)



class ResendCodeByEmailView(APIView):
    render_classes = [UserRenderers]
    perrmisson_class = [IsAuthenticated]

    def post(self, request):
        if request.user.is_staff:
            return self.error_response("You already verified...")

        sms_code = generate_sms_code()
        self.send_verification_email(request.user, sms_code)
        self.save_sms_code(request.user, sms_code)
        token = get_token_for_user(request.user)

        return success_response(sms_code, token)

    def send_verification_email(self, user, sms_code):
        email_body = f"Hi {user.email} \nThis is your verification code to register your account: {sms_code} \nThanks..."
        email_data = {
            "email_body": email_body,
            "to_email": user.email,
            "email_subject": "Verify your email",
        }
        Util.send(email_data)

    def save_sms_code(self, user, sms_code):
        SmsHistory.objects.create(code=sms_code, user=user)