from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from rest_framework import generics, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from authentification.models import SmsHistory
from authentification.serializers.serializers import RegisterSerializer, LoginSerializer, LogoutSerializer
from authentification.service.generate_code import generate_sms_code
from authentification.service.utils import Util
from main_services.expected_fields import check_required_key
from main_services.main import get_token_for_user, UserRenderers
from main_services.responses import (
    bad_request_response,
    success_response,
    success_created_response, success_deleted_response,
)
from main_services.swaggers import swagger_schema, swagger_extend_schema
from django.core.cache import cache

@swagger_extend_schema(fields={"username", "email", "role", "password", "confirm_password"}, description="Register")
@swagger_schema(serializer=RegisterSerializer)
class RegisterViews(APIView):
    def post(self, request):
        valid_fields = {"username", "email", "role", "password", "confirm_password"}
        unexpected_fields = check_required_key(request, valid_fields)
        if unexpected_fields:
            return bad_request_response(f"Unexpected fields: {', '.join(unexpected_fields)}")

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user_instance = self.create_user(serializer)
            sms_code = generate_sms_code()
            self.send_verification_email(user_instance, sms_code)
            self.save_sms_code(user_instance, sms_code)
            token = self.generate_user_token(user_instance)

            response_data = {
                "msg": "Verification code sent to your email, check it",
                "token": token,
            }

            return success_created_response(response_data)

        return bad_request_response(serializer.errors)

    def get_serializer(self, *args, **kwargs):
        return RegisterSerializer(*args, **kwargs)

    def create_user(self, serializer):
        return serializer.save()

    def send_verification_email(self, user_instance, sms_code):
        email_body = f"Hi {user_instance.username},\nThis is your verification code to register your account: {sms_code}\nThanks..."
        email_data = {
            "email_body": email_body,
            "to_email": user_instance.email,
            "email_subject": "Verify your email",
        }
        Util.send(email_data)

    def save_sms_code(self, user_instance, sms_code):
        SmsHistory.objects.create(code=sms_code, user=user_instance)
        cache.set(f"otp_{user_instance.id}", sms_code, timeout=300)

    def verify_otp(user_id, sms_code):
        cached_code = cache.get(f"otp_{user_id}")
        return cached_code == sms_code

    def generate_user_token(self, user_instance):
        return get_token_for_user(user_instance)


@swagger_extend_schema(fields={"code"}, description="Verification sms code")
class VerificationSmsCodeView(APIView):
    render_classes = [UserRenderers]
    perrmisson_class = [IsAuthenticated]

    def put(self, request):
        valid_fields = {"code"}
        unexpected_fields = check_required_key(request, valid_fields)
        if unexpected_fields:
            return bad_request_response(f"Unexpected fields: {', '.join(unexpected_fields)}")

        if "code" not in request.data:
            return bad_request_response("Code key is missing in the request data")

        sms_code = request.data["code"]
        user = request.user

        try:
            check_code = self.get_latest_sms_code(user)

            if check_code and check_code.code == int(sms_code):
                self.activate_user(check_code.user)
                token = get_token_for_user(check_code.user)
                return success_response(token)

            return bad_request_response("The verification code was entered incorrectly")

        except ObjectDoesNotExist:
            return bad_request_response("Object does not exist")

    def get_latest_sms_code(self, user):
        return SmsHistory.objects.select_related("user").filter(Q(user=user)).last()

    def activate_user(self, user):
        user.is_staff = True
        user.save()


@swagger_extend_schema(fields={"email", "password"}, description="Login")
@swagger_schema(serializer=LoginSerializer)
class LoginView(APIView):
    def post(self, request):
        valid_fields = {"email", "password"}
        unexpected_fields = check_required_key(request, valid_fields)
        if unexpected_fields:
            return bad_request_response(f"Unexpected fields: {', '.join(unexpected_fields)}")

        serializer = LoginSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        token = get_token_for_user(user)

        return success_response(token)


@swagger_extend_schema(fields={"refresh_token"}, description="Log Out")
@swagger_schema(serializer=LoginSerializer)
class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return success_deleted_response("Successfully logged out.")
