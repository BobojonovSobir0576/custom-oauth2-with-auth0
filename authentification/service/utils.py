from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth import tokens
from django.utils.encoding import smart_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings
from django.urls import reverse
from authentification.service.tasks import send_verification_email_task


class Util:
    @staticmethod
    def send(data):
        send_verification_email_task.delay(
            data['email_subject'],
            data['email_body'],
            data['to_email']
        )


class PasswordReset:
    @staticmethod
    def send_email(user, request):
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = tokens.PasswordResetTokenGenerator().make_token(user)

        doamin = get_current_site(request).domain

        path = reverse('password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token})
        redirect_url = settings.FRONTEND_URL + '/reset-password-complete'
        url = 'http://{}{}?redirect_url={}'.format(doamin, path, redirect_url)

        body = 'Hi! You can use the link below to reset your password on "Win corporation":\n{}'.format(url)
        data = {
            'email_subject': 'Reset your password',
            'email_body': body,
            'to_email': user.email
        }

        Util.send(data)