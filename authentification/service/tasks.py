from celery import shared_task
from django.core.mail import EmailMessage


@shared_task
def send_verification_email_task(email_subject, email_body, to_email):
    email = EmailMessage(
        subject=email_subject,
        body=email_body,
        to=[to_email])
    email.send()