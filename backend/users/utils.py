from django.conf import settings
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives, BadHeaderError
from django.contrib.auth import get_user_model

from .tokens import accountValidationToken

from rest_framework_simplejwt.tokens import RefreshToken

from smtplib import SMTPException
import socket

def custom_send_mail(subject, recipients, html_content):
    email = EmailMultiAlternatives(subject=subject, from_email=settings.EMAIL_HOST_USER, to=recipients)
    email.attach_alternative(html_content, 'text/html')
    try:
        email.send()
        print("Email Sent Sucessfully to {}".format(recipients))
        return True
    except BadHeaderError as b:
        print("Invalid Header Found while sending Mail BH: {}".format(b) )
        return False
    except SMTPException as se:
        print("Exception while sending Mail SE:{}".format(se))
        return False
    except TimeoutError as t:
        print("Exception while sending Mail t:{}".format(t))
        return False
    except socket.gaierror as ge:
        print("Exce ption while sending Mail ge:{}".format(ge))
        return False

def send_mail_to_user(user, current_site):
    print("sending mail to the User:", user)
    recipients = [user.email]
    subject = settings.EMAIL_ACCOUNT_ACTIVATION_SUBJECT
    html_content = render_to_string('activate_mail.html', {
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'user': user,
        'domain': current_site.domain,
        'token': accountValidationToken.make_token(user)
    })
    return custom_send_mail(subject, recipients, html_content)


def activate_account(uidb64, token):
    user_model = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        print("Inside activate_account | uid: {}".format(uid))
        user = user_model.objects.get(pk=uid)
        print("activate_account | User: {}".format(user))
    except user_model.DoesNotExist as ue:
        user = None
    if(
        user is not None and accountValidationToken.check_token(user, token)
    ):
        user.is_active = True
        user.is_email_verified = True
        user.save()
        return True
    else:
        return False


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }