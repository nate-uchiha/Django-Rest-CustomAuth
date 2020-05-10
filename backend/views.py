from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import get_user_model
from django.contrib.auth import (
    login as django_login,
    logout as django_logout
)
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext_lazy as _
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_text
from django.conf import settings

from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.viewsets import ModelViewSet
from rest_framework.generics import GenericAPIView, RetrieveAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication

from .serializers import (
    LoginSerializer, TokenSerializer, UserRegisterSerializer, PasswordResetConfirmSerializer, 
    PasswordResetSerializer, UserSerializer
)
from .models import Profile
from .tokens import accountValidationToken
from .utils import (
    default_create_token, default_create_user, default_create_profile, send_activation_mail, send_password_reset_mail, reset_password
)

import logging

logger = logging.getLogger('backend')

# Create your views here.
class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    token_model = Token
    authentication_classes = (TokenAuthentication,)

    def process_login(self):
        django_login(self.request, self.user)

    def login(self):
        self.user = self.serializer.validated_data['user']
        self.token = default_create_token(self.token_model, self.user)
        self.process_login()

    def get_avatar_url(self, user):
        if user.profile.avatar:
            return user.profile.avatar.url
        else:
            return ""

    def get_user_group_names(self, user):
        groups = []
        for gn in user.groups.all():
            groups.append(gn.name)
        return groups

    def get_response(self):
        serializer_class = TokenSerializer
        serializer = serializer_class(instance=self.token,
                                          context={'request': self.request})
        logger.info("LoginView | get_response | serializer_data: {}".format(serializer.data))
        
        response = JsonResponse({
            'status': "success",
            'data': {
                'token': self.token.key,
                'user_id': self.user.id,
                'username': self.user.username,
                'email': self.user.email,
                'last_login': self.user.last_login, 
                'is_active': self.user.is_active,
                'avatar_url': self.get_avatar_url(self.user),
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'birth_date': self.user.profile.birth_date,
                'groups': self.get_user_group_names(self.user),
            }
        })
        #response = Response(serializer.data, status=status.HTTP_200_OK)
        return response

    def post(self, request, *args, **kwargs):
        self.request = request
        logger.info("LoginView | post | request: {}".format(self.request))
        self.serializer = self.get_serializer(data=self.request.data, context={'request': request})
        if self.serializer.is_valid(raise_exception=True):
            user = self.serializer.validated_data['user']
            if user is not None:
                if not user.is_active:
                    logger.info("LoginView | post | User is not active")
                    return Response({
                        'status': _('fail'),
                        'message': _("User account is disabled")
                    })
                else:
                    logger.info("LoginView | post | User :{}".format(user))
                    self.login()
                    return self.get_response() 
            else:
                return Response({
                    'status': _('fail'),
                    'message': _('Unable to log in with provided credentials.')
                })

class RegisterView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    user_model = get_user_model()
    profile_model = Profile

    def create_user(self):
        self.data = self.serializer.validated_data['data']
        logger.info("RegisterView | create_user | data: {}".format(self.data))
        self.user = default_create_user(self.user_model, self.data)
        self.profile = default_create_profile(self.profile_model, self.user, self.data)

    def post(self, request, *args, **kwargs):
        self.request = request
        logger.info("UserRegisterView | post | request: {}".format(self.request))
        self.serializer = self.get_serializer(data=self.request.data, context={'request': request})
        if self.serializer._validate_username(self.request.data):
            return Response({
                'status': "fail",
                "message": "User with this username already exists"
            })
        elif self.serializer._validate_email(self.request.data):
            return Response({
                'status': "fail",
                "message": "User with this email already exists"
            })
        elif self.serializer._validate_password(self.request.data):
            return Response({
                'status': "fail",
                "message": "Passwords did not match"
            })
        else:
            self.serializer.is_valid(raise_exception=True)
        self.create_user()
        self.crnt_site = get_current_site(request)
        if send_activation_mail(self.user, self.crnt_site):
            response = Response({
                    "status": "success",
                    "message": _("Activation Mail has been sent to the User"),
                }, status = status.HTTP_200_OK)
        else:
            response = Response({
                    "status": "fail",
                    "message": _("Some Problem in Sending Mail. Please Contact Administrator.")
                }, status = status.HTTP_500_INTERNAL_SERVER_ERROR)
        return response
        

class LogoutView(APIView):
    def logout(self, request):
        logger.info("LogoutView | logout | request user: {}".format(request.user))
        try:
            request.user.auth_token.delete()

        except (AttributeError, ObjectDoesNotExist):
            pass
        django_logout(request)
        response = Response(
            {
                "message": _("Successfully logged out."),
                "status": "success"
            }, status=status.HTTP_200_OK)
        return response

    def get(self, request, *args, **kwargs):
        response = self.http_method_not_allowed(request, *args, **kwargs)
        return response
    
    def post(self, request, *args, **kwargs):
        return self.logout(request)

class PaswordResetView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(data=self.request.data, context={'request': request})
        self.serializer.is_valid(raise_exception=True)
        user = self.serializer.validated_data
        if user is None:
            response = Response({
                "status": _("fail"),
                "message": _("User with given Email does not exists")
            },
            status=status.HTTP_406_NOT_ACCEPTABLE)
        else:
            logger.info("PaswordResetView | post | user_pk: {}".format(user.pk))
            # send password reset mail
            if send_password_reset_mail(user):
                response = Response({
                    "status": _("success"),
                    "message": _("Password Reset Mail has been sent to the user.")
                }, status= status.HTTP_200_OK)
            else:
                response = Response({
                    "status": _("fail"),
                    "message": _("Some Problem in seding mail to the user. Please Contact Administrator."),
                }, status= status.HTTP_500_INTERNAL_SERVER_ERROR)
            return response
         

class PasswordResetConfirmView(GenericAPIView):
    """
    Password reset e-mail link is confirmed, therefore
    this resets the user's password.

    Accepts the following POST parameters: token, uid,
        new_password1, new_password2
    Returns the success/fail message.
    """
    serializer_class = PasswordResetConfirmSerializer
    def post(self, request, *args, **kwargs):
        self.serializer = self.get_serializer(data=self.request.data, context={'request': request})
        self.serializer.is_valid(raise_exception=True)
        data = self.serializer.validated_data['user_data']
        logger.info("PasswordResetConfirmView | post | data: {}".format(data))
        reset_password(data['user'], data['password'])
        return Response({
            'status': _("success"),
            "message":_('Password has been reset')
        }, status=status.HTTP_200_OK)


def activate(request, uidb64, token):
    user_model = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        logger.info("Inside activate method | uid: {}".format(uid))
        user = user_model.objects.get(pk=uid)
        logger.info("activate | User: {}".format(user))
    except user_model.DoesNotExist as ue:
        user = None
    if(
     user is not None and accountValidationToken.check_token(user, token)
    ):
        user.is_active = True
        user.save()
        return redirect(settings.REDIRECT_ON_ACTIVATE)
    else:
        return HttpResponse("Activation Link is Invalid")


class UserDetailView(RetrieveAPIView):
    UserModel = get_user_model()
    queryset = UserModel.objects.all()
    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)