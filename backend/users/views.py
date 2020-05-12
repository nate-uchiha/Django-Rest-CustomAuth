from django.shortcuts import render, redirect
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.contrib.auth import authenticate, login

from rest_framework import permissions
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView
from rest_framework.response import Response

from .serizlizer import (
    UserRegisterSerializer, LoginSerializer, UserDetailsSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
)
from .utils import (
    send_mail_to_user, activate_account, get_tokens_for_user, send_password_reset_mail, validate_uid, validate_token, _validate_password
)

# Create your views here.
class UserRegisterView(GenericAPIView):
    """
    View to Register Users
    """
    permission_classes = [permissions.AllowAny,]
    serializer_class = UserRegisterSerializer
    def post(self, request, *args, **kwargs):
        print("Request Data: ", request.data)
        serializer = self.serializer_class(data=request.data)
        request_data = request.data
        # check for field validations
        if serializer.is_valid():
            serialized_data = serializer.validated_data
            print("UserRegisterVIew | post | serialier data:", serializer.validated_data)
            #check if user with email exists
            if serializer._validate_email(serialized_data['email']):
                if serializer._validate_password(serialized_data['password1'], serialized_data['password2']):
                    #validate_phone_number
                    if serializer._validate_phone(serialized_data['phone_number']):
                        #create user
                        user = serializer._create_user(serialized_data)
                        current_site = get_current_site(request)
                        if send_mail_to_user(user, current_site):
                            response = Response({
                                'status': 'success',
                                'message': 'Verification mail has been sent to the User'
                            })
                        else:
                            response = Response({
                                'status': 'success',
                                'message': 'Verification mail has been sent to the User'
                            })
                    else:
                        response = Response({
                            'status': 'fail',
                            'message': 'User with this phone number already exists. Provide alternative number'
                        })
                else:
                    response = Response({
                        'status': 'fail',
                        'message': 'Passwords did not match!'
                    })
            else:
                response = Response({
                    'status': 'fail',
                    'message': 'User with given email alreadt exists!'
                })
        else:
            print("Serializer Errors:", serializer.errors)
            response = Response({
                'status': 'fail',
                'message': "Validation Error",
                'errors': serializer.errors
            })
        return response

def activate(request, uidb64, token):
    """
    function to Activate Users
    """
    if activate_account(uidb64, token):
        redirect(settings.REDIRECT_ON_ACTIVATE)
    else:
        HttpResponse("Activation Link is Invalid")
    

class LoginView(GenericAPIView):
    """
    View to Log in Users
    """
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        print("Request Data: ", request.data)
        serializer = self.serializer_class(data=request.data)
        request_data = request.data
        # check for field validations
        if serializer.is_valid():
            print("Serializer Data ", serializer.validated_data)
            user = authenticate(**serializer.validated_data)
            if user is not None:
                if user.is_email_verified:
                    if user.is_active:
                        #create token for user
                        login(request, user)
                        token_data = get_tokens_for_user(user)
                        response = Response({
                            'status': 'success',
                            'access_token': token_data['access'],
                            'refresh_token': token_data['refresh'],
                            'email': user.email,
                            'first_name': user.first_name,
                            'last_name': user.last_name,
                            'phone_number': str(user.phone_number),
                            'last_login': user.last_login
                        })
                    else:
                        response = Response({
                            'status': "fail",
                            'message': 'User Account is Inactive'
                        })
                else:
                    response = Response({
                        'status': "fail",
                        'message': 'User email is not verified'
                    })
            else:
                response = Response({
                    'status': "fail",
                    'message': 'Invalid Credentials'
                })
        else:
            response = Response({
                'status': "fail",
                'message': 'Validation Error',
                'errors': serializer.errors
            })
        return response


class PasswordResetView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer._validate_email(serializer.validated_data['email'])
            if user is not None:
                if send_password_reset_mail(user):
                    response = Response({
                        'status': 'success',
                        'message': "Password Reset mail has been sent successfully"
                    })
                else:
                    response = Response({
                        'status': 'fail',
                        'message': "Problems in sending mail to the user. Please contact admininstrator!"
                    })
            else:
                response = Response({
                    'status': 'fail',
                    'message': "User with this email does not exists"
                })
        else:
            response = Response({
                'status': 'fail',
                'message': "Please provide proper email address"
            })
        return response


class PasswordResetConfimView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            print("PasswordResetConfimView", validated_data)
            user = validate_uid(token['uidb'])
            if user is not None:
                if validate_token(user, validated_data['token']):
                    if _validate_password(validated_data['new_password1'], validated_data['new_password2']):
                        user.set_password(validated_data['new_password1'])
                        user.save()
                        response = Response({
                            'status': "Success",
                            "message": "Password has been reset successfully"
                        })
                    else:
                        response = Response({
                            'status': 'fail',
                            'message': "Passwords did not match!!!"
                        })
                else:
                    response = Response({
                        'status': 'fail',
                        'message': "Invalid Token"
                    })
            else:
                response = Response({
                    'status': 'fail',
                    'message': "Invalid Uid"
                })
            response = Response(serializer.data) 
        else:
            response = Response({
                'status': 'fail',
                'message': 'Validation Error'
            })


class UserDetailsView(GenericAPIView):
    serializer_class = UserDetailsSerializer
    permission_classes = (permissions.IsAuthenticated,)
    
    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        serialized_data = serializer.data
        return Response({
            "email": serialized_data['email'],
            "first_name": serialized_data['first_name'],
            "last_name": serialized_data['last_name'],
            "last_login": serialized_data['last_login'],
            "groups": serialized_data['groups'],
            "profile": serialized_data['profile']
        })