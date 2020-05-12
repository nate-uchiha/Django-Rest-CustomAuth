from django.shortcuts import render, redirect
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.contrib.auth import authenticate, login

from rest_framework.generics import GenericAPIView
from rest_framework import permissions
from rest_framework.response import Response

from .serizlizer import UserRegisterSerializer, LoginSerializer
from .utils import send_mail_to_user, activate_account, get_tokens_for_user

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
        