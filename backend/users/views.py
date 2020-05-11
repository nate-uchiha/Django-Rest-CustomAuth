from django.shortcuts import render, redirect
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse

from rest_framework.generics import GenericAPIView
from rest_framework import permissions
from rest_framework.response import Response

from .serizlizer import UserRegisterSerializer
from .utils import send_mail_to_user, activate_account

# Create your views here.
class UserRegisterView(GenericAPIView):
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
    if activate_account(uidb64, token):
        redirect(settings.REDIRECT_ON_ACTIVATE)
    else:
        HttpResponse("Activation Link is Invalid")
    
