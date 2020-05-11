from django.shortcuts import render

from rest_framework.generics import GenericAPIView
from rest_framework import permissions
from rest_framework.response import Response

from .serizlizer import UserRegisterSerializer

# Create your views here.
class UserRegisterView(GenericAPIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = UserRegisterSerializer
    def post(self, request, *args, **kwargs):
        print("Request Data: ", request.data)
        serialized = self.serializer_class(data=request.data)
        # check for field validations
        if serialized.is_valid():
            serialized_data = serialized.data
            #check if user with email exists
            if self.serializer_class._validate_email(serialized_data['email']):
                if self.serializer_class._validate_password(serialized_data['password1'], serialized_data['password2']):
                    #create user
                    self.serializer_class._create_user(serialized.data)
                else:
                    return Responnse({
                        'status': 'fail',
                        'message': 'Passwords did not match!'
                    })
            else:
                return Responnse({
                    'status': 'fail',
                    'message': 'User with given email alreadt exists!'
                })
            # send mail to the user
            return Response({
                'status': 'succes',
                'message': "email sent sucessfully"
            })
        else:
            print("Serializer Errors:", serialized.errors)
            return Response({
                'status': 'fail',
                'message': "Validation Error"
            })        