from pyexpat import model
from pkg_resources import require
from rest_framework.exceptions import APIException
from asyncio.log import logger
from http.client import OK
from .models import Bracelet, User, Shop, product
from rest_framework import serializers 
from django.contrib.auth import authenticate
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import pdb;
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str , smart_bytes 
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from cashless.utils import Util
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str , smart_bytes ,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


class RegisterSerializer(serializers.ModelSerializer):
  
    class Meta:
        model= User
        fields=['email','username','password']

        extra_kwargs={
            'password':{'write_only':True}
        }


        def validate(self,attrs):
            email = attrs.get('email','')
            username = attrs.get('username','')

            if not username.isalnum():
                raise serializers.ValidationError(
                    'the username should only contain alphanumeric characters'
                )
            return attrs

        def create(self,validated_data):
            user = User.objects.create_user(**validated_data)
            return user

        

class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model=User
        fields=['token']


class LoginSerializer(serializers.Serializer):    
    email=serializers.EmailField()
    password = serializers.CharField()

    def get_tokens(self,user):
        user = user

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }
    def save(self):
        email = self.validated_data['email']
        password = self.validated_data['password']
        #user = auth.authenticate(email=email, password=password)
        user=User.objects.filter(email=email,password=password).first()
        
        if user:
            print(user.email)
            token=self.get_tokens(user)
            print(token)
            msg={
                "username":user.username,
                "email":user.email,
                "token":token
            }
            
        elif not user:
            #raise AuthenticationFailed('Invalid credentials, try again')
            msg={'error':'user not found'}
        elif not user.is_active:
            
            msg={'error''Account disabled, contact admin'}
            #raise AuthenticationFailed('Account disabled, contact admin')
        elif not user.is_verified:
            msg={'error':'Email is not verified'}
            #raise AuthenticationFailed('Email is not verified')  
        else:
            msg={'error':'Unknown Error'}           
        return msg
   


class RestPasswordEmailRequestSerialiser(serializers.Serializer):
    email=serializers.EmailField(min_length=2)
    
    class Meta:
        fields  =['email']
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length = 6, max_length=68,write_only=True)
    token = serializers.CharField(min_length = 1,write_only=True)
    uidb64 = serializers.CharField(min_length = 1,write_only=True)
    class Meta:
        fields=['password','token','uidb64']

    def validate(self,attrs):
        try:
            password=attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed('the reset link is invalid',401)
            user.set_password(password)
            user.save()


        except Exception as identifier :
            raise AuthenticationFailed('the reset link is invalid',401)
        return super().validate(attrs)



class UserSerializer(serializers.ModelSerializer):
    """
    user detail serializer
    """
    class Meta :
        model = User
        fields = ['id','username','email','first_name','last_name','phone','image','address','membre']
        depth = 1




class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = product
        fields = ['id','name_product','price_product','image_product']
       
class ShopSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Shop
        fields = ['id','name_shop','email_shop','address_shop','products','image_shop']
        depth = 1
    
class BraceletSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Bracelet
        fields = ['id','user','shop','amount','maximum_amount']
        depth = 1