# Create your views here.

from cgitb import lookup
from os import stat
from re import S
from urllib import response
import uuid
from urllib3 import HTTPResponse
from authentication.utils.phone_verif import send_verification
from cashless import settings
from django.shortcuts import render
from rest_framework import generics, status,views
from django.conf import settings
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.generics import ListCreateAPIView, ListAPIView
from django.contrib.auth import get_user_model
from cashless.settings import SECRET_KEY
from  .serializers import  ProductSerializer,RegisterSerializer, EmailVerificationSerializer,RestPasswordEmailRequestSerialiser , SetNewPasswordSerializer, ShopSerializer, UserSerializer
from rest_framework.response import Response 
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Payment, Transaction, User, Shop, Wallet, product, shop_account
from cashless.utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.shortcuts import redirect
import jwt
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str , smart_bytes ,DjangoUnicodeDecodeError
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from cashless.utils import Util
from rest_framework.generics import ListCreateAPIView,RetrieveUpdateDestroyAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from authentication import serializers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
# Create your views here.
from django.db.models import Q



class RegisterAPIView(views.APIView):
    serializer_class = serializers.RegisterSerializer

    def get(self, request):
      
        message = "Welcome to PayDrop! Create an account today!"
        # obj = Wallet(wallet_id='0956', balance=0,account=request.user, is_disabled=False)
        # obj.save()
        return Response(message, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
   
        if serializer.is_valid(raise_exception=True):
            serializer.save()
           
           

            phone_number = serializer.validated_data['phone_number']
            account_created = User.objects.get(phone_number=phone_number)
          

            send_verification(phone_number, account_created.verification_code)
            return redirect('http://0.0.0.0:8000/api/auth/verify/')

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyAPIView(views.APIView):
    serializer_class = serializers.VerifySerializer

    def get(self, request):
        message = "verify your account with the OTP code you received via SMS"
        return Response(message, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            try:
                account_to_verify = User.objects.get(verification_code=serializer.validated_data['otp'])
                if account_to_verify.is_active == True:
                    return Response("No need for verification.")

                else:
                    account_to_verify.is_active = True 
                    account_to_verify.verification_code = "VERIFIED"
                    account_to_verify.save()
                    return Response(f"Account {account_to_verify.email} has been activated.", status=status.HTTP_200_OK)

            except:
                return Response("Invalid Verification Code", status=status.HTTP_404_NOT_FOUND)

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework_simplejwt.views import TokenViewBase
from .serializers import TokenObtainLifetimeSerializer, TokenRefreshLifetimeSerializer


class TokenObtainPairView(TokenViewBase):
    """
        Return JWT tokens (access and refresh) for specific user based on username and password.
    """
    serializer_class = TokenObtainLifetimeSerializer


class TokenRefreshView(TokenViewBase):
    """
        Renew tokens (access and refresh) with new expire time based on specific user's access token.
    """
    serializer_class = TokenRefreshLifetimeSerializer





# class RegisterView(generics.GenericAPIView):
#     serializer_class = RegisterSerializer


#     def post(self,request):
#         user=request.data
#         serializer=self.serializer_class(data=user)
#         serializer.is_valid(raise_exception=True)
#         serializer.save() 

#         user_data=serializer.data 
        
#         user =User.objects.get(email=user_data['email'])

#         token=RefreshToken.for_user(user).access_token
#         current_site=get_current_site(request).domain
        
#         relativeLink=reverse('email-verify')
#         absurl='http://'+ str(current_site)+str(relativeLink)+"?token="+str(token)
#         email_body='hi'+user.username+'Use link below to verify your email \n' + absurl
#         data={'email_body':email_body ,'to_email':user.email,'email_subject':'Verify your email'}
        
   
#         Util.send_email(data)

#         return Response(user_data,status=status.HTTP_201_CREATED)


# class verifyEmail(views.APIView):

#     serializer_class=EmailVerificationSerializer

#     #token_param_config=openapi.Parameter('token',in_=openapi.IN_QUERY,description='description',type=openapi.TYPE_STRING)
    
    
#     #@swagger_auto_schema(manual_parameters=[token_param_config])
#     def get(self,request):
#         token = request.GET.get('token')
        
#         try:
#             payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
#             user=User.objects.get(id=payload['user_id'])
#             if not user.is_verified: 
#                 user.is_verified = True
#                 user.save()
#             return Response({'email':'Successfully activated'},status=status.HTTP_201_CREATED)
#         except jwt.ExpiredSignatureError as identifier :
#             return Response({'error':'Activation expired'},status=status.HTTP_400_BAD_REQUEST)
#         except jwt.exceptions.DecodeError as identifier :
#             return Response({'error':'Invalid token'},status=status.HTTP_400_BAD_REQUEST)
        

    
# class LoginAPIView(views.APIView):

    
    
#    # serializer_class = LoginSerializer

    
#     def post(self,request):
        
        
#         serializer=LoginSerializer(data=request.data)
#        # user=User.objects.filter(email=request.data['email'],password=request.data['password']).first()
#         if serializer.is_valid():
#             data=serializer.save()
#             try:
#                 print(data['error'])
#                 return Response(data,status=status.HTTP_400_BAD_REQUEST)
#             except:    
#              return Response(data)
#         data={"Error":"Invaild Credential"}  
#         return Response(data, status=status.HTTP_400_BAD_REQUEST)   

        
        

  
    
    
# class RequestPasswordRestEmail(generics.GenericAPIView):

#     serializer_class = RestPasswordEmailRequestSerialiser

#     def post(self,request):
#         serializer= self.serializer_class(data=request.data)
#         email= request.data['email']
#         if User.objects.filter(email=email).exists():
#                 user=User.objects.filter(email=email).first()
#                 uidb64=urlsafe_base64_encode(smart_bytes(user.id))
#                 token = PasswordResetTokenGenerator().make_token(user)
#                 current_site=get_current_site(request=request).domain
        
#                 relativeLink=reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
#                 absurl='http://'+ str(current_site)+str(relativeLink)
#                 email_body='hello ,\n Use link below to reset  your password \n' + absurl
#                 data={'email_body':email_body ,'to_email':user.email,'email_subject':'reset your password'}
    
#                 Util.send_email(data)
#         return Response({'success':'we have sent you a link to reset your password'},status=status.HTTP_200_OK)

# class PasswordTokenCheckAPI(generics.GenericAPIView):
#     def get(self,request,uidb64,token):
#         try:
#             id = smart_str(urlsafe_base64_decode(uidb64))
#             user=User.objects.get(id=id)
#             if not PasswordResetTokenGenerator().check_token(user,token):
#                 return Response({'error':'Token is not valid , please request a new one'})
            
#             return Response({'success':True,'message':'Credentials Valid','uidb64':uidb64,'token':token},status=status.HTTP_200_OK)

#         except DjangoUnicodeDecodeError as identifier:
#                 if not PasswordResetTokenGenerator().check_token(user):
#                     return Response({'error' : 'Token is not valid , please request a new one'})

# class SetNewPasswordAPIView(generics.GenericAPIView):
#     serializer_class=SetNewPasswordSerializer

#     def patch(self,request):
#         serializer = self.serializer_class(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         return Response({'success': True,'message':'Password reset success'},status=status.HTTP_200_OK)

class UserList(ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]


class UserDetail(RetrieveUpdateDestroyAPIView):
    queryset = User
    serializer_class = UserSerializer

class ShopDetail(RetrieveUpdateDestroyAPIView):
    queryset = Shop
    serializer_class = ShopSerializer
    permission_classes = [IsAuthenticated]



class ProductDetail(RetrieveUpdateDestroyAPIView):
    queryset = product
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated]

    

class ShopAPIView(views.APIView):
    permission_classes = [IsAuthenticated]


    
    def get(self,request):
        shops = Shop.objects.all()
        serializer= ShopSerializer(shops,many=True)
        return Response(serializer.data,status = status.HTTP_200_OK)

    def post(self,request):
       
        serializer=ShopSerializer(data=request.data)
        if serializer.is_valid():
            # shop = Shop()
            # x=uuid.uuid4().int
            # print(x)
            # shop_account.objects.create(
            #     wallet_id=x, balance=0,account=self.request.shop, is_disabled=False

            # )
            serializer.save()
            return Response(serializer.data,status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class ShopUpdateAPIView(views.APIView):
    lookup_fields = 'id'
    # def get_shop(self,id):
    #     print("imen")
    #     try:
    #         shop = Shop.objects.get(id=id)
    #         print('hello')
    #     except shop.DoesNotExist:
    #         return HTTPResponse(status=status.HTTP_404_NOT_FOUND)

    def get(self,request,id):
        shop = Shop.objects.get(id=id)
        serializer = ShopSerializer(shop)
        return Response(serializer.data,status = status.HTTP_200_OK)

    def put(self,request,id):
        shop = Shop.objects.get(id=id)
        serializer = ShopSerializer(shop,data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status=status.HTTP_200_OK)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

    def delete(self,request,id):
        shop = Shop.objects.get(id=id)
        shop.delete()
        return Response(status = status.HTTP_204_NO_CONTENT)

class productAPIView(views.APIView):
    def get(self,request):
        prod = product.objects.all()
       # for product in shop.products.all():
        serializer = ProductSerializer(prod,many = True)
        return Response(serializer.data,status = status.HTTP_200_OK)


    def post(self,request):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors , status=status.HTTP_400_BAD_REQUEST)
        

class ProductUpdateAPIView(views.APIView):
    lookup_fields = 'id'
    def get(self,request,id):
        prod= product.objects.get(id=id)
        serializer = ProductSerializer(prod)
        return Response(serializer.data, status = status.HTTP_200_OK)

    def put(self,request,id):
        prod = product.objects.get(id=id)
        serializer =ProductSerializer(prod,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data,status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request , id):
        prod = product.objects.get(id=id)
        prod.delete()
        return Response(status= status.HTTP_204_NO_CONTENT)



class ShopProductAPIView(views.APIView):

    def get(self,request,id):
        #products = ProductSerializer(many = True)
        try:
            e = Shop.objects.get(id=id)
            h=e.products.all()
            prod = ProductSerializer(h,many =True)
            return  Response(prod.data , status=status.HTTP_200_OK)
        except Shop.DoesNotExist:
            return Response(status = status.HTTP_404_NOT_FOUND)





    def post(self,request,id):
        e = Shop.objects.get(id=id)
        print(e, "hello")
        print(request.data['id'])
        l = request.data['id']
        print(l)
        e.products.add(l)
        return Response(status=status.HTTP_200_OK)

        
    

    def put(self,request,id,pk):
     
            e = Shop.objects.get(id=id)
            h=e.products.get(pk=pk)
            serializer = ProductSerializer(h,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return  Response(serializer.data , status=status.HTTP_200_OK)


    def delete(self,request,id,pk):
        e = Shop.objects.get(id=id)
        h=e.products.get(pk=pk)
        h.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# class ProductShopsAPIView(views.APIView):
    
#     def get(self,request,id):
#         products= product.objects.get(id=id)
#         print(products)
#         # h=e.Shop().first()
#         # serializer = ShopSerializer(h)
#         return Response(products, status = status.HTTP_200_OK)
    
    

class membreAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    lookup_fields = 'id'
    def get(self,request,id):
        user= User.objects.get(id=id)
        membres = user.membre.all()
        serializer = UserSerializer(membres, many = True)
        return Response(serializer.data , status=status.HTTP_200_OK)

    def post(self,request,id):
        e = User.objects.get(id=id)
        print(e)
        l = request.data['id']
        h=e.membre.add(l)
        print(h)
        return Response("member added with success",status=status.HTTP_201_CREATED)
    



class membreUpdateAPIView(views.APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request,id,pk):

        user= User.objects.get(id=id)
        membr = user.membre.get(pk=pk)
        serializer = UserSerializer(membr)
        return Response(serializer.data,status=status.HTTP_200_OK)



    def put(self,request,id,pk):
        e = User.objects.get(id=id)
        membres=e.membre.get(pk=pk)
        serializer = UserSerializer(membres,data=request.data)
        if serializer.is_valid():
            serializer.save()
            return  Response(serializer.data , status=status.HTTP_200_OK)


    def delete(self,request,id,pk):
        e=User.objects.get(id=id)
        membre = e.membre.get(pk=pk)
        membre.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



class AccountWalletView(APIView):
    serializer_class = serializers.WalletSerializer
    permission_classes = [IsAuthenticated]

    # def get(self, request):
       
    #     obj = Wallet(wallet_id='0958', balance=0,account=request.user, is_disabled=False)
    #     obj.save()
    #     print('request.user',request.user)
    #     wallet_data2 = Wallet.objects.filter(
    #         account=8004867)
    #     print('wallet_data2',wallet_data2)

    #     wallet_data='Usama'
    #     #if wallet_data["is_disabled"] == True:
    #     return Response({
    #         "account status": "blocked",
    #         "wallet id": wallet_data,
    #         "message": "Your account has been disabled, contact support"
    #     })

    def get(self, request):
        print('request.user',request.user.id)
        wallet_data = Wallet.objects.filter(account__id=request.user.id).values()[0]

        if wallet_data["is_disabled"] == True:
            return Response({
                "account status": "blocked",
                "wallet id": wallet_data['wallet_id'],
                "message": "Your account has been disabled, contact support"
            })

        else:
            return Response({
                "account status": "enabled",
                "wallet id": wallet_data['wallet_id'],
                "balance": float(wallet_data['balance'])
            })

class SuccessView(APIView):
    def get(self, request):
        return Response({
            "message": "Transfer Complete! Head back home http://0.0.0.0:8000/auth/my-wallet/"
        }, status=status.HTTP_200_OK)


class TransactionsListView(ListAPIView):
    serializer_class = serializers.TransactionHistorySerializer
    queryset = Transaction.objects.all()
    permission_classes = [IsAuthenticated]

    def list(self, request):
        print(self.request.user.username)
        account_transactions = Transaction.objects.filter(Q(to = self.request.user.username) |Q(account = self.request.user) )
        my_trans = Transaction.objects.filter(account = self.request.user)
        my_trans.update(type='Outflow')
        my_trans2 = Transaction.objects.filter(to = self.request.user.username)
        my_trans2.update(type='Inflow')
        print(account_transactions)
        serializer = serializers.TransactionHistorySerializer(account_transactions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
  



class MakePaymentView(APIView):
    serializer_class = serializers.PaymentSerializer

    def get(self, request, format=None):
        message = "Start sending money by just typing in a username!"
        return Response({
            "message": message
        })

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            val_data = dict(serializer.validated_data)

            if User.objects.filter(username=val_data['to_acct']).count() == 1:
                if val_data['to_acct'] == request.user.username:
                    return Response({
                        "alert": "You can't send money to yourself silly!"
                    }, status=status.HTTP_406_NOT_ACCEPTABLE)

                else:
                    amount = val_data['amount']
                    sender_acct = Wallet.objects.get(account=self.request.user)
                    recv_account = User.objects.get(username=val_data['to_acct'])
                    wallet_instance = Wallet.objects.get(account=recv_account)

                    if float(amount) > float(sender_acct.balance):
                        return Response({
                            'alert': "You do not have enough funds to complete the transfer..."
                        }, status=status.HTTP_406_NOT_ACCEPTABLE)

                    else:
                        wallet_instance.balance = float(wallet_instance.balance) + float(amount)
                        wallet_instance.save()

                        sender_acct.balance = float(sender_acct.balance) - float(val_data['amount'])
                        sender_acct.save()

                        trx = Transaction.objects.create(
                            account = request.user,
                            amount = amount,
                            to = val_data['to_acct']
                        )

                        trx.save()
                        return redirect('success')

            else:
                return Response({
                    "alert": f"Account not found, please try again."
                }, status=status.HTTP_404_NOT_FOUND)



class MakePaymentShopView(APIView):
    serializer_class = serializers.PaymentSerializer

    def get(self, request, format=None):
        message = "Start sending money by just typing in a shop_name!"
        return Response({
            "message": message
        })

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            val_data = dict(serializer.validated_data)

            if Shop.objects.filter(name_shop=val_data['to_acct']).count() == 1:
                if val_data['to_acct'] == request.shop.name_shop:
                    return Response({
                        "alert": "You can't send money to yourself silly!"
                    }, status=status.HTTP_406_NOT_ACCEPTABLE)

                else:
                    amount = val_data['amount']
                    sender_acct = Wallet.objects.get(account=self.request.user)
                    recv_account = Shop.objects.get(name_shop=val_data['to_acct'])
                    wallet_instance = shop_account.objects.get(account=recv_account)

                    if float(amount) > float(sender_acct.balance):
                        return Response({
                            'alert': "You do not have enough funds to complete the transfer..."
                        }, status=status.HTTP_406_NOT_ACCEPTABLE)

                    else:
                        wallet_instance.balance = float(wallet_instance.balance) + float(amount)
                        wallet_instance.save()

                        sender_acct.balance = float(sender_acct.balance) - float(val_data['amount'])
                        sender_acct.save()

                        trx = Transaction.objects.create(
                            account = request.user,
                            amount = amount,
                            to = val_data['to_acct']
                        )

                        trx.save()
                        return redirect('success')

            else:
                return Response({
                    "alert": f"Account not found, please try again."
                }, status=status.HTTP_404_NOT_FOUND)



class MakeTransactionsView(APIView):
    serializer_class = serializers.TransactionSerializer

    def get(self, request, format=None):
        message = "Start sending money by just typing in a username!"
        return Response({
            "message": message
        })

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            val_data = dict(serializer.validated_data)

            if User.objects.filter(username=val_data['to_acct']).count() == 1:
                if val_data['to_acct'] == request.user.username:
                    return Response({
                        "alert": "You can't send money to yourself silly!"
                    }, status=status.HTTP_406_NOT_ACCEPTABLE)

                else:
                    amount = val_data['amount']
                    sender_acct = Wallet.objects.get(account=self.request.user)
                    recv_account = User.objects.get(username=val_data['to_acct'])
                    wallet_instance = Wallet.objects.get(account=recv_account)

                    if float(amount) > float(sender_acct.balance):
                        return Response({
                            'alert': "You do not have enough funds to complete the transfer..."
                        }, status=status.HTTP_406_NOT_ACCEPTABLE)

                    else:
                        wallet_instance.balance = float(wallet_instance.balance) + float(amount)
                        wallet_instance.save()

                        sender_acct.balance = float(sender_acct.balance) - float(val_data['amount'])
                        sender_acct.save()

                        trx = Payment.objects.create(
                            from_acct = request.user,
                            amount = amount,
                            to_acct = val_data['to_acct']
                        )

                        trx.save()
                        return redirect('success')

            else:
                return Response({
                    "alert": f"Account not found, please try again."
                }, status=status.HTTP_404_NOT_FOUND)
# get current user ok !

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


