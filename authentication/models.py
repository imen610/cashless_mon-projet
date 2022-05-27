from operator import truediv
from django.db import models
#from django.db.models.signals import post_save
# Create your models here.
from django.db import models
from django.contrib.auth.models import User
# Create your models here.
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.forms import CharField, IntegerField
from django.urls import is_valid_path
from rest_framework_simplejwt.tokens import RefreshToken
from cashless import settings


class UserManager(BaseUserManager):

    def create_user(self,username,email,password=None):

        if username is None:
            raise TypeError('Users should have a userneme')
        if email is None:
            raise TypeError('Users should have an email')
        user=self.model(username=username,email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user


    def create_superuser(self,username,email,password=None):

        if password is None:
            raise TypeError('Password should not be none')
        user=self.create_user(username,email,password)
        user.is_superuser=True
        user.is_staff=True
        user.save()

        return user

    

class User(AbstractBaseUser,PermissionsMixin):
    membre = models.ManyToManyField(to=settings.AUTH_USER_MODEL,null = True)
    username=models.CharField(max_length=255,unique=True,db_index=True)
    email=models.EmailField(max_length=255,unique=True,db_index=True)
    is_verified=models.BooleanField(default=True)
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=False)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)
    first_name= models.CharField(max_length=100,null=True,blank=True)
    last_name=models.CharField(max_length=100,null=True,blank=True)
    phone=models.IntegerField(null=True,blank=True)
    image= models.CharField(max_length=100000, default=None,null=True,blank=True)
    address=models.CharField(max_length=255, default=None,null=True,blank=True)
    birthday = models.DateField(default=None,null=True,blank=True)
    #id_member = IntegerField(null=True,blank=True)
    USERNAME_FIELD='email'
    REQUIRED_FIELDS=['username']

    objects = UserManager()
 
    def __str__(self):
        return self.email
   
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh':str(refresh) ,
            'access':str(refresh.access_token)
        }




class product(models.Model):
    name_product = models.CharField(max_length=255,default = None,null =True)
    price_product = models.FloatField(default = None,null =True)


    def __str__(self):
        return f"{self.name_product}"

class Shop(models.Model):
    products=models.ManyToManyField(product)
    name_shop=models.CharField(max_length=255,default = None,null =True)
    address_shop=models.CharField(max_length=255 , default = None,null =True)
    email_shop= models.CharField(max_length=255,default = None,null =True)

    def __str__(self):
        return f"{self.id}"

        

    

# class Album(models.Model):
#     album_name = models.CharField(max_length=100)
#     artist = models.CharField(max_length=100)

# class Track(models.Model):
#     album = models.ForeignKey(Album, related_name='tracks', on_delete=models.CASCADE)
#     order = models.IntegerField()
#     title = models.CharField(max_length=100)
#     duration = models.IntegerField()

#     class Meta:
#         unique_together = ['album', 'order']
#         ordering = ['order']

#     def __str__(self):
#         return '%d: %s' % (self.order, self.title)


class Bracelet(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    shop = models.OneToOneField(Shop,on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=4, decimal_places=3)
    maximum_amount = models.DecimalField(max_digits=4, decimal_places=3)


    def __str__(self):
        return f"{self.id}"


    