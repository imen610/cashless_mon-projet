from unicodedata import name
from django.urls import path 
from . import views
from rest_framework_simplejwt.views import (
    TokenRefreshView
)


urlpatterns=[
    path('register/',views.RegisterView.as_view(),name="register"),
    path('email-verify',views.verifyEmail.as_view(),name="email-verify"),
    path('login/',views.LoginAPIView.as_view(),name='login'),
    path('token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    path('request-reset-email',views.RequestPasswordRestEmail.as_view(),name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/',views.PasswordTokenCheckAPI.as_view(),name='password-reset-confirm'),
    path('password-reset-complete',views.SetNewPasswordAPIView.as_view(),name='password-reset-complete'),
    path('users/',views.UserList.as_view(),name='list_users'),
    path('users/<int:pk>/',views.UserDetail.as_view(),name='detail_users'),
    path('shops/',views.ShopAPIView.as_view(),name='shops'),
    path('shops/<int:id>/',views.ShopUpdateAPIView.as_view(),name='update_shop'),
    path('products/',views.productAPIView.as_view(),name='getshopproducts'),
    path('products/<int:id>/',views.ProductUpdateAPIView.as_view(),name='product_id'),
    path('proshop/<int:id>/',views.ShopProductAPIView.as_view(),name='shopproduct_id'),
    path('proshop/<int:id>/<int:pk>/',views.ShopProductAPIView.as_view(),name='updateshopproduct'),
    path('usermem/<int:id>/',views.membreAPIView.as_view(),name='membres_liste'),
    path('usermem/<int:id>/<int:pk>/',views.membreUpdateAPIView.as_view(),name='membres_update_get_delete'),
   # path('shopproducts/<int:id>/',views.ProductShopsAPIView.as_view(),name='shop_product_id'),
    path('bracelet/list/',views.BraceletAPIView.as_view(),name='bracelet_list'),

   ]