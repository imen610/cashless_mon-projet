from unicodedata import name
from django.urls import path 
from . import views



urlpatterns=[
    path("sign-up/", views.RegisterAPIView.as_view(), name="register"),
    path("verify/", views.VerifyAPIView.as_view(), name="verify"),
    path('login/', views.TokenObtainPairView.as_view(), name="token_obtain_view"),
    # path('register/',views.RegisterView.as_view(),name="register"),
    # path('email-verify',views.verifyEmail.as_view(),name="email-verify"),
    # path('login/',views.LoginAPIView.as_view(),name='login'),
    # path('token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    # path('request-reset-email',views.RequestPasswordRestEmail.as_view(),name='request-reset-email'),
    # path('password-reset/<uidb64>/<token>/',views.PasswordTokenCheckAPI.as_view(),name='password-reset-confirm'),
    #path('password-reset-complete',views.SetNewPasswordAPIView.as_view(),name='password-reset-complete'),
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
    path('shop/<int:pk>/',views.ShopDetail.as_view(),name='detail_shops'),
    path('product/<int:id>/',views.ProductDetail.as_view(),name='detail_products'),
    path("my-wallet/", views.AccountWalletView.as_view(), name="wallet"),
    path("my-wallet/<int:pk>/", views.AccountWalletMemberView.as_view(), name="wallet_member"),
    path("transactions/", views.TransactionsListView.as_view(), name="transactions"),
    path("transactionsShop/", views.TransactionsShopListView.as_view(), name="transactionsShop"),
    path("PaymentShopsAdminDashView/", views.PaymentShopsAdminDashView.as_view(), name="PaymentShopsAdminDashView"),
    path("TransactionsAdminDashListView/", views.TransactionsAdminDashListView.as_view(), name="TransactionsAdminDashListView"),
    path("transactions/<int:pk>/<str:username>/", views.TransactionsMemberListView.as_view(), name="transactions_member"),
    path("stat/", views.statistiqueWallets.as_view(), name="statistiqueWallets"),
    path("pay/", views.MakePaymentView.as_view(), name="pay"),
    path("payshop/", views.MakePaymentShopView.as_view(), name="payshop"),
    path("transfer/", views.MakeTransactionsView.as_view(), name="transfer"),
    path("transfer-success/", views.SuccessView.as_view(), name="success"),
    path("current/", views.CurrentUserView.as_view(), name='test'),
    path("currentgroup/<int:pk>/", views.CurrentUsergroup.as_view(), name='test'),
    path("groups/", views.ListGroups.as_view(), name='test'),
    path("ProductBlocked/", views.ProductBlockedview.as_view(), name='ProductBlocked'),
    path("UpdateProductStatus/<int:id>/<int:pk>/", views.UpdateProductStatusview.as_view(), name='UpdateProductStatus'),
    path("UpdateWalletStatus/<int:id>/", views.UpdateWalletStatusView.as_view(), name='UpdateWalletStatus'),
#    UpdateWalletStatus
   ]


