
from django.contrib import admin
from django.urls import path
from account.views import UserRegiStationView,UserLoginView,UserProfileView,UserChangePasswordView,SendPasswordResetEmailView,UserResetPasswordView

urlpatterns = [
    path('register/', UserRegiStationView.as_view(),name="register"),
    path('login/', UserLoginView.as_view(),name="login"),
    path('profile/', UserProfileView.as_view(),name="profile"),
    path('change_password/', UserChangePasswordView.as_view(),name="change_password"),
    path('send_reset_password_email/', SendPasswordResetEmailView.as_view(),name="reset_password"),
    path('send_reset_password_email/<uid>/<token>/', UserResetPasswordView.as_view(),name="reset_password"),

]
