from django.urls import path
from .views import *

urlpatterns = [
    path('create/', UserCreateView.as_view()),
    path('login/', LoginView.as_view()),
    path('login/refresh/', LoginRefreshView.as_view()),
    path('logout/', LogOutView.as_view()),
    path('verify/', GetNewVerification.as_view()),
    path('change/user/', ChangeUserDataView.as_view()),
    path('change/user/photo', ChangeUserPhotoView.as_view()),
    path('forgot/password/', ForgotPasswordView.as_view()),
    path('renew/password/', ResetPasswordView.as_view()),

]