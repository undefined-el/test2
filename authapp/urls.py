from django.urls import path

from . import views

app_name = 'authapp'

urlpatterns = [
    path('login/', views.UserLogin.as_view()),
    path('logout/', views.UserLogout.as_view()),
    path('token/check/', views.UserTokenCheck.as_view()),
]
