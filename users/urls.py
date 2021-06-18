from django.urls import path
from . import views
from django.conf.urls import url

app_name = 'users'
urlpatterns = [
    path('register/', views.register, name='register'),
    path('logout/', views.logout_request, name='logout'),
    path('login/', views.login_request, name='login'),
    ]