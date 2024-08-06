from django.urls import path
from . import views

urlpatterns = [
    path('secret-sharing/split', views.secretshare_split, name='secretshare_split'),
    path('secret-sharing/reconstruct', views.secretshare_reconstruct, name='secretshare_reconstruct'),
    path('anonymize/sync', views.anonymize_sync, name='anonymize_sync'),
    path('anonymize/async', views.anonymize_async, name='anonymize_async'),
    path('results', views.results, name='results'),
    path('result_detail/<str:task_id>', views.result_detail, name='result_detail'),
    path('register', views.register, name='register'),  
    path('login', views.login, name='login'),         
]
