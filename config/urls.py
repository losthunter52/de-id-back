from django.urls import include, path
from django.contrib import admin

urlpatterns = [
    path('', include('service.urls')),
    path('admin/', admin.site.urls),
]