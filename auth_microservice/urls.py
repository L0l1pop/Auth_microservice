from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('users.urls')),
    path('', lambda request: redirect('login')),
    
   # path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]


