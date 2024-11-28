"""
URL configuration for accounts project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from acc_app.views import login_view  
from django.shortcuts import redirect# Pastikan impor yang benar
from acc_app.views import landingpage_view

urlpatterns = [
    path('', lambda request: redirect('landingpage')),  # Redirect otomatis ke login
    path('admin/', admin.site.urls),
    path('accounts/', include('acc_app.urls')),  # URL untuk aplikasi akun
    path('accounts/', login_view, name='home'),  # Root URL diarahkan ke login_view
    path('',landingpage_view, name='landing_page'),  # Landing page sebagai URL root
]


