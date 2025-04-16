"""
URL configuration for Library_Management_System project.

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
from django.urls import path,include
from library_app.views import admin_login
from django.shortcuts import redirect


urlpatterns = [
    path('', lambda request: redirect('api/')),  # 👈 redirect root to /api/

    # path('admin/', admin.site.urls),
    path('admin/login/', admin_login, name='admin_login'),  # Resolves to /api/admin/login/

    path('api/', include('library_app.urls')),
]
