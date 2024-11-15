from django.urls import path
from .views import register_view, login_view, dashboard_view, logout_view,classes_view,profile_view,settings_view,landingpage_view

urlpatterns = [
    path('', landingpage_view, name='landingpage'),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('classes/', classes_view, name='classes'),
    path('profile/', profile_view, name='profile'),
    path('settings/', settings_view, name='settings'),
    path('dashboard/', dashboard_view, name='dashboard'),  # URL untuk halaman dashboard
    path('logout/', logout_view, name='logout'),  # URL untuk logout
]
