from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django import forms
from django.contrib.auth.decorators import login_required


# Form registrasi
class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    # Validasi password
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        if password != confirm_password:
            self.add_error('confirm_password', "Password tidak sama")
        return cleaned_data

# Register view
def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            messages.success(request, 'Registrasi berhasil!')
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'acc_app/register.html', {'form': form})

# Login view
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Login berhasil!')
            return redirect('dashboard')  # Sesuaikan URL tujuan setelah login
        else:
            messages.error(request, 'Username atau password salah')
    return render(request, 'acc_app/login.html')
#landingpage view
def landingpage_view(request):
    return render(request, 'acc_app/landingpage.html')  # Jika belum login, tampilkan landing page
#classes view
def classes_view(request):
    return render(request, 'acc_app/classes.html')
#profile view
def profile_view(request):
    return render(request, 'acc_app/profile.html')
#settings view
def settings_view(request):
    return render(request, 'acc_app/settings.html')
#dashboard view
@login_required
def dashboard_view(request):
    return render(request, 'acc_app/dashboard.html')  # Halaman dashboard

def logout_view(request):
    logout(request)
    return redirect('acc_app/landingpage.html')  # Setelah logout, arahkan ke halaman login