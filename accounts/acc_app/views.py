from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django import forms
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserChangeForm
from django.contrib.auth import login, authenticate

#forms.register
class RegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password'
        }),
        label="Password"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm your password'
        }),
        label="Confirm Password"
    )
#register
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        labels = {
            'username': 'Username',
            'email': 'Email',
            'password': 'Password'
        }
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your username'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your email'
            }),
            'password': forms.PasswordInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter your password'
            })
        }
#validation
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")

        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords do not match.")

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
            messages.success(request, f'Welcome back, {user.username}!')
            return redirect('dashboard')  # Redirect to dashboard
        else:
            messages.error(request, 'Invalid username or password')
    return render(request, 'acc_app/login.html')

#landingpage view
def landingpage_view(request):
    return render(request, 'acc_app/landingpage.html')  
#classes view
def classes_view(request):
    return render(request, 'acc_app/classes.html')
#profile view
from django.contrib.auth import logout

@login_required
def profile_view(request):
    if request.method == 'POST':
        form = UserChangeForm(request.POST, instance=request.user)
        if form.is_valid():
            old_username = request.user.username  # Simpan username lama
            user = form.save()

            # Perbarui sesi login dengan username baru jika berubah
            if old_username != user.username:
                login(request, user)  # Otomatis refresh sesi pengguna
                messages.success(request, 'Username updated. Session refreshed.')

            messages.success(request, 'Profile updated successfully!')
            return redirect('profile')
    else:
        form = UserChangeForm(instance=request.user)

    return render(request, 'acc_app/profile.html', {
        'form': form,
        'username': request.user.username,
    })


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