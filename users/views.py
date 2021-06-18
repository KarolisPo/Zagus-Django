from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import logout, authenticate, login
from django.contrib import messages
from .forms import UserRegistrationForm
from django.http import HttpResponse


#imports special for email verification
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage


def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Account created! Log In!')
            return redirect("polls:base")

    else:
        form = UserRegistrationForm()
        return render(request, 'users/register.html', {'form': form})

    form = UserRegistrationForm
    return render(request=request,
                  template_name="users/register.html",
                  context={"form": form})


def logout_request(request):
    logout(request)
    messages.info(request, "Logged out successfully")
    return redirect("polls:base")


def login_request(request):
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, f'You are now logged in as {username}')
                return redirect('polls:base')
            else:
                messages.error(request, 'Invalid user name or password')
        else:
            messages.error(request, 'Invalid user name or password')
    form = AuthenticationForm()
    return render(request=request, template_name='users/login.html', context={"form": form})


"""def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        context = {'uidb64':uidb64, 'token':token}
        return render(request, 'users/acc_activate.html', context)
    else:
        return HttpResponse('Activation link is invalid!')"""