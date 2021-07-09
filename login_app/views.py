from django.shortcuts import render, redirect
from .models import User
from django.contrib import messages
import bcrypt


def index(request):
    return render(request, 'login.html')

def register_login(request):
    if request.method == 'POST':
        errors = User.objects.validator(request.POST)
        if len(errors) > 0 :
            for k, v in errors.items():
                messages.error(request, v)
            return redirect('/')
        else:
            password = request.POST['password']
            pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            print(pw_hash)

            user1 = User.objects.create(
                first_name=request.POST['first_name'], 
                last_name=request.POST['last_name'],
                email=request.POST['email'],
                password=pw_hash,
                confirm_pw=request.POST['confirm_pw']
                )
            request.session['userid'] = user1.first_name
            return redirect('/success')

def login(request):
    if request.method == 'POST':
        errors = User.objects.login_validator(request.POST)
        if len(errors) > 0 :
            for k, v in errors.items():
                messages.error(request, v)
            return redirect('/')
    user = User.objects.filter(email = request.POST['email'])
    if user:
        logged_user = user[0]

        if bcrypt.checkpw(request.POST['password'].encode(), logged_user.password.encode()):
            request.session['userid'] = logged_user.first_name
            return redirect('/success')
        else:
            messages.error(request, 'Password and Email DO NOT MATCH')
        return redirect('/')
    return redirect('/')

def success(request):
    if 'userid' not in request.session:
        return redirect ('/')
    return render (request, 'login_success.html')

def logout(request):
    request.session.flush()
    return redirect('/')


        
# Create your views here.
