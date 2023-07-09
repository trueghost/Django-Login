from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from sta import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from django.core.mail import EmailMessage, send_mail

# Create your views here.
def home(request):
    return render(request, "authentication/index.html")

def signup(request):
    
    if request.method == 'POST':
        #username = request.POST.get('username')
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']
        
        if User.objects.filter(username=username):
            messages.error(request, "Username already exists! Please try some other username")
            return redirect('home')
        
        if User.objects.filter(email=email):
            messages.error(request, "Email already registered!")
            return redirect('home')

        if len(username)>10:
            messages.error(request, "Username must be under 10 characters")

        if pass1 != pass2:
            messages.error(request, "Passwords didnot match!")
            
        if not username.isalnum():
            messages.error(request, "Username must be Alpha-Numeric!")
            return redirect('home')
        
        myUser = User.objects.create_user(username, email, pass1) # type: ignore
        myUser.first_name = fname
        myUser.last_name = lname
        myUser.is_active = False
        myUser.save()
        
        messages.success(request, "Your account has been successfully created. We have sent you a confirmation email, please confirm your email in order to activate you account.")
        
        #welcome Email
        
        subject = "Welcome to STA - Django Login!!"
        message = "Hello " + myUser.first_name + "!! \n" + "Welcome ot STA!! \n Thankyou for visiting my website \n We have also sent you a confirmation email, please confirm your email adress in order to activate your account.\n\n Thanking You\n Saurav T Ajith"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myUser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)
        
        # Email Address Confirmation Email
        
        current_site = get_current_site(request)
        email_subject = "Confirm your email @ STA - Django Login!!"
        message2 = render_to_string('email_confirmation.html',{
            'name': myUser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myUser.pk)),
            'token': generate_token.make_token(myUser)
        }) 
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myUser.email],
        )
        email.fail_silently = True # type: ignore
        email.send()
        
        return redirect('signin')
    
    return render(request, "authentication/signup.html")

def signin(request):
    
     if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']
        
        user = authenticate(username=username, password=pass1)
        
        if user is not None:
            login(request, user)
            fname = user.first_name # type: ignore
            return render(request, "authentication/index.html", {'fname': fname})
        
        else: 
            messages.error(request, "Login Failed, please check if your username or password is correct.")
            return redirect('home')
    
     return render(request, "authentication/signin.html")

def signout(request):
    logout(request)
    messages.success(request, "Logged Out Successfully!")
    return redirect('home')

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myUser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myUser = None
        
    if myUser is not None and generate_token.check_token(myUser, token):
        myUser.is_active = True
        myUser.save()
        login(request, myUser)
        return redirect('home')
    else:
        return render(request, 'activation_failed.html')