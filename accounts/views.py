import random
import datetime
import re
import json
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.core.mail import send_mail
from django.utils import timezone
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from .models import FarmerUser
from accounts.models import ScanHistory  # Make sure this model exists

# Home Page
def home(request):
    return render(request, "home.html")

# Signup View
def signup_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if FarmerUser.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return redirect('signup')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('signup')

        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$'
        if not re.match(pattern, password):
            messages.error(
                request,
                "Password must be at least 8 characters long and include an uppercase letter, "
                "a lowercase letter, a number, and a special character (!@#$%^&*)."
            )
            return redirect('signup')

        FarmerUser.objects.create(
            username=username,
            email=email,
            password=make_password(password)
        )

        messages.success(request, "Account created successfully. Please log in.")
        return redirect('login')

    return render(request, "registration/signup.html")

# Login View
def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        user = authenticate(request, email=email, password=password)
        if user:
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            send_mail(
                "Your FloraScan OTP",
                f"Your OTP is {otp}. It will expire in 5 minutes.",
                "no-reply@florascan.com",
                [email],
                fail_silently=False,
            )

            request.session['email'] = email
            return redirect('verify_otp')
        else:
            messages.error(request, "Invalid email or password.")

    return render(request, "registration/login.html")

# OTP Verification
def verify_otp_view(request):
    email = request.session.get('email')
    if not email:
        return redirect('login')

    try:
        user = FarmerUser.objects.get(email=email)
    except FarmerUser.DoesNotExist:
        messages.error(request, "Invalid session. Please login again.")
        return redirect('login')

    if request.method == "POST":
        otp_entered = request.POST.get("otp")
        if user.otp == otp_entered and timezone.now() - user.otp_created_at <= datetime.timedelta(minutes=5):
            auth_login(request, user)
            user.otp = None
            user.save()
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid or expired OTP.")

    return render(request, "registration/verify_otp.html")

# Forgot Password
def forgot_password_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = FarmerUser.objects.get(email=email)
            otp = str(random.randint(100000, 999999))
            user.otp = otp
            user.otp_created_at = timezone.now()
            user.save()

            send_mail(
                "FloraScan - Password Reset OTP",
                f"Your OTP for password reset is {otp}. It expires in 5 minutes.",
                "no-reply@florascan.com",
                [email],
                fail_silently=False,
            )

            request.session['reset_email'] = email
            messages.success(request, "OTP sent to your email.")
            return redirect('reset_password')
        except FarmerUser.DoesNotExist:
            messages.error(request, "No account found with this email.")

    return render(request, "registration/forgot_password.html")

# Reset Password
def reset_password_view(request):
    email = request.session.get('reset_email')
    if not email:
        return redirect('forgot_password')

    try:
        user = FarmerUser.objects.get(email=email)
    except FarmerUser.DoesNotExist:
        messages.error(request, "Invalid request.")
        return redirect('forgot_password')

    if request.method == "POST":
        otp_entered = request.POST.get("otp")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        if user.otp != otp_entered or timezone.now() - user.otp_created_at > datetime.timedelta(minutes=5):
            messages.error(request, "Invalid or expired OTP.")
        elif new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
        else:
            user.password = make_password(new_password)
            user.otp = None
            user.save()
            messages.success(request, "Password reset successful. Please log in.")
            return redirect('login')

    return render(request, "registration/reset_password.html")

# Logout
def logout_view(request):
    auth_logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('home')

# Dashboard
@login_required
def dashboard_view(request):
    total_predictions = ScanHistory.objects.filter(user=request.user).count()
    monthly_predictions = ScanHistory.objects.filter(
        user=request.user,
        created_at__month=timezone.now().month
    ).count()

    # Example of extra stats
    recent_scans = ScanHistory.objects.filter(user=request.user).order_by('-created_at')[:5]
    common_disease = ScanHistory.objects.filter(user=request.user).values_list('disease', flat=True).order_by().distinct().first()
    accuracy_rate = 95  # placeholder until you calculate real accuracy
    tips = [
        "Water plants early in the morning.",
        "Rotate crops to prevent soil depletion.",
        "Inspect leaves regularly for pests."
    ]
    random_tip = random.choice(tips)

    return render(request, "pages/dashboard.html", {
        "total_predictions": total_predictions,
        "predictions_this_month": monthly_predictions,
        "accuracy_rate": accuracy_rate,
        "most_common_disease": common_disease or "N/A",
        "recent_scans": recent_scans,
        "tip_of_the_day": random_tip,
        "now": timezone.now(),
    })

# Pages
@login_required
def new_scan_view(request):
    return render(request, "pages/new_scan.html")

@login_required
def profile_view(request):
    return render(request, "pages/profile.html")

@login_required
def history_view(request):
    return render(request, "pages/history.html")

@login_required
def settings_view(request):
    return render(request, "pages/settings.html")
