from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator

# You can replace this with your frontend URL
frontend_url = "http://localhost:5173"  # Change to your React/Vue/Angular frontend URL

def send_email_verification_link(user, signup=True, role=None, password=None):
    token = default_token_generator.make_token(user)
    pass