from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.exceptions import ImmediateHttpResponse
from django.contrib.auth import get_user_model
from django.http import HttpResponse

User = get_user_model()

class MyAccountAdapter(DefaultAccountAdapter):
    def save_user(self, request, user, form, commit=True):
        user = super(MyAccountAdapter, self).save_user(request, user, form, commit=False)
        user.save()
        return user

class MySocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        # This is called after a successful authentication from the social provider
        # but before the login is actually processed.
        if sociallogin.is_existing:
            return

        # If the user is not logged in and the email address is already taken,
        # link the social account to the existing user.
        email = sociallogin.user.email
        if email:
            try:
                existing_user = User.objects.get(email=email)
                sociallogin.connect(request, existing_user)
            except User.DoesNotExist:
                # Create a new user if one does not exist
                sociallogin.user.username = sociallogin.user.email.split('@')[0]
                sociallogin.user.save()
                sociallogin.user.roles.add(2)