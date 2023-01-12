from django.db import models
from django.contrib.auth.models import AbstractUser

from .managers import UserManager

class User(AbstractUser):
    """User model"""
    username = None
    email = models.EmailField(unique=True, max_length=100)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()


class ZendeskToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    zendesk_user_id = models.CharField(max_length=64)
    token = models.CharField(max_length=256)
