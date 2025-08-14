from django.db import models
from django.contrib.auth.models import AbstractUser
import uuid

class FarmerUser(AbstractUser):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']  # Keep username but email will be used for login

class ScanHistory(models.Model):
    user = models.ForeignKey('FarmerUser', on_delete=models.CASCADE)
    disease = models.CharField(max_length=255)
    confidence = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.disease} ({self.confidence}%)"