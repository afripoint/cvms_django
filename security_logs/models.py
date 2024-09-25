from django.db import models
from django.utils import timezone



"""
SecurityLog will store logs for blocked IPs, security breaches, and policy violations.
BruteForceAttempt will keep track of repeated failed login attempts (brute force).
"""
class SecurityLogs(models.Model):
    ip_address = models.GenericIPAddressField()
    user_agent = models.CharField(max_length=255)
    action_type = models.CharField(max_length=50)
    description = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)

def __str__(self):
        return f'{self.ip_address} - {self.action_type}'


# bruteforce
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField()
    reason = models.TextField(blank=True, null=True)
    blocked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.ip_address
    

