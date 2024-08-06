# models.py

from django.db import models
from django.contrib.auth.models import User

class Task(models.Model):
    TASK_STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
    )

    description = models.CharField(max_length=100)
    task_id = models.CharField(max_length=100, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=100, default='PENDING')
    errors = models.TextField(default="[]")
    result = models.TextField(blank=True, null=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    real_data_k_anonymity = models.TextField(blank=True, null=True)
    real_data_t_closeness = models.TextField(blank=True, null=True)
    real_data_l_diversity = models.TextField(blank=True, null=True)
    anonymized_data_k_anonymity = models.TextField(blank=True, null=True)
    anonymized_data_t_closeness = models.TextField(blank=True, null=True)
    anonymized_data_l_diversity = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Task ID: {self.task_id}, Description: {self.description}, User: {self.user.username}, Status: {self.status}"
    