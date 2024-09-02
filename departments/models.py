from django.db import models


class Command(models.Model):
    command_name = models.CharField(max_length=50)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.command_name

    class Meta:
        verbose_name = "command"
        verbose_name_plural = "commands"
        ordering = ["-commands"]



class Department(models.Model):
    department_name = models.CharField(max_length=50)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


    def __str__(self):
        return self.department_name

    class Meta:
        verbose_name = "department"
        verbose_name_plural = "departments"
        ordering = ["-department"]



class Rank(models.Model):
    rank_level = models.CharField(max_length=50)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


    def __str__(self):
        return self.rank_level

    class Meta:
        verbose_name = "rank"
        verbose_name_plural = "ranks"
        ordering = ["-rank"]

class Zone(models.Model):
    zone = models.CharField(max_length=50)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


    def __str__(self):
        return self.zone

    class Meta:
        verbose_name = "zone"
        verbose_name_plural = "zones"
        ordering = ["-zone"]

