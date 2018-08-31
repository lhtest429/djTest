# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

class VirusPath(models.Model):
	nameid = models.CharField(primary_key=True,max_length=255)
	name = models.CharField(max_length=255)
	namestamp = models.CharField(max_length=255)
	dateTime = models.DateTimeField(auto_now=True)
	virusTotalTrue = models.IntegerField()
	virusTotalFalse = models.IntegerField()
	cuckooScore = models.FloatField()

class Task(models.Model):
        nameid = models.CharField(primary_key=True,max_length=255)
        taskid = models.CharField(max_length=255)
	beizhu = models.CharField(max_length=255)
# Create your models here.
