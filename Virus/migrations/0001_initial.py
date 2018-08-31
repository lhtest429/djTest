# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Task',
            fields=[
                ('nameid', models.CharField(max_length=255, serialize=False, primary_key=True)),
                ('taskid', models.CharField(max_length=255)),
                ('beizhu', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='VirusPath',
            fields=[
                ('nameid', models.CharField(max_length=255, serialize=False, primary_key=True)),
                ('name', models.CharField(max_length=255)),
                ('namestamp', models.CharField(max_length=255)),
                ('dateTime', models.DateTimeField(auto_now=True)),
                ('virusTotalTrue', models.IntegerField()),
                ('virusTotalFalse', models.IntegerField()),
                ('cuckooScore', models.FloatField()),
            ],
        ),
    ]
