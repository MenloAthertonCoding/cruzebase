# -*- coding: utf-8 -*-
# Generated by Django 1.11.4 on 2017-09-13 07:40
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('rest-auth', '0002_auto_20170830_0303'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='num_seats',
            field=models.PositiveSmallIntegerField(null=True, blank=True, verbose_name='Number of Car seats'),
        ),
    ]
