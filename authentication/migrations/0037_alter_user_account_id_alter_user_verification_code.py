# Generated by Django 4.0.4 on 2022-08-16 13:23

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0036_article_vendues_user_alter_article_vendues_code_nfc_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=9050926, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='863659', max_length=9),
        ),
    ]
