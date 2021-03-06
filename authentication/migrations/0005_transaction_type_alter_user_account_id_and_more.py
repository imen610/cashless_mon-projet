# Generated by Django 4.0.4 on 2022-07-15 11:30

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0004_alter_user_account_id_alter_user_verification_code'),
    ]

    operations = [
        migrations.AddField(
            model_name='transaction',
            name='type',
            field=models.CharField(choices=[('outflow', 'Outflow'), ('inflow', 'Inflow')], default='outflow', max_length=10),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=9213435, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='642810', max_length=9),
        ),
    ]
