# Generated by Django 4.0.4 on 2022-08-31 20:47

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0077_rename_max_amount_wallet_maxamount_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=7344908, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='812186', max_length=9),
        ),
    ]
