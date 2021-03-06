# Generated by Django 4.0.4 on 2022-07-15 11:36

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0005_transaction_type_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='transaction',
            name='type',
            field=models.CharField(choices=[('outflow', 'Outflow'), ('inflow', 'Inflow')], default='inflow', max_length=10),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=2052497, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='155105', max_length=9),
        ),
    ]
