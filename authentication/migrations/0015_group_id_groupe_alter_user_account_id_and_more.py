# Generated by Django 4.0.4 on 2022-07-28 10:05

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0014_alter_user_account_id_alter_user_verification_code_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='group',
            name='id_groupe',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=4498363, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='300837', max_length=9),
        ),
    ]