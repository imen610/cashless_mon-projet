# Generated by Django 4.0.4 on 2022-07-15 12:37

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0006_alter_transaction_type_alter_user_account_id_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='wallet',
            name='creation_date',
            field=models.DateTimeField(null=True, verbose_name='creation date'),
        ),
        migrations.AlterField(
            model_name='user',
            name='account_id',
            field=models.CharField(default=6151360, max_length=7, validators=[django.core.validators.MinLengthValidator(7), django.core.validators.MaxLengthValidator(7)]),
        ),
        migrations.AlterField(
            model_name='user',
            name='verification_code',
            field=models.CharField(default='919096', max_length=9),
        ),
    ]