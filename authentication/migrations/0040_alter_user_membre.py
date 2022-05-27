# Generated by Django 4.0.4 on 2022-05-27 11:51

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0039_remove_user_membre_user_membre'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='membre',
            field=models.ManyToManyField(null=True, related_name='membre_id', to=settings.AUTH_USER_MODEL),
        ),
    ]
