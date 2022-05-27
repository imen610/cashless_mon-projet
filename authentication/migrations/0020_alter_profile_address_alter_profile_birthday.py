# Generated by Django 4.0.4 on 2022-05-20 00:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0019_alter_profile_birthday'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='address',
            field=models.CharField(blank=True, default=None, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name='profile',
            name='birthday',
            field=models.DateField(blank=True, default=None, null=True),
        ),
    ]
