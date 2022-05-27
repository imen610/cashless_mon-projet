# Generated by Django 4.0.4 on 2022-05-23 15:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0025_user_address_user_birthday_user_first_name_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('id_product', models.CharField(max_length=255)),
                ('name_product', models.CharField(max_length=255)),
                ('price_product', models.FloatField()),
            ],
        ),
        migrations.CreateModel(
            name='shop',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('address', models.CharField(default=None, max_length=255)),
                ('email', models.CharField(max_length=255)),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='authentication.product')),
            ],
        ),
    ]