# Generated by Django 4.0.4 on 2022-07-05 13:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0046_card_wallet_alter_bracelet_options_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='card',
            name='amount',
            field=models.DecimalField(decimal_places=2, max_digits=65),
        ),
    ]
