# Generated by Django 4.1.4 on 2023-01-09 14:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='zendesktoken',
            name='zendesk_user_id',
            field=models.CharField(max_length=64),
        ),
    ]
