# Generated by Django 5.1.4 on 2025-02-16 21:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0011_user_is_staff'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(max_length=254),
        ),
    ]
