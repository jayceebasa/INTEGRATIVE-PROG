# Generated by Django 5.1.4 on 2025-02-16 21:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('posts', '0010_likes_created_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False),
        ),
    ]
