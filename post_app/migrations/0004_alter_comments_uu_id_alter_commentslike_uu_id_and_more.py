# Generated by Django 5.0.6 on 2024-06-26 05:15

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('post_app', '0003_alter_comments_uu_id_alter_commentslike_uu_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='comments',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('c7773919-584d-4e18-8eea-89773392d293'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='commentslike',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('c7773919-584d-4e18-8eea-89773392d293'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='post',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('c7773919-584d-4e18-8eea-89773392d293'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='postlike',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('c7773919-584d-4e18-8eea-89773392d293'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]
