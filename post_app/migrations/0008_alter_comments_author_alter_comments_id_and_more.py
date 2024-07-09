# Generated by Django 5.0.6 on 2024-06-26 06:16

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('post_app', '0007_remove_comments_uu_id_remove_commentslike_uu_id_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name='comments',
            name='author',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='author', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='comments',
            name='id',
            field=models.UUIDField(default=uuid.UUID('05b08de8-66d2-4ed0-8800-7b6639e26821'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='commentslike',
            name='id',
            field=models.UUIDField(default=uuid.UUID('05b08de8-66d2-4ed0-8800-7b6639e26821'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='post',
            name='id',
            field=models.UUIDField(default=uuid.UUID('05b08de8-66d2-4ed0-8800-7b6639e26821'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='postlike',
            name='id',
            field=models.UUIDField(default=uuid.UUID('05b08de8-66d2-4ed0-8800-7b6639e26821'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]
