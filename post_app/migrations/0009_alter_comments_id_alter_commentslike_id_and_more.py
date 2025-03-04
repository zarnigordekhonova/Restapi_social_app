# Generated by Django 5.0.6 on 2024-06-26 06:31

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('post_app', '0008_alter_comments_author_alter_comments_id_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='comments',
            name='id',
            field=models.UUIDField(default=uuid.UUID('85a91e1c-f50f-4f64-aa3a-e26ae29bf19f'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='commentslike',
            name='id',
            field=models.UUIDField(default=uuid.UUID('85a91e1c-f50f-4f64-aa3a-e26ae29bf19f'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='post',
            name='id',
            field=models.UUIDField(default=uuid.UUID('85a91e1c-f50f-4f64-aa3a-e26ae29bf19f'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='postlike',
            name='id',
            field=models.UUIDField(default=uuid.UUID('85a91e1c-f50f-4f64-aa3a-e26ae29bf19f'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]
