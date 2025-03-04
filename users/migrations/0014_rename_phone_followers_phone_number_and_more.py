# Generated by Django 5.0.6 on 2024-06-26 05:45

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_alter_codeverify_uu_id_alter_followers_image_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='followers',
            old_name='phone',
            new_name='phone_number',
        ),
        migrations.AlterField(
            model_name='codeverify',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('b670ea78-7ce8-48e2-b056-9fdd4930e56e'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='followers',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('b670ea78-7ce8-48e2-b056-9fdd4930e56e'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]
