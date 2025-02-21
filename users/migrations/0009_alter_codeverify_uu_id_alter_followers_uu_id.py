# Generated by Django 5.0.6 on 2024-06-25 22:28

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_alter_codeverify_uu_id_alter_followers_uu_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='codeverify',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('93f9c8ad-a19f-4b94-a6b3-d1d46a893671'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='followers',
            name='uu_id',
            field=models.UUIDField(default=uuid.UUID('93f9c8ad-a19f-4b94-a6b3-d1d46a893671'), editable=False, primary_key=True, serialize=False, unique=True),
        ),
    ]
