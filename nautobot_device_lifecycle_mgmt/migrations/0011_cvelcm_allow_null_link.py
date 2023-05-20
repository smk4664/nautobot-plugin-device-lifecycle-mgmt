# Generated by Django 3.2.16 on 2023-05-19 21:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('nautobot_device_lifecycle_mgmt', '0010_softwareimagelcm_hash_algorithm'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cvelcm',
            name='link',
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='cvelcm',
            name='published_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
