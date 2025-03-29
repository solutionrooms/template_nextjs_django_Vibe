# Generated by Django 5.0.2 on 2025-03-22 10:48

import django.core.validators
import django.db.models.deletion
import users.models
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Club',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('address', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='CompetitionType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Competition',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('num_players', models.IntegerField()),
                ('parallel_matches', models.IntegerField(default=1)),
                ('max_rounds', models.IntegerField(default=5)),
                ('status', models.CharField(choices=[('open', 'Open'), ('full', 'Full'), ('scheduled', 'Scheduled'), ('in_progress', 'In Progress'), ('completed', 'Completed')], default='open', max_length=20)),
                ('club', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='competitions', to='users.club')),
                ('creator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='competitions', to=settings.AUTH_USER_MODEL)),
                ('competition_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='competitions', to='users.competitiontype')),
            ],
            options={
                'ordering': ['-created_at'],
                'unique_together': {('name', 'club')},
            },
        ),
        migrations.CreateModel(
            name='CompetitionUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('guest_name', models.CharField(blank=True, max_length=50, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('order', models.PositiveIntegerField()),
                ('competition', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='competition_users', to='users.competition')),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='competition_participations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['order'],
                'unique_together': {('competition', 'guest_name'), ('competition', 'user')},
            },
        ),
        migrations.CreateModel(
            name='CompetitionSchedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('round', models.IntegerField()),
                ('sub_round', models.IntegerField(default=1)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('competition', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='schedules', to='users.competition')),
                ('side_1_player_1', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_1_player_1_games', to='users.competitionuser')),
                ('side_1_player_2', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_1_player_2_games', to='users.competitionuser')),
                ('side_1_player_3', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_1_player_3_games', to='users.competitionuser')),
                ('side_1_player_4', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_1_player_4_games', to='users.competitionuser')),
                ('side_2_player_1', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_2_player_1_games', to='users.competitionuser')),
                ('side_2_player_2', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_2_player_2_games', to='users.competitionuser')),
                ('side_2_player_3', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_2_player_3_games', to='users.competitionuser')),
                ('side_2_player_4', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='side_2_player_4_games', to='users.competitionuser')),
            ],
            options={
                'ordering': ['round', 'sub_round', 'created_at'],
                'unique_together': {('competition', 'round', 'sub_round')},
            },
        ),
        migrations.CreateModel(
            name='PasswordResetToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('used', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='password_reset_tokens', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('profile_picture', models.ImageField(blank=True, null=True, upload_to='profile_pictures/', validators=[django.core.validators.FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png']), users.models.validate_image_size])),
                ('postcode', models.CharField(blank=True, max_length=20, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ClubApplication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending', max_length=20)),
                ('message', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('club', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='applications', to='users.club')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='club_applications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
                'unique_together': {('user', 'club')},
            },
        ),
        migrations.CreateModel(
            name='ClubUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_admin', models.BooleanField(default=False)),
                ('club_role', models.CharField(blank=True, choices=[('', 'No Role'), ('President', 'President'), ('Vice-President', 'Vice-President'), ('Treasurer', 'Treasurer'), ('Secretary', 'Secretary')], default='', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_login_at', models.DateTimeField(blank=True, null=True)),
                ('club', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='members', to='users.club')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='club_memberships', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['created_at'],
                'unique_together': {('user', 'club')},
            },
        ),
        migrations.CreateModel(
            name='GameScore',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('side_1_score', models.IntegerField(default=0)),
                ('side_2_score', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('completed', models.BooleanField(default=False)),
                ('schedule', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scores', to='users.competitionschedule')),
            ],
            options={
                'ordering': ['-updated_at'],
                'unique_together': {('schedule',)},
            },
        ),
    ]
