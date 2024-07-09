import uuid
from datetime import datetime, timedelta
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.core.exceptions import ValidationError
import random
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from shared_app.models import BaseModel

# Create your models here.

ORDINARY_USER, ADMIN, MANAGER = ('ordinary_user', 'admin', 'manager')
VIA_EMAIL, VIA_PHONE = ('via_email', 'via_phone')
NEW, CONFIRM, DONE, DONE_PHOTO = ('new', 'confirm', 'done', 'done_photo')
MALE, FEMALE = ('male', 'female')


def FileSizeValidator(value):
    limit = 2 * 1024 * 1024
    if value.size > limit:
        raise ValidationError('File size should not be over 2 MB!')


class Followers(AbstractUser, BaseModel):
    USER_ROLES = (
        (ORDINARY_USER, ORDINARY_USER),
        (ADMIN, ADMIN),
        (MANAGER, MANAGER)
    )
    AUTH_TYPES = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE)
    )
    USER_STATUS = (
        (NEW, NEW),
        (CONFIRM, CONFIRM),
        (DONE, DONE),
        (DONE_PHOTO, DONE_PHOTO)
    )
    GENDER = (
        (MALE, MALE),
        (FEMALE, FEMALE)
    )

    user_role = models.CharField(max_length=64, choices=USER_ROLES, default=ORDINARY_USER)
    auth_type = models.CharField(max_length=64, choices=AUTH_TYPES)
    user_status = models.CharField(max_length=64, choices=USER_STATUS)
    gender = models.CharField(max_length=32, choices=GENDER)
    email = models.EmailField(max_length=50, unique=True, blank=True, null=True)
    phone_number = models.CharField(max_length=50, unique=True, blank=True, null=True)
    image = models.ImageField(upload_to='images/', default='default.png')


    def __str__(self):
        return f'{self.username} - {self.user_role}'

    @property
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    def create_verify_code(self, verify_type):
        code = "".join([str(random.randint(0, 10000) % 10) for _ in range(4)])
        CodeVerify.objects.create(
            user_id=self.id,
            verify_type=verify_type,
            code=code
        )
        return code

    def username_validate(self):
        if not self.username:
            temp_username = f'social{uuid.uuid4().__str__().split("-")[-1]}'
            while Followers.objects.filter(username=temp_username):
                temp_username = f'{temp_username}{str(random.randint(0, 9))}'
            self.username = temp_username


    def email_validate(self):
        if self.email:
            normalized_email = self.email.lower()
            self.email = normalized_email

    def password_validate(self):
        if not self.password:
            temp_password = f'password_{uuid.uuid4().__str__().split('-')[-2]}'
            self.password = temp_password


    def token(self):
        refresh = RefreshToken.for_user(self)
        return {
            "access": str(refresh.access_token),
            "refresh_token": str(refresh)
        }

    def clean(self):
        self.username_validate()
        self.email_validate()
        self.password_validate()


    def save(self, *args, **kwargs):
        self.clean()
        super(Followers, self).save(*args, **kwargs)





EMAIL_EXPIRE = 2
PHONE_EXPIRE = 2



class CodeVerify(BaseModel):
    VERIFY_TYPE = (
        (VIA_EMAIL, VIA_EMAIL),
        (VIA_PHONE, VIA_PHONE)
    )
    code = models.CharField(max_length=4)
    verify_type = models.CharField(max_length=50, choices=VERIFY_TYPE)
    is_confirm = models.BooleanField(default=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='code_verifications')
    expire_time = models.DateTimeField(null=True)

    class Meta:
        db_table = 'code_verify'

    def __str__(self):
        return f'{self.user} - {self.code}'

    def save(self, *args, **kwargs):
        if self.verify_type == VIA_EMAIL:
            self.expiration_time = datetime.now() + timedelta(minutes=EMAIL_EXPIRE)
        else:
            self.expiration_time = datetime.now() + timedelta(minutes=PHONE_EXPIRE)
        super(CodeVerify, self).save(*args, **kwargs)
