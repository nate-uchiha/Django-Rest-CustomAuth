from django.db import models
from django.db.models.signals import post_save
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin, AbstractBaseUser, BaseUserManager
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _


from phonenumber_field.modelfields import PhoneNumberField

# Create your models here.

class CustomUserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None):
        if not email:
            raise ValueError("Users must have an Email Address")
        user = self.model(
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password=None):
        user = self.create_user(
            email, 
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        user.is_admin = True
        user.is_superuser = True
        user.is_active = True
        user.is_email_verified = True
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
            verbose_name='email_address', max_length=255, unique=True
        )
    first_name = models.CharField(_("First Name"), max_length=30)
    last_name = models.CharField(_("Last Name"), max_length=30)
    phone_number = PhoneNumberField(_("Contact Number"), blank=True, null=True, unique=True)
    is_email_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name',]

    def __str__(self):
        return self.email

    def get_full_name(self):
        return "{0} {1}".format(self.first_name, self.last_namex)

    @property
    def is_staff(self):
        return self.is_admin

    class Meta:
        db_table = 'customAuthUser'
        verbose_name = 'Custom Auth User'
        verbose_name_plural = 'Custom Auth Users'


class Profile(models.Model):
    def upload_avatar(self, filename):
        return 'images/user_{0}/{1}_{2}'.format(self.user.id, timezone.now().timestamp(), filename) 

    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    avatar = models.ImageField(_("Avatar"), upload_to=upload_avatar, blank=True, null=True)

    class Meta:
        db_table = "profile"
        verbose_name = "profile"
        verbose_name_plural = "profiles"

    def __str__(self):
        return self.user.email

@receiver(post_save, sender=CustomUser)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=CustomUser)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
