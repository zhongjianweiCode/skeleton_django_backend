import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.core.exceptions import ValidationError

class UserManager(BaseUserManager):
    """自定义用户管理器"""
    def create_user(self, email, password=None, **extra_fields):
        """创建并保存一个带有给定电子邮件和密码的用户"""
        if not email:
            raise ValueError(_('the Email field is required.'))
        email = self.normalize_email(email)
        extra_fields.setdefault('username', email)  # 使用 email 作为 username
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """创建并保存一个超级用户"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('superuser must set is_staff to be True'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('superuser must set the is_superuser to be True'))
        return self.create_user(email, password, **extra_fields)

class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()
    
    def __str__(self):
        return self.email

class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order_name = models.CharField(
        max_length=100,
        unique=True,
        db_index=True  # 添加索引提升查询性能
    )
    order_batch = models.CharField(
        max_length=20, 
        unique=True,
        null=True,  # 允许数据库NULL
        blank=True,  # 允许表单空值
        db_index=True,
        validators=[
            RegexValidator(
                regex='^[a-zA-Z0-9]*$',
                message='Batch number must be alphanumeric'
            )
        ]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.order_name} - {self.order_batch}"
    
    class Meta:
        ordering = ['-created_at']

class SkeletonProduct(models.Model):
    class StatusChoices(models.TextChoices):
        CMM_CHECKED= 'CMM', _('CMM checked')
        LABORATORY_CHECKING = 'Laboratory', _('Laboratory Checking')
        CUSTOMER_CHECKING = 'Customer', _('Customer Checking')
        QC_RELEASED = 'Released', _('QC Released')
        REJECTED = 'Rejected', _('Rejected')
        USED = 'Used', _('Used')

    class TypeChoices(models.TextChoices):
        AFA3G_AA = 'AFA3G_AA', _('AFA3G_AA_M5')
        AFA3G_A = 'AFA3G_A', _('AFA3G_A_Zry4')

    class PlatformChoices(models.TextChoices):
        A = 'A', _('A')
        B = 'B', _('B')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sk_number = models.CharField(
        max_length=9,
        unique=True,
        help_text=_('Skeleton product number (Format: GRH followed by 6 digits)'),
        validators=[
            RegexValidator(
                regex=r'^GRH\d{6}$',
                message=_('Skeleton number must start with GRH followed by 6 digits'),
                code='invalid_sk_number'
            )
        ]
    )
    perpendiculartity = models.FloatField(
        help_text=_('Rb measurement (0-0.25)'),
        validators=[
            MinValueValidator(0.0, message=_('Value must be greater than or equal to 0')),
            MaxValueValidator(0.25, message=_('Value must be less than or equal to 0.25'))
        ]
    )
    flatness = models.FloatField(
        help_text=_('flatness measurement (0-0.15)'),
        validators=[
            MinValueValidator(0.0, message=_('Value must be greater than or equal to 0')),
            MaxValueValidator(0.15, message=_('Value must be less than or equal to 0.15'))
        ]
    )
    length = models.FloatField(
        help_text=_('length measurement (3972.5-3974.1)'),
        validators=[
            MinValueValidator(3972.5, message=_('Value must be greater than or equal to 3972.5')),
            MaxValueValidator(3974.1, message=_('Value must be less than or equal to 3974.1'))
        ]
    )
    leg1_length = models.FloatField(
        help_text=_('leg1 length measurement (-136.0:-130.0)'),
        validators=[
            MinValueValidator(-136.0, message=_('Value must be greater than or equal to -136.0')),
            MaxValueValidator(-130.0, message=_('Value must be less than or equal to -130.0'))
        ],
        null=True
    )
    leg2_length = models.FloatField(
        help_text=_('leg2 length measurement (-136.0:-130.0)'),
        validators=[
            MinValueValidator(-136.0, message=_('Value must be greater than or equal to -136.0')),
            MaxValueValidator(-130.0, message=_('Value must be less than or equal to -130.0'))
        ],
        null=True
    )
    leg3_length = models.FloatField(
        help_text=_('leg3 length measurement (-136.0:-130.0)'),
        validators=[
            MinValueValidator(-136.0, message=_('Value must be greater than or equal to -136.0')),
            MaxValueValidator(-130.0, message=_('Value must be less than or equal to -130.0'))
        ],
        null=True
    )
    leg4_length = models.FloatField(
        help_text=_('leg4 length measurement (-136.0:-130.0)'),
        validators=[
            MinValueValidator(-136.0, message=_('Value must be greater than or equal to -136.0')),
            MaxValueValidator(-130.0, message=_('Value must be less than or equal to -130.0'))
        ],
        null=True
    )
    x = models.FloatField(blank=True, null=True)
    y = models.FloatField(blank=True, null=True)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    status = models.CharField(
        max_length=20,
        choices=StatusChoices.choices,
        default=StatusChoices.USED
    )
    type = models.CharField(
        max_length=20,
        choices=TypeChoices.choices,
        default=TypeChoices.AFA3G_AA
    )
    platform = models.CharField(
        max_length=20,
        choices=PlatformChoices.choices,
        default=PlatformChoices.A
    )
    
    def __str__(self):
        return f"{self.sk_number}"
    
    class Meta:
        ordering = ['-created_at']
        
    def calculate_xy(self):
        """计算 x 和 y 值"""
        if all(value is not None for value in [
            self.leg1_length, self.leg2_length, 
            self.leg3_length, self.leg4_length
        ]):
            self.x = round(
                ((self.leg4_length + self.leg1_length) / 2 - 
                 (self.leg2_length + self.leg3_length) / 2) * 20, 
                3
            )
            self.y = round(
                ((self.leg4_length + self.leg3_length) / 2 - 
                 (self.leg2_length + self.leg1_length) / 2) * 20, 
                3
            )
    
    def save(self, *args, **kwargs):
        self.full_clean()  # 验证数据
        self.calculate_xy()  # 计算 x 和 y 值
        super().save(*args, **kwargs)
    
    def clean(self):
        super().clean()
        # 验证 sk_number
        if self.sk_number and not self.sk_number.startswith('GRH'):
            raise ValidationError({
                'sk_number': str(_('Skeleton number must start with GRH'))
            })
        
        if self.sk_number:
            number_part = self.sk_number[3:]
            if not (len(number_part) == 6 and number_part.isdigit()):
                raise ValidationError({
                    'sk_number': str(_('Skeleton number must have exactly 6 digits after GRH'))
                })
        
        # 验证所有 leg_length 值都存在或都不存在
        leg_lengths = [
            self.leg1_length, self.leg2_length, 
            self.leg3_length, self.leg4_length
        ]
        if any(leg_lengths) and not all(leg_lengths):
            raise ValidationError({
                'leg_length': str(_('All leg length values must be provided together'))
            })

class SkeletonRelease(models.Model):
    """骨架放行单模型"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    release_number = models.CharField(
        max_length=100,
        unique=True,
        verbose_name=_('Release Number'),
        help_text=_('Format: XX-XX-XX/YYY')
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    skeletons = models.ManyToManyField(
        SkeletonProduct,
        through='ReleaseMembership',
        related_name='releases',
        verbose_name=_('Released Skeletons')
    )

    def __str__(self):
        return f"{self.release_number}"
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = _('Skeleton Release')
        verbose_name_plural = _('Skeleton Releases')

class ReleaseMembership(models.Model):
    """放行单-骨架关联中间模型"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    release = models.ForeignKey(
        SkeletonRelease,
        on_delete=models.CASCADE,
        related_name='memberships',
        verbose_name=_('Release')
    )
    skeleton = models.OneToOneField(
        SkeletonProduct,
        on_delete=models.CASCADE,
        related_name='release_membership',
        verbose_name=_('Skeleton')
    )
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _('Release Membership')
        verbose_name_plural = _('Release Memberships')
        unique_together = ['release', 'skeleton']

    def __str__(self):
        return f"{self.release.release_number} - {self.skeleton.sk_number}"