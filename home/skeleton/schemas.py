from datetime import datetime
from uuid import UUID
import uuid
from ninja import ModelSchema, Schema
from pydantic import ConfigDict, EmailStr, field_validator, Field, model_validator, BaseModel
from typing import List, Dict, Any, Annotated, Optional
from .models import Order, ReleaseMembership, SkeletonProduct, User, SkeletonRelease
import re
from django.utils.translation import gettext_lazy as _

class UserSchema(ModelSchema):
    class Meta:
        model = User
        fields = ['id', 'email', 'is_active']

class UserRegistrationIn(Schema):
    """简化的用户注册输入模式"""
    email: str
    password: str
    confirm_password: str
    
    @model_validator(mode='after')
    def passwords_match(self) -> 'UserRegistrationIn':
        if self.password != self.confirm_password:
            raise ValueError(_('Passwords do not match'))
        return self

    @field_validator('email')
    def validate_email(cls, v: str) -> str:
        # 确保邮箱不为空
        if not v:
            raise ValueError(_('Email address is required'))
        
        # 转换为小写
        v = v.lower().strip()
        
        # 基本格式验证
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError(_('Invalid email format'))
        
        # 检查邮箱长度
        if len(v) > 254:  # RFC 5321
            raise ValueError(_('Email address is too long'))
        
        # 检查用户名部分长度
        local_part = v.split('@')[0]
        if len(local_part) > 64:  # RFC 5321
            raise ValueError(_('Email username is too long'))
        
        # 检查特殊字符
        if re.search(r'[<>()[\]\\,;:\s]', v):
            raise ValueError(_('Email contains invalid characters'))
        
        # 检查连续的点
        if '..' in v:
            raise ValueError(_('Email cannot contain consecutive dots'))
        
        # 检查开头和结尾的点
        if v.startswith('.') or v.endswith('.'):
            raise ValueError(_('Email cannot start or end with a dot'))
        
        # 检查域名部分
        domain = v.split('@')[1]
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            raise ValueError(_('Invalid email domain'))
        
        # 检查域名中的连字符
        if domain.startswith('-') or domain.endswith('-'):
            raise ValueError(_('Domain cannot start or end with a hyphen'))
        
        return v

    @field_validator('password')
    def validate_password(cls, v: str) -> str:
        if not v or len(v) < 8:
            raise ValueError(_('Password must be at least 8 characters long'))
        return v

class TokenSchema(BaseModel):
    access: str
    refresh: str

class UserOut(BaseModel):
    id: str
    email: str
    is_active: bool

class RegistrationOut(Schema):
    """注册响应模式"""
    user: UserOut
    token: TokenSchema
    message: str

class LoginIn(Schema):
    """登录输入模式"""
    email: EmailStr
    password: str

class MessageOut(Schema):
    """消息响应模式"""
    message: str

class ErrorOut(Schema):
    """错误响应模式"""
    detail: str

class ValidationErrorOut(Schema):
    """验证错误响应模式"""
    detail: List[Dict[str, Any]]

class PasswordChangeIn(BaseModel):
    old_password: str
    new_password: str
    confirm_new_password: str

    @model_validator(mode='after')
    def passwords_match(self) -> 'PasswordChangeIn':
        if self.new_password != self.confirm_new_password:
            raise ValueError(_('New passwords do not match'))
        return self   



class OrderSchema(ModelSchema):
    class Meta:
        model = Order
        fields = ['id', 'order_name', 'order_batch', 'created_at', 'updated_at']

class SkeletonProductSchema(ModelSchema):
    order: OrderSchema
    # 新增
    # skeleton_release: SkeletonRelease 
    class Meta:
        model = SkeletonProduct
        fields = [
            'id', 
            'sk_number', 
            'perpendiculartity', 
            'flatness',
            'length',
            'leg1_length',
            'leg2_length',
            'leg3_length',
            'leg4_length',
            'x',
            'y',
            'created_at',
            'updated_at',
            'status',
            'type',
            'platform',
            'created_at',
            'updated_at',
        ]

class CreateOrderSchema(BaseModel):
    order_name: str
    order_batch: str

    @field_validator('order_name')
    def validate_order_name(cls, v):
        """更精确的订单名称验证"""
        if not v.strip():
            raise ValueError("Order name cannot be empty")
        if len(v) > 100:
            raise ValueError("Order name exceeds 100 characters limit")
        if Order.objects.filter(order_name__iexact=v).exists():
            raise ValueError("Order name already exists")
        return v.strip()

    @field_validator('order_batch')
    def validate_order_batch(cls, v):
        """增强批次号验证逻辑"""
        if not v.isalnum():
            raise ValueError("Batch number must be alphanumeric")
        if len(v) > 20:
            raise ValueError("Batch number exceeds 20 characters limit")
        if Order.objects.filter(order_batch__iexact=v).exists():
            raise ValueError("Order batch already exists")
        return v.upper()  # 统一转为大写存储

class UpdateOrderSchema(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    order_name: Optional[str] = None
    order_batch: Optional[str] = None

    @field_validator('order_name')
    def validate_order_name(cls, v, values):
        # 获取通过上下文传递的订单实例
        current_order = values.data.get("_current_order")
        
        if v is not None and current_order:
            # 只在新值不同于原值时验证
            if v != current_order.order_name:
                if Order.objects.filter(order_name=v).exclude(id=current_order.id).exists():
                    raise ValueError("Order name already exists")
        return v

    @field_validator('order_batch')
    def validate_order_batch(cls, v, values):
        current_order = values.data.get("_current_order")
        
        if v is not None and current_order:
            if v != current_order.order_batch:
                if Order.objects.filter(order_batch=v).exclude(id=current_order.id).exists():
                    raise ValueError("Order batch already exists")
        return v

class DeleteOrderSchema(Schema):
    id: str

# 嵌套 Order 的 Schema
class OrderInSchema(BaseModel):
    order_name: str | None = None
    order_batch: str | None = None

class CreateSkeletonProductSchema(Schema):
    sk_number: str = Field(..., pattern=r'^GRH\d{6}$')
    perpendiculartity: Annotated[float, Field(ge=0, le=0.25)] = Field(
        ...,
        description="Perpendicularity measurement (must be between 0 and 0.25)"
    )
    flatness: Annotated[float, Field(ge=0, le=0.15)] = Field(
        ...,
        description="Flatness measurement (must be between 0 and 0.15)"
    )
    length: Annotated[float, Field(ge=3972.5, le=3974.1)] = Field(
        ...,
        description="Length measurement (must be between 3972.5 and 3974.1)"
    )
    leg1_length: Annotated[float, Field(ge=-136.0, le=-130.0)] = Field(
        ...,
        description="Leg1 length measurement (must be between -136.0 and -130.0)"
    )
    leg2_length: Annotated[float, Field(ge=-136.0, le=-130.0)] = Field(
        ...,
        description="Leg2 length measurement (must be between -136.0 and -130.0)"
    )
    leg3_length: Annotated[float, Field(ge=-136.0, le=-130.0)] = Field(
        ...,
        description="Leg3 length measurement (must be between -136.0 and -130.0)"
    )
    leg4_length: Annotated[float, Field(ge=-136.0, le=-130.0)] = Field(
        ...,
        description="Leg4 length measurement (must be between -136.0 and -130.0)"
    )
    order_id: UUID  # 外键字段
    status: str = Field(default=SkeletonProduct.StatusChoices.USED.value)
    type: str = Field(default=SkeletonProduct.TypeChoices.AFA3G_AA.value)
    platform: str = Field(default=SkeletonProduct.PlatformChoices.A.value)
    created_at: str

    @field_validator('sk_number')
    def validate_sk_number(cls, v):
        if not re.match(r'^GRH\d{6}$', v):
            raise ValueError('Skeleton number must start with GRH followed by 6 digits')
        return v
    
    @field_validator('created_at')
    def validate_created_at(cls, v):
        try:
            # 验证日期格式
            datetime.strptime(v, '%Y-%m-%d')
            return v
        except ValueError:
            raise ValueError('Invalid date format. Expected YYYY-MM-DD')

class UpdateSkeletonProductSchema(Schema):
    sk_number: str = Field(None, pattern=r'^GRH\d{6}$')
    perpendiculartity: Annotated[float, Field(ge=0, le=0.25)] = Field(
        ...,
        description="Perpendicularity measurement (must be between 0 and 0.25)"
    )
    flatness: Annotated[float, Field(ge=0, le=0.15)] = Field(
        ...,
        description="Flatness measurement (must be between 0 and 0.15)"
    )
    length: Annotated[float, Field(ge=3972.5, le=3974.1)] = Field(
        ...,
        description="Length measurement (must be between 3972.5 and 3974.1)"
    )
    leg1_length: Annotated[float, Field(ge=-136.0, le=-133.0)] = Field(
        ...,
        description="Leg1 length measurement (must be between -136.0 and -133.0)"
    )
    leg2_length: Annotated[float, Field(ge=-136.0, le=-133.0)] = Field(
        ...,
        description="Leg2 length measurement (must be between -136.0 and -133.0)"
    )
    leg3_length: Annotated[float, Field(ge=-136.0, le=-133.0)] = Field(
        ...,
        description="Leg3 length measurement (must be between -136.0 and -133.0)"
    )
    leg4_length: Annotated[float, Field(ge=-136.0, le=-133.0)] = Field(
        ...,
        description="Leg4 length measurement (must be between -136.0 and -133.0)"
    )
    status: str = 'USED'  # 设置默认值
    type: str
    platform: str
    order_id: UUID | None = None  #
    created_at: str

    @field_validator('sk_number')
    def validate_sk_number(cls, v):
        if v is not None and not re.match(r'^GRH\d{6}$', v):
            raise ValueError('Skeleton number must start with GRH followed by 6 digits')
        return v

class DeleteSkeletonProductSchema(Schema):
    product_id: str


class ImportResultSchema(Schema):
    success_count: int
    error_count: int
    errors: list[str] = [] 



# ================== 骨架放行单 Schemas ==================
class SkeletonReleaseBase(Schema):
    """放行单基础字段"""
    release_number: str = Field(
        ...,
        pattern=r'^\d{2}-\d{2}-\d{2}/\d+$',
        example="23-01-01/001",
        description="release number should be: XX-XX-XX/YYY"
    )

class SkeletonReleaseSchema(ModelSchema):
    """放行单基本信息输出"""
    class Meta:
        model = SkeletonRelease
        fields = ['id', 'release_number', 'created_at', 'updated_at']

class ReleaseMembershipOut(Schema):
    """关联记录输出"""
    id: UUID
    skeleton: str
    added_at: datetime

    model_config = ConfigDict(from_attributes=True)

class SkeletonReleaseOut(Schema):
    """放行单详情输出（包含关联骨架）"""
    id: UUID
    release_number: str
    created_at: datetime
    updated_at: datetime
    memberships: List[Dict[str, Any]] = Field(
        default=[],
        description="related skeleton lists"
    )

    @staticmethod
    def resolve_memberships(obj):
        return [
            {
                "id": str(membership.id),
                "skeleton": membership.skeleton.sk_number,
                "added_at": membership.added_at
            }
            for membership in obj.memberships.select_related('skeleton').all()
        ]

    model_config = ConfigDict(from_attributes=True)

class SkeletonReleaseCreate(Schema):
    """创建放行单输入"""
    release_number: str = Field(
        ...,
        pattern=r'^\d{2}-\d{2}-\d{2}/\d+$',
        example="23-01-01/001"
    )
    skeleton_numbers: Optional[List[str]] = Field(
        default=None,
        example=["GRH123456", "GRH654321"],
        description="需要关联的骨架编号列表（可选）"
    )

    @field_validator('release_number')
    def validate_release_number(cls, v):
        if not re.match(r'^\d{2}-\d{2}-\d{2}/\d+$', v):
            raise ValueError("Release number format must be XX-XX-XX/YYY")
        if SkeletonRelease.objects.filter(release_number=v).exists():
            raise ValueError("Release number already exists")
        return v

    @field_validator('skeleton_numbers')
    def validate_skeletons(cls, v):
        if v is None:
            return v
            
        # 验证所有骨架编号是否存在
        existing_skeletons = set(SkeletonProduct.objects.filter(
            sk_number__in=v
        ).values_list('sk_number', flat=True))
        
        missing_skeletons = set(v) - existing_skeletons
        if missing_skeletons:
            raise ValueError(f"Skeletons not found: {', '.join(missing_skeletons)}")
        
        # 验证骨架是否已被其他放行单关联
        already_released = list(ReleaseMembership.objects.filter(
            skeleton__sk_number__in=v
        ).select_related('release', 'skeleton').values_list(
            'skeleton__sk_number', 'release__release_number'
        ))
        
        if already_released:
            error_messages = [
                f"{sk_num} (already exist in {rel_num}.)"
                for sk_num, rel_num in already_released
            ]
            raise ValueError(f"以下骨架已被关联: {', '.join(error_messages)}")
        
        return v

class SkeletonReleaseUpdate(Schema):
    """更新放行单信息"""
    release_number: Optional[str] = Field(
        None,
        pattern=r'^\d{2}-\d{2}-\d{2}/\d+$',
        example="23-01-01/002"
    )

    @field_validator('release_number')
    def validate_release_number(cls, v, values):
        if v is None:
            return v
        if not re.match(r'^\d{2}-\d{2}-\d{2}/\d+$', v):
            raise ValueError("Release number format must be XX-XX-XX/YYY")
        return v

class ReleaseMembershipCreate(Schema):
    """添加单个骨架到放行单"""
    skeleton_number: str = Field(
        ...,
        pattern=r'^GRH\d{6}$',
        description="related skeleton numbers"
    )

    @field_validator('skeleton_number')
    def validate_skeleton(cls, v):
        try:
            skeleton = SkeletonProduct.objects.get(sk_number=v)
            if ReleaseMembership.objects.filter(skeleton=skeleton).exists():
                raise ValueError(f"This {v} already exist in other release sheet")
            return v
        except SkeletonProduct.DoesNotExist:
            raise ValueError(f"This skeleton {v} not exist.")

class BatchReleaseMembershipCreate(Schema):
    """批量添加骨架到放行单"""
    skeleton_numbers: List[str] = Field(
        ...,
        min_items=1,
        description="related skeletons lists"
    )

    @field_validator('skeleton_numbers')
    def validate_skeletons(cls, v):
        # 验证所有骨架编号格式
        for skeleton_number in v:
            if not re.match(r'^GRH\d{6}$', skeleton_number):
                raise ValueError(f"The number of {skeleton_number} is wrong. Need starts with GRH, and 6 numbers")

        # 验证所有骨架编号是否存在
        existing_skeletons = set(SkeletonProduct.objects.filter(
            sk_number__in=v
        ).values_list('sk_number', flat=True))
        
        missing_skeletons = set(v) - existing_skeletons
        if missing_skeletons:
            raise ValueError(f"Thess: {', '.join(missing_skeletons)} skeleton does not exist.")
        
        # 验证骨架是否已被其他放行单关联
        already_released = list(ReleaseMembership.objects.filter(
            skeleton__sk_number__in=v
        ).select_related('release', 'skeleton').values_list(
            'skeleton__sk_number', 'release__release_number'
        ))
        
        if already_released:
            error_messages = [
                f"{sk_num} (already in {rel_num}.)"
                for sk_num, rel_num in already_released
            ]
            raise ValueError(f"The follow skeletons already have release number: {', '.join(error_messages)}")
        
        return v

class SkeletonReleaseDelete(Schema):
    """删除放行单"""
    confirm: bool = Field(
        True,
        description="Should be True and then operate"
    )

