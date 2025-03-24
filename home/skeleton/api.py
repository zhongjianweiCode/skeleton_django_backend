"""
Django API for the fuelassembly application.
This module serves as the main entry point for all API endpoints.
"""

from datetime import datetime, time
import re
from typing import List, Optional
import uuid
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.core.cache import cache
from django.utils import timezone 
from ninja import File, UploadedFile, Router, Schema
from ninja_extra import NinjaExtraAPI, api_controller, route, permissions
from ninja_jwt.authentication import JWTAuth
from ninja_jwt.controller import NinjaJWTDefaultController
from ninja_extra.throttling import UserRateThrottle
from ninja_jwt.tokens import RefreshToken
import pandas as pd
from .models import Order, ReleaseMembership, SkeletonProduct, SkeletonRelease
from .schemas import (
    ImportResultSchema, ReleaseMembershipCreate, SkeletonReleaseCreate, SkeletonReleaseDelete, SkeletonReleaseOut, SkeletonReleaseSchema, SkeletonReleaseUpdate, UserRegistrationIn, RegistrationOut, UserOut,
    MessageOut, ErrorOut, ValidationErrorOut,
    PasswordChangeIn,  TokenSchema, SkeletonProductSchema,
    OrderSchema, CreateOrderSchema, UpdateOrderSchema,
   CreateSkeletonProductSchema,
    UpdateSkeletonProductSchema,
    BatchReleaseMembershipCreate
)
from django.db import transaction
import logging

from django.contrib.auth.models import User
from rest_framework.response import Response
from django.contrib import auth
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from ninja.security import HttpBearer

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.debug('start this program')


User = get_user_model()

class AuthRateThrottle(UserRateThrottle):
    rate = '60/minute'

class BaseController:
    def get_cache_key(self, prefix, id):
        return f"{prefix}:{id}"

api = NinjaExtraAPI()

@api_controller('/auth', tags=['auth'], permissions=[])
class AuthController:
    throttle_classes = [AuthRateThrottle]
    
    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
    @route.post('/register/', response={201: RegistrationOut, 400: ErrorOut, 422: ValidationErrorOut})
    def register_user(self, data: UserRegistrationIn):
        try:
            if User.objects.filter(email=data.email).exists():
                return 400, {"detail": str(_("This email is already in use"))}
            
            validate_password(data.password)
            user = User.objects.create_user(
                email=data.email,
                password=data.password
            )
            
            tokens = self.get_tokens_for_user(user)
            response_data = {
                "user": UserOut(id=str(user.id), email=user.email, is_active=user.is_active),
                "token": tokens,
                "message": str(_("User registered successfully"))
            }
            return 201, response_data
        
        except ValidationError as e:
            return 422, {"detail": [{"loc": ["password"], "msg": str(e)}]}
        except Exception as e:
            return 400, {"detail": str(e)}
    
    @route.post('/login/', response={200: TokenSchema, 400: ErrorOut})
    def login_user(self, request):
        """用户登录"""
        data = request.data
        try:
            user = authenticate(request, username=data['email'], password=data['password'])
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': UserOut(id=str(user.id), email=user.email, is_active=user.is_active)
                })
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @route.post('/change-password/', response={200: MessageOut, 400: ErrorOut, 422: ValidationErrorOut}, auth=JWTAuth())
    def change_password(self, request, data: PasswordChangeIn):
        user = request.user
        print(f"User ID: {user.id}")  # 打印用户ID
        print(f"User Email: {user.email}")  # 打印用户邮箱
        print(f"Old password provided: {data.old_password}")  # 调试日志
        print(f"Password check result: {user.check_password(data.old_password)}")  # 调试日志
        
        if not user.check_password(data.old_password):
            return 400, {"detail": str(_("Old password is incorrect"))}
        
        if data.old_password == data.new_password:
            return 400, {"detail": str(_("New password must be different from old password"))}
        
        try:
            validate_password(data.new_password, user=user)
            user.set_password(data.new_password)
            user.save()
            
            from ninja_jwt.tokens import OutstandingToken
            OutstandingToken.objects.filter(user=user).delete()
            
            return 200, {"message": str(_("Password changed successfully"))}
        except ValidationError as e:
            return 422, {"detail": [{"loc": ["new_password"], "msg": str(e)}]}
        except Exception as e:
            return 400, {"detail": str(e)}

@api_controller('/orders', tags=['orders'], auth=JWTAuth())
class OrderController(BaseController):
    @route.get('/', response={200: List[OrderSchema]})
    def get_all_orders(self):
        return Order.objects.all()
    
    @route.get('/{order_id}/', response={200: OrderSchema, 404: ErrorOut})
    def get_order_by_id(self, order_id: str):
        cache_key = self.get_cache_key('order', order_id)
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return 200, cached_data
            
        try:
            order = get_object_or_404(Order, id=order_id)
            cache.set(cache_key, order, timeout=300)
            return 200, order
        except Order.DoesNotExist:
            return 404, {"detail": str(_("Order not found"))}
    
    @route.post('/', response={201: OrderSchema, 400: ErrorOut, 409: ErrorOut})
    def create_order(self, payload: CreateOrderSchema):
        try:
            # 直接使用验证后的数据创建
            order = Order.objects.create(
                order_name=payload.order_name,
                order_batch=payload.order_batch
            )
            return 201, order

        except IntegrityError as e:
            # 处理数据库唯一性约束冲突
            error_msg = "Database constraint violation"
            if 'order_name' in str(e):
                error_msg = "Order name already exists"
            elif 'order_batch' in str(e):
                error_msg = "Order batch already exists"
            return 409, {"detail": error_msg}

        except ValueError as e:
            # 捕获来自Schema的验证错误
            return 400, {"detail": str(e)}

        except Exception as e:
            # 处理其他意外错误
            return 500, {"detail": "Internal server error"}

    @route.patch('/{order_id}/', response={200: OrderSchema, 400: ErrorOut, 404: ErrorOut})
    def update_order(self, order_id: str, payload: UpdateOrderSchema):
        try:
            order = get_object_or_404(Order, id=order_id)

            # 将当前订单实例添加到验证数据中
            validation_data = payload.model_dump()
            validation_data["_current_order"] = order  # 添加关键上下文
            
            # 执行验证
            validated_data = UpdateOrderSchema(**validation_data).model_dump(exclude_unset=True)


            # 更新字段
            for key, value in validated_data.items():
                if key == "_current_order":
                    continue
                setattr(order, key, value)

            # data = payload.model_dump()
            # for key, value in data.items():
            #     setattr(order, key, value)
            order.full_clean()  # 执行完整的模型验证
            order.save()
            
            cache_key = self.get_cache_key('order', order_id)
            cache.delete(cache_key)
            
            return 200, order
        except ValidationError as e:
            return 400, {"detail": str(e)}
        except Order.DoesNotExist:
            return 404, {"detail": str(_("Order not found"))}
        except Exception as e:
            return 400, {"detail": str(e)}

    @route.delete('/{order_id}/', response={200: MessageOut, 404: ErrorOut, 433: ErrorOut, 500: ErrorOut})
    def delete_order(self, order_id: str):
        try:
            # 验证UUID格式
            uuid.UUID(order_id, version=4)
        except ValueError:
            return 404, {"detail": str(_("Invalid order ID format"))}

        try:
            order = get_object_or_404(Order, id=order_id)
            order.delete()
            
            cache_key = self.get_cache_key('order', order_id)
            cache.delete(cache_key)
            
            return 200, {"message": str(_("Order deleted successfully"))}
        except Order.DoesNotExist:
            return 404, {"detail": str(_("Order not found"))}
        except IntegrityError as e:
            return 423, {"detail": str(_("Related data constraint prevents deletion"))}
        except Exception as e:
            return 500, {"detail": str(_("Internal server error"))}
        
@api_controller('/releases', tags=['Skeleton Releases'], auth=JWTAuth())
class SkeletonReleaseController(BaseController):
    """骨架放行单管理"""
    
    @route.get('/', response={200: List[SkeletonReleaseOut]})
    def list_releases(self, request):
        """获取所有放行单列表"""
        releases = (
            SkeletonRelease.objects
            .prefetch_related('memberships__skeleton')
            .all()
            .order_by('-created_at')
        )
        return 200, releases

    @route.get('/{release_id}/', response={200: SkeletonReleaseOut, 404: ErrorOut})
    def get_release(self, request, release_id: uuid.UUID):
        """获取单个放行单详情"""
        try:
            release = (
                SkeletonRelease.objects
                .prefetch_related('memberships__skeleton')
                .get(id=release_id)
            )
            return 200, release
        except SkeletonRelease.DoesNotExist:
            return 404, {"detail": "Release not found"}

    @route.post('/', response={201: SkeletonReleaseOut, 400: ErrorOut})
    @transaction.atomic
    def create_release(self, request, payload: SkeletonReleaseCreate):
        """创建新的放行单"""
        try:
            # 创建放行单
            release = SkeletonRelease.objects.create(
                release_number=payload.release_number
            )

            # 如果提供了骨架编号，则创建关联
            if payload.skeleton_numbers:
                # 获取所有骨架
                skeletons = SkeletonProduct.objects.filter(
                    sk_number__in=payload.skeleton_numbers
                )

                # 创建关联
                memberships = [
                    ReleaseMembership(release=release, skeleton=skeleton)
                    for skeleton in skeletons
                ]
                ReleaseMembership.objects.bulk_create(memberships)

            # 重新获取包含关联数据的放行单
            release = SkeletonRelease.objects.prefetch_related(
                'memberships__skeleton'
            ).get(id=release.id)

            return 201, release
        except IntegrityError:
            return 400, {"detail": "Release number already exists"}
        except ValidationError as e:
            return 400, {"detail": str(e)}

    @route.patch('/{release_id}/', response={200: SkeletonReleaseOut, 404: ErrorOut})
    def update_release(self, request, release_id: uuid.UUID, payload: SkeletonReleaseUpdate):
        """更新放行单信息"""
        try:
            release = SkeletonRelease.objects.get(id=release_id)
            
            if payload.release_number:
                if SkeletonRelease.objects.filter(
                    release_number=payload.release_number
                ).exclude(id=release_id).exists():
                    return 400, {"detail": "Release number already exists"}
                release.release_number = payload.release_number
            
            release.save()
            
            # 重新获取更新后的数据
            release = SkeletonRelease.objects.prefetch_related(
                'memberships__skeleton'
            ).get(id=release_id)
            
            return 200, release
        except SkeletonRelease.DoesNotExist:
            return 404, {"detail": "Release not found"}
        except ValidationError as e:
            return 400, {"detail": str(e)}

    @route.delete('/{release_id}/', response={200: MessageOut, 404: ErrorOut})
    @transaction.atomic
    def delete_release(self, request, release_id: uuid.UUID, payload: SkeletonReleaseDelete):
        """删除放行单"""
        if not payload.confirm:
            return 400, {"detail": "Deletion must be confirmed"}

        try:
            release = SkeletonRelease.objects.get(id=release_id)
            release_number = release.release_number
            release.delete()
            return 200, {"message": f"Release {release_number} deleted successfully"}
        except SkeletonRelease.DoesNotExist:
            return 404, {"detail": "Release not found"}

    @route.post('/{release_id}/skeletons/', response={201: SkeletonReleaseOut, 404: ErrorOut})
    @transaction.atomic
    def add_skeleton(self, request, release_id: uuid.UUID, payload: ReleaseMembershipCreate):
        """添加骨架到放行单"""
        try:
            release = SkeletonRelease.objects.get(id=release_id)
            skeleton = SkeletonProduct.objects.get(sk_number=payload.skeleton_number)
            
            if ReleaseMembership.objects.filter(skeleton=skeleton).exists():
                return 400, {"detail": "Skeleton already released"}
            
            ReleaseMembership.objects.create(release=release, skeleton=skeleton)
            
            # 重新获取更新后的数据
            release = SkeletonRelease.objects.prefetch_related(
                'memberships__skeleton'
            ).get(id=release_id)
            
            return 201, release
        except SkeletonRelease.DoesNotExist:
            return 404, {"detail": "Release not found"}
        except SkeletonProduct.DoesNotExist:
            return 404, {"detail": "Skeleton not found"}

    @route.delete('/{release_id}/skeletons/{skeleton_number}/', response={200: SkeletonReleaseOut, 404: ErrorOut})
    @transaction.atomic
    def remove_skeleton(self, request, release_id: uuid.UUID, skeleton_number: str):
        """从放行单中移除骨架"""
        try:
            release = SkeletonRelease.objects.get(id=release_id)
            membership = ReleaseMembership.objects.get(
                release=release,
                skeleton__sk_number=skeleton_number
            )
            membership.delete()
            
            # 重新获取更新后的数据
            release = SkeletonRelease.objects.prefetch_related(
                'memberships__skeleton'
            ).get(id=release_id)
            
            return 200, release
        except (SkeletonRelease.DoesNotExist, ReleaseMembership.DoesNotExist):
            return 404, {"detail": "Release or skeleton association not found"}

    

@api_controller('/skeleton', tags=['skeleton'], auth=JWTAuth())
class SkeletonProductController(BaseController):
    @route.get('/', response={200: List[SkeletonProductSchema]})
    def get_all_skeleton_products(self):
        return SkeletonProduct.objects.all()
    
    @route.get('/{sk_id}/', response={200: SkeletonProductSchema, 404: ErrorOut})
    def get_skeleton_product_by_id(self, sk_id: str):
        cache_key = self.get_cache_key('skeleton', sk_id)
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return 200, cached_data
            
        try:
            product = get_object_or_404(SkeletonProduct, id=sk_id)
            cache.set(cache_key, product, timeout=300)
            return 200, product
        except SkeletonProduct.DoesNotExist:
            return 404, {"detail": str(_("Product not found"))}
    
    @route.post('/', response={201: SkeletonProductSchema, 400: ErrorOut, 404: ErrorOut})
    def create_skeleton_product(self, payload: CreateSkeletonProductSchema):
        try:
            data = payload.model_dump()
            sk_number = data['sk_number']
            order_id = data.pop('order_id')

            # 处理创建时间
            created_at_str = data.pop('created_at')  # 从data中移除created_at
            try:
                # 将日期字符串转换为datetime对象，设置时间为00:00:00
                created_date = datetime.strptime(created_at_str, '%Y-%m-%d').date()
                created_at = datetime.combine(created_date, time())
            except ValueError:
                return 400, {"detail": "Invalid date format. Expected YYYY-MM-DD"}
            
            # 检查编号是否已存在
            if SkeletonProduct.objects.filter(sk_number=sk_number).exists():
                return 400, {"detail": str(_("Skeleton number already exists"))}
            
            # # 获取关联的 Order
            # order = get_object_or_404(Order, id=order_id)

            # 获取关联的 Order
            try:
                order = get_object_or_404(Order, id=order_id)
            except Order.DoesNotExist:
                return 404, {"detail": "This order does not exist"}
            
            # sk_product = SkeletonProduct.objects.create(**data)

            # 创建骨架产品实例
            # x 和 y 值会在 save() 时自动计算
            # sk_product = SkeletonProduct(order=order, **data)
            # 创建骨架产品实例
            sk_product = SkeletonProduct(
                order=order,
                created_at=created_at,  # 设置手动指定的创建时间
                **data
            )
            # sk_product.full_clean()
            # 验证数据
            try:
                sk_product.full_clean()
            except ValidationError as e:
                return 400, {"detail": str(e)}
            sk_product.save()  # 这里会触发 calculate_xy

            return 201, sk_product        
        
        except IntegrityError as e:
            return 400, {"detail": "The data is not valid"}
        except Exception as e:
            return 400, {"detail": str(e)}

    @route.patch('/{sk_id}/', response={200: SkeletonProductSchema, 400: ErrorOut, 404: ErrorOut})
    def update_skeleton_product(self, sk_id: str, payload: UpdateSkeletonProductSchema):
        try:
            product = get_object_or_404(
                SkeletonProduct,
                id=sk_id
            )
            # data = payload.model_dump()
            # for key, value in data.items():
            #     setattr(product, key, value)
            # product.save()

            data = payload.model_dump(exclude_unset=True)  # 只获取实际传递的字段
        
            # 处理新 Order 关联
            order_id = data.pop("order_id", None)
            if order_id:
                new_order = get_object_or_404(Order, id=order_id)
                product.order = new_order

            # 处理创建时间
            if 'created_at' in data:  # 检查是否有created_at字段
                created_at_str = data.pop('created_at')
                try:
                    # 将日期字符串转换为datetime对象，设置时间为00:00:00
                    created_date = datetime.strptime(created_at_str, '%Y-%m-%d').date()
                    created_at = datetime.combine(created_date, time())
                    product.created_at = created_at  # 设置新的创建时间
                except ValueError as e:
                    return 400, {"detail": f"Invalid date format. Expected YYYY-MM-DD: {str(e)}"}
            
            # 2. 更新 SkeletonProduct 自身字段
            for key, value in data.items():
                setattr(product, key, value)
            product.save()
            
            cache_key = self.get_cache_key('skeleton', sk_id)
            cache.delete(cache_key)
            
            return 200, product
        except SkeletonProduct.DoesNotExist:
            return 404, {"detail": _("Product not found")}
        except Exception as e:
            return 400, {"detail": str(e)}

    @route.delete('/{sk_id}/', response={200: MessageOut, 404: ErrorOut})
    def delete_skeleton_product(self, sk_id: str):
        try:
            product = get_object_or_404(
                SkeletonProduct,
                id=sk_id,
            )
            product.delete()
            
            cache_key = self.get_cache_key('skeleton', sk_id)
            cache.delete(cache_key)
            
            return 200, {"message": str(_("Skeleton product deleted successfully"))}
        except SkeletonProduct.DoesNotExist:
            return 404, {"detail": str(_("Product not found"))}       
       
    
@api_controller('/skeletons/', tags=['skeletons import'], auth=JWTAuth())
class SkeletonImportController(BaseController):
    def clean_order_batch(self, order_value: str) -> str:
        """
        清理订单批次号的辅助函数
        """
        if not order_value:
            return order_value
        
        # 转换为字符串并清理
        order_value = str(order_value)
        
        # 移除所有可能的特殊字符
        order_value = order_value.replace('#', '')  # 移除 '#' 符号
        order_value = order_value.replace('＃', '')  # 移除全角 '#' 符号
        order_value = order_value.replace('批', '')  # 移除 '批' 字
        order_value = order_value.replace('号', '')  # 移除 '号' 字
        
        # 移除所有空白字符
        order_value = ''.join(order_value.split())
        
        # 如果需要，可以添加其他清理规则
        
        return order_value

    def process_leg_length(self, value) -> Optional[float]:
        """
        处理腿长数据的辅助函数
        - 如果值为空（nan, None, 空字符串等），返回 None
        - 如果是有效数值，返回浮点数
        - 如果转换失败，抛出 ValidationError
        """
        if pd.isna(value) or value == '' or value is None:
            return None
        
        try:
            # 尝试转换为浮点数
            value = float(value)
            # 可以添加数值验证（如果需要）
            if value < -136.0:
                raise ValidationError("Leg length cannot be less than -136.0")
            return value
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid leg length value: {value}")
    @route.post('/import/', response={201: ImportResultSchema, 400: ErrorOut})
    def import_skeleton_products(self, request, file: UploadedFile = File(...)):
        """
        Import skeletons products from Excel file
        """
        if not file:
            return 400, {"detail": "No file provided"}
        
        try:
            # 读取Excel文件
            df = pd.read_excel(
                file.file,
                usecols=[
                    "SK_ID", "Rb", "flatness", "length",
                    "platform", "order", "Leg-1", "Leg-2", 
                    "Leg-3", "Leg-4", "date"
                ],
                dtype={
                    "SK_ID": str,
                    "order": str,
                    "platform": str
                }
            )

            # 数据预处理
            df = df.rename(columns={
                "SK_ID": "sk_number",
                "Rb": "perpendiculartity",
                "Leg-1": "leg1_length",
                "Leg-2": "leg2_length",
                "Leg-3": "leg3_length",
                "Leg-4": "leg4_length",
                "date": "created_at"
            })

            # 验证数据
            if df.empty:
                return 400, {"detail": "Excel file is empty"}

            required_columns = ["sk_number", "perpendiculartity", "flatness", "length", "platform"]
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                return 400, {"detail": f"Missing required columns: {', '.join(missing_columns)}"}

            success_count = 0
            error_count = 0
            errors = []

            # 处理数据
            with transaction.atomic():
                for index, row in df.iterrows():
                    try:
                        # 基本数据验证
                        if not row['sk_number'].startswith('GRH'):
                            raise ValidationError(f"Row {index + 2}: Skeleton number must start with GRH")

                        # 准备基础数据
                        skeleton_data = {
                            'sk_number': row['sk_number'],
                            'perpendiculartity': float(row['perpendiculartity']),
                            'flatness': float(row['flatness']),
                            'length': float(row['length']),
                            'platform': row['platform'],
                            'status': 'Used',  # 默认状态
                            'type': 'AFA3G_AA'  # 默认类型
                        }

                        # 处理可选的 leg 长度
                        # leg_lengths = ['leg1_length', 'leg2_length', 'leg3_length', 'leg4_length']
                        # if all(leg in row for leg in leg_lengths):
                        #     for leg in leg_lengths:
                        #         if pd.notna(row[leg]):
                        #             skeleton_data[leg] = float(row[leg]) if row[leg].isdigit() else None
                        leg_fields = ['leg1_length', 'leg2_length', 'leg3_length', 'leg4_length']
                        for field in leg_fields:
                            try:
                                value = self.process_leg_length(row.get(field))
                                if value is not None:
                                    skeleton_data[field] = value
                                # 如果值为 None，且字段允许为空，不添加到 skeleton_data 中
                                # 如果字段不允许为空，设置默认值
                                elif not SkeletonProduct._meta.get_field(field).null:
                                    skeleton_data[field] = -135  # 设置默认值为 135
                            except ValidationError as e:
                                raise ValidationError(f"Error in {field} at row {index + 2}: {str(e)}")


                        # 处理 order 关联
                        if pd.notna(row['order']):
                            # try:
                            #     # 尝试查找订单
                            #     order = Order.objects.get(order_batch=str(row['order']))
                            #     skeleton_data['order'] = order
                            # except Order.DoesNotExist:
                            #     raise ValidationError(f"Order with batch number {row['order']} does not exist")
                            try:
                                # 清理并获取 order_batch
                                order_batch = self.clean_order_batch(row['order'])
                                if not order_batch:
                                    raise ValidationError(f"Empty order batch number after cleaning in row {index + 2}")

                                try:
                                    # 尝试查找订单
                                    order = Order.objects.get(order_batch=order_batch)
                                    skeleton_data['order'] = order
                                except Order.DoesNotExist:
                                    raise ValidationError(
                                        f"Order with batch number {order_batch} does not exist "
                                        f"(original value: {row['order']})"
                                    )
                            except Exception as e:
                                raise ValidationError(f"Error processing order in row {index + 2}: {str(e)}")

                        # 处理创建时间
                        if 'created_at' in row and pd.notna(row['created_at']):
                            try:
                                date_str = str(row['created_at'])
                                try:
                                    # 尝试 DD.MM.YYYY 格式
                                    date_obj = datetime.strptime(date_str, '%d.%m.%Y')
                                except ValueError:
                                    try:
                                        # 尝试 YYYY-MM-DD 格式
                                        date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                                    except ValueError:
                                        try:
                                            # 尝试 DD/MM/YYYY格式
                                            date_obj = datetime.strptime(date_str, '%d/%m/%Y')
                                        except ValueError:
                                            # 如果是 pandas Timestamp，转换为 datetime
                                            if isinstance(row['created_at'], pd.Timestamp):
                                                date_obj = row['created_at'].to_pydatetime()
                                            else:
                                                raise ValueError(f"Unsupported date format: {date_str}")
                                
                                # 设置时间为当天的开始时间并添加时区信息
                                date_obj = date_obj.replace(hour=0, minute=0, second=0, microsecond=0)
                                skeleton_data['created_at'] = timezone.make_aware(date_obj)
                            except Exception as e:
                                raise ValidationError(f"Invalid date format in row {index + 2}: {str(e)}")
                        else:
                            skeleton_data['created_at'] = timezone.now()

                        # 创建骨架产品
                        skeleton = SkeletonProduct(**skeleton_data)
                        skeleton.full_clean()  # 验证所有字段
                        skeleton.save()
                        success_count += 1

                    except ValidationError as e:
                        if hasattr(e, 'message_dict'):
                            error_msg = f"Row {index + 2}: {'; '.join([f'{k}: {v[0]}' for k, v in e.message_dict.items()])}"
                        else:
                            error_msg = f"Row {index + 2}: {str(e)}"
                        errors.append(error_msg)
                        error_count += 1
                        logging.error(f"Validation error in row {index + 2}: {str(e)}")
                    except Exception as e:
                        error_msg = f"Row {index + 2}: {str(e)}"
                        errors.append(error_msg)
                        error_count += 1
                        logging.error(f"Error processing row {index + 2}: {str(e)}", exc_info=True)

        except Exception as e:
            logging.error(f"Error processing file: {str(e)}", exc_info=True)
            return 400, {"detail": f"Error processing file: {str(e)}"}

        # 返回结果
        return 201, {
            "success_count": success_count,
            "error_count": error_count,
            "errors": errors
        }
    
@api_controller('/batch_releases', tags=['Skeleton Batch Releases'], auth=JWTAuth())
class SkeletonBatchReleaseController(BaseController):
    @route.post('/{release_id}/', response={201: SkeletonReleaseOut, 404: ErrorOut})
    @transaction.atomic
    def add_skeletons_batch(self, request, release_id: uuid.UUID, payload: BatchReleaseMembershipCreate):
        """批量添加骨架到放行单"""
        try:
            release = SkeletonRelease.objects.get(id=release_id)
            
            # 获取所有骨架
            skeletons = SkeletonProduct.objects.filter(
                sk_number__in=payload.skeleton_numbers
            )
            
            # 验证是否所有骨架都存在
            found_numbers = set(skeleton.sk_number for skeleton in skeletons)
            missing_numbers = set(payload.skeleton_numbers) - found_numbers
            if missing_numbers:
                return 400, {"detail": f"The following skeletons do not exist: {', '.join(missing_numbers)}"}
            
            # 验证骨架是否已被关联
            already_released = list(ReleaseMembership.objects.filter(
                skeleton__in=skeletons
            ).values_list('skeleton__sk_number', 'release__release_number'))
            
            if already_released:
                error_messages = [
                    f"{sk_num} (already exists in {rel_num})"
                    for sk_num, rel_num in already_released
                ]
                return 400, {"detail": f"The following skeletons are already released: {', '.join(error_messages)}"}
            
            # 批量创建关联
            memberships = [
                ReleaseMembership(release=release, skeleton=skeleton)
                for skeleton in skeletons
            ]
            ReleaseMembership.objects.bulk_create(memberships)
            
            # 重新获取更新后的数据
            release = SkeletonRelease.objects.prefetch_related(
                'memberships__skeleton'
            ).get(id=release_id)
            
            return 201, release
        except SkeletonRelease.DoesNotExist:
            return 404, {"detail": "Release not found"}
    

api.register_controllers(
    AuthController,
    OrderController,
    SkeletonProductController,
    NinjaJWTDefaultController,
    SkeletonImportController,
    SkeletonReleaseController,
    SkeletonBatchReleaseController
)

