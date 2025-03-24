from django.contrib import admin

from .models import Order, SkeletonProduct, User, SkeletonRelease

# Register your models here.
admin.site.register(User)
admin.site.register(Order)
admin.site.register(SkeletonProduct)
admin.site.register(SkeletonRelease)