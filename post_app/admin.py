from django.contrib import admin
from .models import *
# Register your models here.


admin.site.register(Post)
admin.site.register(PostLike)
admin.site.register(Comments)
admin.site.register(CommentsLike)