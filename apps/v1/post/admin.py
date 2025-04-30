from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from apps.v1.shared.admin import BaseAdmin
from .models import Post, PostLike, PostComment, CommentLike

class PostResource(resources.ModelResource):
    class Meta:
        model = Post

class PostCommentResource(resources.ModelResource):
    class Meta:
        model = PostComment

class PostLikeResource(resources.ModelResource):
    class Meta:
        model = PostLike

class CommentLikeResource(resources.ModelResource):
    class Meta:
        model = CommentLike


class PostAdmin(ImportExportModelAdmin, BaseAdmin):
    resource_classes = [PostResource]
    list_display = [f.name for f in Post._meta.fields]
    search_fields = ('id', 'author__username', 'caption')


class PostCommentAdmin(ImportExportModelAdmin, BaseAdmin):
    resource_classes = [PostCommentResource]
    list_display = [f.name for f in PostComment._meta.fields]
    search_fields = ('id', 'author__username', 'comment')


class PostLikeAdmin(ImportExportModelAdmin, BaseAdmin):
    resource_classes = [PostLikeResource]
    list_display = [f.name for f in PostLike._meta.fields]
    search_fields = ('id', 'author__username')


class CommentLikeAdmin(ImportExportModelAdmin, BaseAdmin):
    resource_classes = [CommentLikeResource]
    list_display = [f.name for f in CommentLike._meta.fields]
    search_fields = ('id', 'author__username')


admin.site.register(Post, PostAdmin)
admin.site.register(PostComment, PostCommentAdmin)
admin.site.register(PostLike, PostLikeAdmin)
admin.site.register(CommentLike, CommentLikeAdmin)

