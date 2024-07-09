from django.db import models
from django.core.validators import FileExtensionValidator, MaxLengthValidator
from django.contrib.auth import get_user_model
from django.db.models import UniqueConstraint
from shared_app.models import BaseModel
from users.models import Followers
# Create your models here.


User = get_user_model()

class Post(BaseModel):
    author = models.ForeignKey(Followers, on_delete=models.CASCADE, related_name='posts')
    image = models.ImageField(upload_to='post_images', validators=[
        FileExtensionValidator(allowed_extensions=['jpeg', 'jpg', 'png'])
    ])
    body = models.TextField(validators=[MaxLengthValidator(2000)])


    class Meta:
        db_table = 'posts'

    def __str__(self):
        return f"{self.body} by {self.author}"

class Comments(BaseModel):
    author = models.ForeignKey(Followers, on_delete=models.CASCADE, related_name='author')
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    comment = models.TextField()
    parent = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        related_name='child',
        blank=True,
        null=True
    )


    def __str__(self):
        return f"{self.comment} by {self.author}"


class PostLike(BaseModel):
    author = models.ForeignKey(Followers, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='likes')

    class Meta:
        constraints = [
            UniqueConstraint(
                fields=['author', 'post'],
                name='postLikeUnique'
            )
        ]

class CommentsLike(BaseModel):
    author = models.ForeignKey(Followers, on_delete=models.CASCADE)
    comment = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comment_likes')

    class Meta:
        constraints = [
            UniqueConstraint(
                fields=['author', 'comment'],
                name='CommentsLikeUnique'
            )
        ]