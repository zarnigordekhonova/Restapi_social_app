from django.urls import path
from .views import (PostListApiView, PostCreateView, PostRetrieveUpdateDestroyView,
                    PostCommentListView, PostCommentCreateView, CommentListCreateApiView,
                    CommentRetrieveView, PostLikeListView, CommentLikeListView, PostLikeApiView,
                    CommentLikeAPiView)


urlpatterns = [
    path('list/', PostListApiView.as_view()),
    path('create/post/', PostCreateView.as_view()),
    path('<uuid:pk>/', PostRetrieveUpdateDestroyView.as_view()),
    path('post/<uuid:pk>/likes/', PostLikeListView.as_view()),
    path('post/<uuid:pk>/comments/', PostCommentListView.as_view()),
    path('post/<uuid:pk>/comments/create/', PostCommentCreateView.as_view()),

    path('comments/create', CommentListCreateApiView.as_view()),
    path('comments/<uuid:pk>/', CommentRetrieveView.as_view()),
    path('comments/<uuid:pk>/likes/', CommentLikeListView.as_view()),

    path('<uuid:pk>/create-delete-like/', PostLikeApiView.as_view()),
    path('comments/<uuid:pk>/create_delete_like/', CommentLikeAPiView.as_view()),

]
