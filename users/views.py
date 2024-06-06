from django.shortcuts import render
from .serializers import FollowersSerializer
from .models import Followers, CodeVerify
from rest_framework.generics import CreateAPIView
# Create your views here.


class UserCreateView(CreateAPIView):
    queryset = Followers
    serializer_class = FollowersSerializer