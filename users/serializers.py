from .models import Followers, CodeVerify
from rest_framework import serializers

class FollowersSerializer(serializers.ModelSerializer):
    id = serializers.UUIDField(read_only=True)
    user_type = serializers.CharField(read_only=True, required=True)

    class Meta:
        model = Followers
        fields = ['id', 'user_type', 'username']
