from django.shortcuts import get_object_or_404
from rest_framework import status

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated

from drf_yasg.utils import swagger_auto_schema

from . import serializers
from .models import User, ZendeskToken

import os
import requests
import base64


class UserLogin(APIView):
    """Login user from zendesk"""

    @swagger_auto_schema(request_body=serializers.ZendeskLoginSerializer)
    def post(self, request):
        # from reguest get data
        serializer = serializers.ZendeskLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # encode email and password to token
        encoded_msg = serializer.data['email'] + ":" + serializer.data['password']
        message_bytes = encoded_msg.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        
        # check token and user profile
        zendesk_domain = os.getenv('ZENDESK_DOMAIN')
        url = f"https://{zendesk_domain}/api/v2/users?query=email:{serializer.data['email']}"
        headers = {"Authorization": f"Basic {base64_message}"}
        response = requests.get(url, headers=headers).json()

        # check for errors
        if 'error' in list(response.keys()):
            return Response({"error": "Error in credentials"}, status=403)

        # create or update user with zendesk token
        user = User.objects.filter(email=serializer.data['email']).first()
        if user:
            user.set_password(serializer.data['password'])
            user.save()
        else:
            user = User.objects.create(
                email=serializer.data['email'],
                is_active=True
            )
            user.set_password(serializer.data['password'])
            user.save()

        ZendeskToken.objects.update_or_create(
            user=user,
            defaults={
                "zendesk_user_id": response['users'][0]['id'],
                "token": base64_message
            }
        )

        # create auth token
        token, _ = Token.objects.get_or_create(user=user)
        token_response = {"token": token.key}

        return Response(token_response)


class UserTokenCheck(APIView):
    """Check access to user token"""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"detail": "Valid token"})


class UserLogout(APIView):
    """Logout user"""

    permission_classes = [IsAuthenticated]

    def delete(self, request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
