from rest_framework import serializers


class ZendeskLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    extra_kwargs = {
            'password': {'read_only': True}
        }
