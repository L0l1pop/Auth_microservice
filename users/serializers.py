from rest_framework import serializers
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
from .validators import validate_strong_password

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)
    use_2fa = serializers.BooleanField(required=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'password2', 'use_2fa', 'telegram_id')
        extra_kwargs = {
            'password': {'write_only': True},
            'telegram_id': {'write_only': True, 'required': False},
        }

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError("Пароли не совпадают.")
        validate_strong_password(data['password'], username=data['username'])

        if data.get('use_2fa') and not data.get('telegram_id'):
            raise serializers.ValidationError("Чтобы включить 2FA, привяжите Telegram.")
        return data

    def create(self, validated_data):
        validated_data.pop('password2')
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

    def create(self, validated_data):
        request = self.context.get('request')
        validated_data.pop('password2')
        validated_data['password'] = make_password(validated_data['password'])

        if request:
            pending_telegram_id = request.session.get('pending_telegram_id')
            if pending_telegram_id:
                validated_data['telegram_id'] = pending_telegram_id
                del request.session['pending_telegram_id']

        return super().create(validated_data)
    

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            raise serializers.ValidationError("Введите имя пользователя и пароль")

        user = authenticate(username=username, password=password)

        if user is None:
            raise serializers.ValidationError("Неверный логин или пароль")
        if not user.is_active:
            raise serializers.ValidationError("Пользователь отключен")

        # Проверка, что если включена 2FA — то telegram_id у пользователя должен быть
        if user.use_2fa and not user.telegram_id:
            raise serializers.ValidationError("2FA включена, но Telegram не привязан.")

        data['user'] = user
        return data
    

# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ('id', 'username', 'telegram_id', 'is_active')

class TokenSerializer(serializers.Serializer):
    refresh = serializers.CharField(read_only=True)
    access = serializers.CharField(read_only=True)

    @classmethod
    def get_tokens_for_user(cls, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }