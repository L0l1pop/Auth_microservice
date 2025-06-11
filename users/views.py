from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import login, logout
from rest_framework.permissions import IsAuthenticated
from .serializers import RegisterSerializer, LoginSerializer, TokenSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, redirect, render
import datetime
from django.utils import timezone
from django.core.cache import cache
from django.http import HttpResponseBadRequest
from django.contrib.auth.decorators import login_required
from .utils import generate_otp, send_telegram_message
from django.views.decorators.http import require_POST


TEMP_SMS_CODES = {}
TEMP_SMS_ATTEMPTS = {}

User = get_user_model()


def bind_telegram(request):
    telegram_id = request.GET.get("telegram_id")

    if telegram_id:
        if request.user.is_authenticated:
            user = request.user
            if not User.objects.filter(telegram_id=telegram_id).exclude(id=user.id).exists():
                user.telegram_id = telegram_id
                user.save()
        else:
            if not User.objects.filter(telegram_id=telegram_id).exists():
                request.session['pending_telegram_id'] = telegram_id
                request.session['telegram_linked'] = True
            else:
                print('dsfsfdsfsdfs')
                request.session['error'] = 'Этот Telegram уже привязан к другому аккаунту'
                return redirect('register')
            request.session['form_data'] = {
                    'username': request.GET.get('username', ''),
                    'password': request.GET.get('password', ''),
                    'password2': request.GET.get('password2', ''),
                    'use_2fa': 'use_2fa' in request.GET,
                }
            print('bind')
            print(request.session['form_data'])

    if request.user.is_authenticated:
        return redirect(f'/auth/profile/{request.user.id}/')
    return redirect(f'/auth/register/')

# @require_POST
# @login_required
def unlink_telegram(request):
    if request.user.is_authenticated:
        user = request.user
        user.telegram_id = None
        user.save()
        return redirect(f"/auth/profile/{user.id}/")
    else:
        request.session.pop('pending_telegram_id', None)
        request.session['telegram_linked'] = False
        return redirect('register')

class Toggle2FAView(LoginRequiredMixin, View):
    def post(self, request):
        user = request.user
        if user.use_2fa:
            user.use_2fa = False
        else:
            if not user.telegram_id:
                return redirect(f'/auth/profile/{user.id}/?error=Для включения 2FA привяжите Telegram')
            user.use_2fa = True
        user.save()
        return redirect(f'/auth/profile/{user.id}/')


class RegisterView(APIView):
    def get(self, request):
        form_data = request.session.pop('form_data', {})
        telegram_linked = request.session.get('telegram_linked')
        form_data['telegram_linked'] = telegram_linked
        error = request.session.pop('error', None)
        print(form_data)
        context =  {
            'form_data': form_data, 
            'telegram_bot': 'authicate_code_bot',
            'error': error
            }
        return render(request, 'users/register.html', context)

    def post(self, request):
        serializer = RegisterSerializer(data=request.POST)
        form_data = request.POST.dict()
        request.session['form_data'] = form_data
        telegram_linked = request.session.get('telegram_linked')
        form_data['telegram_linked'] = telegram_linked

        if serializer.is_valid():
            user = serializer.save()
            telegram_id = request.session.get('pending_telegram_id')
            if telegram_id:
                user.telegram_id = telegram_id
                user.save()
                del request.session['pending_telegram_id']

            login(request, user)
            tokens = TokenSerializer.get_tokens_for_user(user)
            response = redirect('login')
            response.set_cookie("access", tokens["access"])
            response.set_cookie("refresh", tokens["refresh"])
            request.session.pop('form_data', None)
            return response

        errors = serializer.errors
        return render(request, 'users/register.html', {'errors': errors, 'form_data': form_data})

class LoginView(APIView):
    def get(self, request):
        return render(request, 'users/login.html')

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            if user.use_2fa and user.telegram_id:
                code = generate_otp(6)
                TEMP_SMS_CODES[user.telegram_id] = code
                TEMP_SMS_ATTEMPTS[user.telegram_id] = 0
                send_telegram_message(user.telegram_id, f"Ваш код подтверждения: {code}")
                request.session['2fa_telegram_id'] = user.telegram_id
                return redirect('verify-2fa')
            # Без 2FA
            login(request, user)
            tokens = TokenSerializer.get_tokens_for_user(user)
            response = redirect(f"/auth/profile/{user.id}/")
            response.set_cookie("access", tokens["access"])
            response.set_cookie("refresh", tokens["refresh"])
            return response
        return render(request, 'users/login.html', {'errors': serializer.errors})

MAX_2FA_ATTEMPTS = 5
BLOCK_TIME_SECONDS = 60 

class Verify2FAView(APIView):
    def get(self, request):
        telegram_id = request.session.get('2fa_telegram_id')
        blocked_until = request.session.get('2fa_blocked_until')

        if blocked_until:
            unblock_time = datetime.datetime.fromisoformat(blocked_until)
            if timezone.now() < unblock_time:
                seconds_left = int((unblock_time - timezone.now()).total_seconds())
                return render(request, 'users/verify_2fa.html', {
                    'telegram_id': telegram_id,
                    'blocked': True,
                    'seconds_left': seconds_left
                })

        return render(request, 'users/verify_2fa.html', {'telegram_id': telegram_id})

    def post(self, request):
        telegram_id = request.session.get('2fa_telegram_id')
        code = request.POST.get("code")

        blocked_until = request.session.get('2fa_blocked_until')
        attempts = request.session.get('2fa_attempts', 0)

        if blocked_until:
            unblock_time = datetime.datetime.fromisoformat(blocked_until)
            if timezone.now() < unblock_time:
                seconds_left = int((unblock_time - timezone.now()).total_seconds())
                return render(request, 'users/verify_2fa.html', {
                    'error': f"Слишком много попыток. Повторите через {seconds_left} сек.",
                    'telegram_id': telegram_id,
                    'blocked': True,
                    'seconds_left': seconds_left
                })

        if TEMP_SMS_CODES.get(telegram_id) == code:
            try:
                user = User.objects.get(telegram_id=telegram_id)
                login(request, user)
                tokens = TokenSerializer.get_tokens_for_user(user)

                del TEMP_SMS_CODES[telegram_id]
                request.session.pop('2fa_telegram_id', None)
                request.session.pop('2fa_attempts', None)
                request.session.pop('2fa_blocked_until', None)

                response = redirect(f"/auth/profile/{user.id}/")
                response.set_cookie("access", tokens["access"])
                response.set_cookie("refresh", tokens["refresh"])
                return response
            except User.DoesNotExist:
                return render(request, 'users/verify_2fa.html', {"error": "Пользователь не найден", 'telegram_id': telegram_id})
        else:
            attempts += 1
            request.session['2fa_attempts'] = attempts

            if attempts >= MAX_2FA_ATTEMPTS:
                blocked_until = (timezone.now() + datetime.timedelta(seconds=BLOCK_TIME_SECONDS)).isoformat()
                request.session['2fa_blocked_until'] = blocked_until
                return render(request, 'users/verify_2fa.html', {
                    "error": "Превышено число попыток. Повторите позже.",
                    "telegram_id": telegram_id,
                    "blocked": True,
                    "seconds_left": BLOCK_TIME_SECONDS
                })

            return render(request, 'users/verify_2fa.html', {
                "error": f"Неверный код. Осталось попыток: {MAX_2FA_ATTEMPTS - attempts}",
                "telegram_id": telegram_id
            })
    

class Resend2FACodeView(APIView):
    def post(self, request):
        telegram_id = request.session.get('2fa_telegram_id')
        if telegram_id:
            code = generate_otp(6)
            TEMP_SMS_CODES[telegram_id] = code
            request.session['2fa_attempts'] = 0
            request.session.pop('2fa_blocked_until', None)
            send_telegram_message(telegram_id, f"Ваш новый код подтверждения: {code}")
        return redirect('verify-2fa')


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get("refresh")
        
        if not refresh_token:
            return Response({"error": "Refresh токен не найден в cookie"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            return Response({"error": "Некорректный refresh токен"}, status=status.HTTP_400_BAD_REQUEST)

        logout(request)

        response = redirect('login')
        # Очистить cookies
        response.delete_cookie("access")
        response.delete_cookie("refresh")
        return response

class RedirectToProfile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if not user.is_authenticated:
            return redirect('login')
        return redirect(f"/auth/profile/{user.id}/")
    

class ProfilePageView(LoginRequiredMixin, View):
    def get(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        context = {
            'user': user,
            'telegram_bot': 'authicate_code_bot',
            'error': request.GET.get('error') 
        }
        return render(request, 'users/profile.html', context)

    def post(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        telegram_id = request.session.get("pending_telegram_id")
        if telegram_id:
            if not User.objects.filter(telegram_id=telegram_id).exclude(id=user.id).exists():
                user.telegram_id = telegram_id
                user.save()
                del request.session['pending_telegram_id']
        return redirect(f"/auth/profile/{user.id}/")