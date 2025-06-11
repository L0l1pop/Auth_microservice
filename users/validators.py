import re
from django.core.exceptions import ValidationError
    

COMMON_SEQUENCES = [
    '0123456789', '1234567890', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiop', 
    'asdfghjkl', 'zxcvbnm'
]

def validate_strong_password(password, username=None):
    if len(password) < 8:
        raise ValidationError("Пароль должен содержать не менее 8 символов.")
    if not re.search(r'[A-Z]', password):
        raise ValidationError("Пароль должен содержать хотя бы одну заглавную латинскую букву.")
    if not re.search(r'[a-z]', password):
        raise ValidationError("Пароль должен содержать хотя бы одну строчную латинскую букву.")
    if not re.search(r'\d', password):
        raise ValidationError("Пароль должен содержать хотя бы одну цифру.")
    if not re.search(r'[!@#$%^&*()\-_=+{};:,<.>/?]', password):
        raise ValidationError("Пароль должен содержать хотя бы один спецсимвол(!@#$%^&*()\-_=+{};:,<.>/?).")

    if username and username.lower() in password.lower():
        raise ValidationError("Пароль не должен содержать имя пользователя.")

    lowered = password.lower()
    for seq in COMMON_SEQUENCES:
        for i in range(len(seq) - 3):
            if seq[i:i+4] in lowered:
                raise ValidationError("Пароль не должен содержать простых последовательностей (например: 1234, abcd).")
