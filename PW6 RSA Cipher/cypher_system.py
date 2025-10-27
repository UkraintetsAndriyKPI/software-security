from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from typing import List
import base64

class CaesarCipher:
    def __init__(self, key: int):
        self.key = self.validate_key(key)
        self.eng_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.eng_lower = "abcdefghijklmnopqrstuvwxyz"
        self.ua_upper = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
        self.ua_lower = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"

    def validate_key(self, key: int) -> int:
        if not isinstance(key, int):
            raise ValueError("Key must be an integer")
        return key

    def validate_data(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            raise ValueError("Text needs to be a non-empty string")
        return text

    def shift_char(self, ch: str, key: int) -> str:
        # English uppercase
        if ch in self.eng_upper:
            idx = self.eng_upper.index(ch)
            return self.eng_upper[(idx + key) % len(self.eng_upper)]
        # English lowercase
        elif ch in self.eng_lower:
            idx = self.eng_lower.index(ch)
            return self.eng_lower[(idx + key) % len(self.eng_lower)]
        # Ukrainian uppercase
        elif ch in self.ua_upper:
            idx = self.ua_upper.index(ch)
            return self.ua_upper[(idx + key) % len(self.ua_upper)]
        # Ukrainian lowercase
        elif ch in self.ua_lower:
            idx = self.ua_lower.index(ch)
            return self.ua_lower[(idx + key) % len(self.ua_lower)]
        # Other symbols (punctuation, numbers, spaces)
        else:
            return ch

    def encrypt(self, text: str) -> str:
        text = self.validate_data(text)
        return "".join(self.shift_char(ch, self.key) for ch in text)

    def decrypt(self, text: str) -> str:
        text = self.validate_data(text)
        return "".join(self.shift_char(ch, -self.key) for ch in text)


class TrithemiusCipher():
    def validate_key(self, key):
        # приймаємо: list/tuple довжини 2 або 3 (числа) або непорожній str
        if isinstance(key, (list, tuple)):
            if len(key) == 2 or len(key) == 3:
                # перевіримо що всі елементи - цілі числа
                try:
                    for x in key:
                        int(x)
                except Exception:
                    raise ValueError("Коефіцієнти ключа повинні бути цілими числами.")
                return True
            else:
                raise ValueError("Векторний ключ повинен мати 2 або 3 коефіцієнти.")
        elif isinstance(key, str):
            if key.strip():
                return True
            else:
                raise ValueError("Текстовий ключ не може бути порожнім.")
        else:
            raise TypeError("Невірний формат ключа.")

    def get_shift(self, i, key):
        """ Обчислення зсуву для позиції i (0-based) """
        if isinstance(key, (list, tuple)):
            if len(key) == 2:      # лінійне: a*i + b
                a, b = map(int, key)
                return (a * i + b) % 26
            elif len(key) == 3:    # квадратичне: a*i^2 + b*i + c
                a, b, c = map(int, key)
                return (a * i * i + b * i + c) % 26
        elif isinstance(key, str):  # текстове гасло: беремо букву як зсув
            if len(key) == 0:
                return 0
            ch = key[i % len(key)]
            # перетворюємо букву в зсув 0..25; працює тільки з English
            if ch.isalpha():
                return (ord(ch.lower()) - ord('a')) % 26
            else:
                # якщо символ не буква - використовуємо його код символу
                return ord(ch) % 26

    def encrypt(self, text, key):
        self.validate_key(key)
        result = []
        cnt = 0  # лічильник тільки для літер (щоб зсув збігався з позицією літери)
        for ch in text:
            if ch.isalpha():
                shift = self.get_shift(cnt, key)
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift) % 26 + base))
                cnt += 1
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, text, key):
        self.validate_key(key)
        result = []
        cnt = 0
        for ch in text:
            if ch.isalpha():
                shift = self.get_shift(cnt, key)
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base - shift) % 26 + base))
                cnt += 1
            else:
                result.append(ch)
        return "".join(result)


class PoemCipher:
    def __init__(self, poem: str):
        self.poem = self.validate_poem(poem)
        self.eng_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.eng_lower = "abcdefghijklmnopqrstuvwxyz"
        self.ua_upper = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
        self.ua_lower = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"

    def validate_poem(self, poem: str) -> str:
        if not isinstance(poem, str) or not poem.strip():
            raise ValueError("Поема повинна бути непорожнім рядком.")
        return poem.replace("\n", " ").strip()

    def get_shift(self, index: int) -> int:
        """Отримати числовий зсув з букви вірша"""
        ch = self.poem[index % len(self.poem)]
        if ch.isalpha():
            if ch.lower() in self.eng_lower:
                return ord(ch.lower()) - ord("a")
            elif ch.lower() in self.ua_lower:
                return self.ua_lower.index(ch.lower())
        return ord(ch) % 33  # fallback для символів, напр. пробіл

    def shift_char(self, ch: str, key: int, encrypt=True) -> str:
        alphabets = [
            self.eng_upper, self.eng_lower,
            self.ua_upper, self.ua_lower
        ]
        for alpha in alphabets:
            if ch in alpha:
                idx = alpha.index(ch)
                if encrypt:
                    return alpha[(idx + key) % len(alpha)]
                else:
                    return alpha[(idx - key) % len(alpha)]
        return ch

    def encrypt(self, text: str) -> str:
        result = []
        cnt = 0
        for ch in text:
            if ch.isalpha():
                shift = self.get_shift(cnt)
                result.append(self.shift_char(ch, shift, encrypt=True))
                cnt += 1
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, text: str) -> str:
        result = []
        cnt = 0
        for ch in text:
            if ch.isalpha():
                shift = self.get_shift(cnt)
                result.append(self.shift_char(ch, shift, encrypt=False))
                cnt += 1
            else:
                result.append(ch)
        return "".join(result)


class KnapsackCipher:
    def __init__(self):
        self.private_key = None  # (w, m, t)
        self.public_key = None   # b
        self.t_inv = None

    def generate_keys(self, w: List[int], m: int, t: int):
        """Генерація відкритого і закритого ключів"""
        if not self._is_superincreasing(w):
            raise ValueError("Послідовність w не є супервеликою.")
        if m <= sum(w):
            raise ValueError("m має бути більшим за суму елементів w.")

        self.private_key = (w, m, t)
        self.t_inv = pow(t, -1, m)  # t^-1
        self.public_key = [(t * wi) % m for wi in w]
        return self.public_key, {"w": w, "m": m, "t": t, "t_inv": self.t_inv}

    def encrypt(self, plaintext: str) -> List[int]:
        """Шифрування тексту відкритим ключем"""
        if not self.public_key:
            raise ValueError("Відкритий ключ не згенерований.")
        bits = ''.join(format(ord(ch), '08b') for ch in plaintext)
        block_size = len(self.public_key)
        ciphertext = []
        for i in range(0, len(bits), block_size):
            block = bits[i:i+block_size]
            c = sum(int(bit) * self.public_key[j] for j, bit in enumerate(block))
            ciphertext.append(c)
        return ciphertext

    def decrypt(self, ciphertext: List[int]) -> str:
        """Розшифрування тексту закритим ключем"""
        if not self.private_key or not self.t_inv:
            raise ValueError("Закритий ключ не згенерований.")
        w, m, t = self.private_key
        decrypted_bits = ""
        for c in ciphertext:
            s = (c * self.t_inv) % m
            block_bits = []
            for wi in reversed(w):
                if wi <= s:
                    block_bits.insert(0, "1")
                    s -= wi
                else:
                    block_bits.insert(0, "0")
            decrypted_bits += ''.join(block_bits)
        chars = [
            chr(int(decrypted_bits[i:i+8], 2))
            for i in range(0, len(decrypted_bits), 8)
        ]
        return ''.join(chars)

    def _is_superincreasing(self, seq: List[int]) -> bool:
        """Перевіряє, чи є послідовність супервеликою"""
        total = 0
        for x in seq:
            if x <= total:
                return False
            total += x
        return True

class RSACipher:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.key_pair = None

    def generate_keys(self, key_size=1024):
        """Генерація пари RSA ключів"""
        random_generator = Random.new().read
        self.key_pair = RSA.generate(key_size, random_generator)

        self.public_key = self.key_pair.publickey()
        self.private_key = self.key_pair

        return {
            'public_key': self.public_key.export_key().decode('ascii'),
            'private_key': self.private_key.export_key().decode('ascii'),
            'key_size': key_size
        }

    def encrypt(self, message, public_key_str=None):
        """Шифрування повідомлення з використанням відкритого ключа"""
        try:
            if public_key_str:
                public_key = RSA.import_key(public_key_str)
            else:
                public_key = self.public_key

            cipher = PKCS1_OAEP.new(public_key)
            encrypted_bytes = cipher.encrypt(message.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('ascii')
        except Exception as e:
            raise ValueError(f"Помилка шифрування: {str(e)}")

    def decrypt(self, encrypted_message, private_key_str=None):
        """Розшифрування повідомлення з використанням закритого ключа"""
        try:
            if private_key_str:
                private_key = RSA.import_key(private_key_str)
            else:
                private_key = self.private_key

            cipher = PKCS1_OAEP.new(private_key)
            encrypted_bytes = base64.b64decode(encrypted_message)
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Помилка розшифрування: {str(e)}")
