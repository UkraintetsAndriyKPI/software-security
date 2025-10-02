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
