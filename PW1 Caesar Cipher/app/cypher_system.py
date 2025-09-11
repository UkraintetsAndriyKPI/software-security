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
