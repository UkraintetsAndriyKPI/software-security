import base64
import os
from flask import Flask, flash, render_template, request, session
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

from cypher_system import CaesarCipher, KnapsackCipher, PoemCipher, RSACipher, TrithemiusCipher

app = Flask(__name__)
app.secret_key = os.urandom(24)

def parse_key_from_form(form):
    """Парсер ключа з форми: вертає list чи str або викликає ValueError."""
    key_type = form.get("key_type")
    if key_type == "vector2":
        a = form.get("a", "").strip()
        b = form.get("b", "").strip()
        if not a or not b:
            raise ValueError("Заповніть обидва коефіцієнти a і b.")
        try:
            return [int(a), int(b)]
        except ValueError:
            raise ValueError("Коефіцієнти повинні бути цілими числами.")
    elif key_type == "vector3":
        a = form.get("a3", "").strip()
        b = form.get("b3", "").strip()
        c = form.get("c3", "").strip()
        if not a or not b or not c:
            raise ValueError("Заповніть коефіцієнти a, b і c.")
        try:
            return [int(a), int(b), int(c)]
        except ValueError:
            raise ValueError("Коефіцієнти повинні бути цілими числами.")
    elif key_type == "text":
        k = form.get("textkey", "").strip()
        if not k:
            raise ValueError("Текстовий ключ не може бути порожнім.")
        return k
    else:
        raise ValueError("Невідомий тип ключа.")

@app.route("/", methods=["GET", "POST"])
def cesar():
    result = ""
    bruteforce_results = []
    text_value = ""
    lang_value = "EN"

    if request.method == "POST":
        text_value = request.form.get("text", "")
        shift = int(request.form.get("shift", 3))
        lang_value = request.form.get("lang", "EN")
        action = request.form.get("action", "encrypt")

        cipher = CaesarCipher(shift)

        if action == "encrypt":
            result = cipher.encrypt(text_value)
        else:
            result = cipher.decrypt(text_value)

            # BRUTEFORCE ATTEMPT
            alphabet_length = 26 if lang_value == "EN" else 33
            for s in range(1, alphabet_length):
                brute_cipher = CaesarCipher(s)
                decoded = brute_cipher.decrypt(text_value)
                bruteforce_results.append((s, decoded))

    return render_template(
        "CeasarCipher.html",
        result=result,
        bruteforce_results=bruteforce_results,
        text_value=text_value,
        lang_value=lang_value
    )

@app.route("/trithemius/", methods=["GET", "POST"])
def trithemius():
    cipher = TrithemiusCipher()
    result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        action = request.form.get("action")
        text = request.form.get("text", "")
        try:
            key = parse_key_from_form(request.form)
            # перевірка ключа (може викликати ValueError/TypeError)
            cipher.validate_key(key)
            if action == "encrypt":
                result = cipher.encrypt(text, key)
            elif action == "decrypt":
                result = cipher.decrypt(text, key)
            else:
                raise ValueError("Невідома дія.")
        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template("TrithemiusCipher.html", result=result, formdata=formdata)

@app.route("/poem/", methods=["GET", "POST"])
def poem():
    result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        action = request.form.get("action")
        text = request.form.get("text", "")
        poem_key = request.form.get("poem", "")

        try:
            cipher = PoemCipher(poem_key)
            if action == "encrypt":
                result = cipher.encrypt(text)
            elif action == "decrypt":
                result = cipher.decrypt(text)
            else:
                raise ValueError("Невідома дія.")
        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template("PoemCipher.html", result=result, formdata=formdata)


@app.route("/des/", methods=["GET", "POST"])
def des_cipher():
    result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        text = request.form.get("text", "")
        key = request.form.get("key", "")
        iv = request.form.get("iv", "")
        mode = request.form.get("mode", "ECB")
        action = request.form.get("action", "encrypt")

        try:
            # Перевірка ключа (рівно 8 байт)
            if len(key.encode()) != 8:
                raise ValueError("Ключ має бути рівно 8 символів (8 байт).")

            # Вибір режиму DES
            mode_map = {
                "ECB": DES.MODE_ECB,
                "CBC": DES.MODE_CBC,
                "CFB": DES.MODE_CFB,
                "OFB": DES.MODE_OFB
            }

            if mode not in mode_map:
                raise ValueError("Невідомий режим DES.")

            # Ініціалізація шифра
            if mode == "ECB":
                cipher = DES.new(key.encode(), mode_map[mode])
            else:
                if len(iv.encode()) != 8:
                    raise ValueError("IV має бути рівно 8 символів для цього режиму.")
                cipher = DES.new(key.encode(), mode_map[mode], iv.encode())

            if action == "encrypt":
                padded_text = pad(text.encode(), DES.block_size)
                encrypted_bytes = cipher.encrypt(padded_text)
                result = base64.b64encode(encrypted_bytes).decode()
            elif action == "decrypt":
                decoded_bytes = base64.b64decode(text)
                decrypted_bytes = cipher.decrypt(decoded_bytes)
                result = unpad(decrypted_bytes, DES.block_size).decode()
            else:
                raise ValueError("Невідома дія (encrypt/decrypt).")

        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template("DES.html", result=result, formdata=formdata)

cipher_knapsack = KnapsackCipher()

@app.route("/knapsack/generate", methods=["GET", "POST"])
def knapsack_generate():
    public_key = None
    private_key = None
    error = None

    if request.method == "POST":
        try:
            w_str = request.form.get("w", "")
            m = int(request.form.get("m", ""))
            t = int(request.form.get("t", ""))
            w = [int(x.strip()) for x in w_str.split(",") if x.strip()]
            public_key, private_key = cipher_knapsack.generate_keys(w, m, t)
        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template("KnapsackKeyGen.html", public_key=public_key, private_key=private_key)


@app.route("/knapsack/", methods=["GET", "POST"])
def knapsack_cipher():

    result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        action = request.form.get("action")
        text = request.form.get("text", "").strip()

        try:
            if action == "encrypt":
                result = cipher_knapsack.encrypt(text)
            elif action == "decrypt":
                ciphertext = [int(x.strip()) for x in text.split(",")]
                result = cipher_knapsack.decrypt(ciphertext)
            else:
                raise ValueError("Невідома дія.")
        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template("KnapsackCipher.html", result=result, formdata=formdata)


rsa_cipher = RSACipher()

@app.route("/rsa/generate", methods=["GET", "POST"])
def rsa_generate_keys():

    """Генерація пари RSA ключів"""
    public_key = None
    private_key = None
    key_info = None
    error = None

    if request.method == "POST":
        try:
            key_size = int(request.form.get("key_size", 1024))

            if key_size not in [512, 1024, 2048, 4096]:
                raise ValueError("Розмір ключа повинен бути 512, 1024, 2048 або 4096 біт")

            key_info = rsa_cipher.generate_keys(key_size)
            public_key = key_info['public_key']
            private_key = key_info['private_key']

            # Зберігаємо ключі в сесії для подальшого використання
            session['rsa_public_key'] = public_key
            session['rsa_private_key'] = private_key

            flash("Ключі успішно згенеровані!", "success")

        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template(
        "RSAKeyGen.html",
        public_key=public_key,
        private_key=private_key,
        key_info=key_info
    )

@app.route("/rsa/", methods=["GET", "POST"])
def rsa_cipher_route():
    """Шифрування та розшифрування за допомогою RSA"""
    result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        action = request.form.get("action")
        text = request.form.get("text", "").strip()
        public_key_input = request.form.get("public_key", "").strip()
        private_key_input = request.form.get("private_key", "").strip()

        try:
            # Використовуємо ключі з форми або з сесії
            public_key_to_use = public_key_input or session.get('rsa_public_key')
            private_key_to_use = private_key_input or session.get('rsa_private_key')

            if not public_key_to_use and action == "encrypt":
                raise ValueError("Відкритий ключ не знайдено. Спочатку згенеруйте ключі.")
            if not private_key_to_use and action == "decrypt":
                raise ValueError("Закритий ключ не знайдено. Спочатку згенеруйте ключі.")

            if action == "encrypt":
                result = rsa_cipher.encrypt(text, public_key_to_use)
                flash("Текст успішно зашифровано!", "success")
            elif action == "decrypt":
                result = rsa_cipher.decrypt(text, private_key_to_use)
                flash("Текст успішно розшифровано!", "success")
            else:
                raise ValueError("Невідома дія.")

        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template(
        "RSACipher.html",
        result=result,
        formdata=formdata,
        stored_public_key=session.get('rsa_public_key'),
        stored_private_key=session.get('rsa_private_key')
    )

@app.route("/rsa/example", methods=["GET", "POST"])
def rsa_example():
    """Сторінка з чисельним прикладом RSA (як у Вікіпедії)"""
    example_data = {
        'p': 61,
        'q': 53,
        'n': 3233,
        'phi': 3120,
        'e': 17,
        'd': 2753,
        'message': 65,
        'encrypted': 2790
    }

    result = None
    verification_result = None

    if request.method == "POST":
        try:
            # Перевірка прикладу
            message = int(request.form.get("message", 65))

            # Шифрування: c = m^e mod n
            encrypted = pow(message, example_data['e'], example_data['n'])

            # Розшифрування: m = c^d mod n
            decrypted = pow(encrypted, example_data['d'], example_data['n'])

            result = {
                'original': message,
                'encrypted': encrypted,
                'decrypted': decrypted,
                'verified': message == decrypted
            }

            verification_result = "ПРИКЛАД ПРАЦЮЄ КОРЕКТНО!" if result['verified'] else "ПРИКЛАД НЕ ПРАЦЮЄ!"

        except Exception as e:
            flash(f"Помилка в прикладі: {str(e)}", "danger")

    return render_template(
        "RSAExample.html",
        example=example_data,
        result=result,
        verification_result=verification_result
    )




@app.route("/rsa/sign/generate", methods=["GET", "POST"])
def rsa_sign_generate_keys():
    """Генерація пари RSA ключів для ЕЦП"""
    public_key = None
    private_key = None
    key_info = None
    error = None

    if request.method == "POST":
        try:
            key_size = int(request.form.get("key_size", 2048))

            if key_size not in [512, 1024, 2048, 4096]:
                raise ValueError("Розмір ключа повинен бути 512, 1024, 2048 або 4096 біт")

            key_info = rsa_cipher.generate_keys(key_size)
            public_key = key_info['public_key']
            private_key = key_info['private_key']

            # Зберігаємо ключі в сесії для подальшого використання
            session['rsa_sign_public_key'] = public_key
            session['rsa_sign_private_key'] = private_key

            flash("Ключі для ЕЦП успішно згенеровані!", "success")

        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template(
        "RSASignKeyGen.html",
        public_key=public_key,
        private_key=private_key,
        key_info=key_info
    )

@app.route("/rsa/sign/", methods=["GET", "POST"])
def rsa_signature():
    """Створення та перевірка ЕЦП"""
    signature_result = None
    verification_result = None
    error = None
    formdata = {}

    if request.method == "POST":
        formdata = request.form.to_dict()
        action = request.form.get("action")
        message = request.form.get("message", "").strip()
        signature_input = request.form.get("signature", "").strip()
        public_key_input = request.form.get("public_key", "").strip()
        private_key_input = request.form.get("private_key", "").strip()

        try:
            if action == "sign":
                # Використовуємо приватний ключ з форми або з сесії
                private_key_to_use = private_key_input or session.get('rsa_sign_private_key')

                if not private_key_to_use:
                    raise ValueError("Приватний ключ не знайдено. Спочатку згенеруйте ключі.")

                signature_result = rsa_cipher.sign_message(message, private_key_to_use)
                flash("Повідомлення успішно підписано!", "success")

            elif action == "verify":
                # Використовуємо публічний ключ з форми або з сесії
                public_key_to_use = public_key_input or session.get('rsa_sign_public_key')

                if not public_key_to_use:
                    raise ValueError("Публічний ключ не знайдено. Спочатку згенеруйте ключі.")
                if not signature_input:
                    raise ValueError("Підпис не може бути порожнім.")

                is_valid = rsa_cipher.verify_signature(message, signature_input, public_key_to_use)
                verification_result = "Підпис ВАЛІДНИЙ" if is_valid else "Підпис НЕВАЛІДНИЙ"
                flash(f"Перевірка підпису: {verification_result}", "success" if is_valid else "warning")

            else:
                raise ValueError("Невідома дія.")

        except Exception as e:
            error = str(e)
            flash(error, "danger")

    return render_template(
        "RSASignature.html",
        signature_result=signature_result,
        verification_result=verification_result,
        formdata=formdata,
        stored_public_key=session.get('rsa_sign_public_key'),
        stored_private_key=session.get('rsa_sign_private_key')
    )

@app.route("/rsa/sign/example", methods=["GET", "POST"])
def rsa_sign_example():
    """Сторінка з чисельним прикладом ЕЦП RSA"""
    example_data = {
        'p': 61,
        'q': 53,
        'n': 3233,
        'phi': 3120,
        'e': 17,
        'd': 2753,
        'message': "Hello RSA",
        'hash_value': "2ef7bde608ce5404e97d5f042f95f89f1c232871"  # SHA1("Hello RSA") для прикладу
    }

    result = None
    verification_result = None

    if request.method == "POST":
        try:
            message = request.form.get("message", "Hello RSA")

            # Простий приклад підпису (без реального хешування для демонстрації)
            # У реальному застосуванні використовувались би методи sign_message/verify_signature
            message_num = int.from_bytes(message.encode(), 'big') % example_data['n']
            signature = pow(message_num, example_data['d'], example_data['n'])
            verified_message = pow(signature, example_data['e'], example_data['n'])

            result = {
                'original': message,
                'signature': signature,
                'verified': message_num == verified_message
            }

            verification_result = "ПРИКЛАД ЕЦП ПРАЦЮЄ КОРЕКТНО!" if result['verified'] else "ПРИКЛАД ЕЦП НЕ ПРАЦЮЄ!"

        except Exception as e:
            flash(f"Помилка в прикладі: {str(e)}", "danger")

    return render_template(
        "RSASignExample.html",
        example=example_data,
        result=result,
        verification_result=verification_result
    )



@app.route("/about/", methods=["GET"])
def about():
    return render_template("about.html")

if __name__ == "__main__":
    app.run(debug=True)
