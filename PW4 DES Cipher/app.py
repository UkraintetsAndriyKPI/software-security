import base64
from flask import Flask, flash, render_template, request
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

from cypher_system import CaesarCipher, PoemCipher, TrithemiusCipher

app = Flask(__name__)

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







@app.route("/about/", methods=["GET"])
def about():
    return render_template("about.html")

if __name__ == "__main__":
    app.run(debug=True)
