from flask import Flask, render_template, request

from cypher_system import CaesarCipher

app = Flask(__name__)

# UA = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
# EN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# def caesar_cipher(text, shift, alphabet, decrypt=False):
#     result = ""
#     shift = -shift if decrypt else shift
#     alphabet_lower = alphabet.lower()

#     for ch in text:
#         if ch.isupper() and ch in alphabet:
#             idx = (alphabet.index(ch) + shift) % len(alphabet)
#             result += alphabet[idx]
#         elif ch.islower() and ch in alphabet_lower:
#             idx = (alphabet_lower.index(ch) + shift) % len(alphabet_lower)
#             result += alphabet_lower[idx]
#         else:
#             result += ch
#     return result

@app.route("/", methods=["GET", "POST"])
def index():
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
        "index.html",
        result=result,
        bruteforce_results=bruteforce_results,
        text_value=text_value,
        lang_value=lang_value
    )

@app.route("/about/", methods=["GET"])
def about():
    return render_template("about.html")

if __name__ == "__main__":
    app.run(debug=True)
