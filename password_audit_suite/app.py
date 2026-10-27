"""
app.py

Flask front end for the Password & Credential Attack Suite project.

Routes tie together the three modules in modules/:
  - dictionary_gen.py   wordlist generation
  - password_analyzer.py  entropy / strength checks
  - cracker_demo.py     hashing a test password + dictionary attack demo

Session (cookie) storage is used to remember the last result from each
tool so the Audit Report page has something to summarize. This is a
class project, so nothing here is meant to persist between runs or
scale past a single user testing locally.
"""

import io
import os

from flask import Flask, render_template, request, session, send_file, redirect, url_for

from modules import dictionary_gen, password_analyzer, cracker_demo

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-key-change-me")

SAMPLE_SHADOW_PATH = os.path.join(os.path.dirname(__file__), "sample_data", "demo_shadow.txt")

# fallback wordlist used by the cracker demo if nothing's been generated yet
FALLBACK_WORDLIST = [
    "password", "password1", "password123", "letmein", "qwerty123",
    "admin123", "welcome1", "football1", "iloveyou1", "monkey123",
]


@app.route("/")
def index():
    return render_template("index.html")


# ---------- Dictionary generator ----------

@app.route("/dictionary", methods=["GET", "POST"])
def dictionary_page():
    wordlist = None
    form_name = form_dob = form_keywords = ""
    use_leet = use_common = True

    if request.method == "POST":
        form_name = request.form.get("name", "").strip()
        form_dob = request.form.get("dob_year", "").strip()
        form_keywords = request.form.get("keywords", "").strip()
        use_leet = "use_leet" in request.form
        use_common = "use_common" in request.form

        keywords = [k.strip() for k in form_keywords.split(",") if k.strip()]
        wordlist = dictionary_gen.build_wordlist(
            name=form_name,
            dob_year=form_dob,
            keywords=keywords,
            use_leet=use_leet,
            use_common=use_common,
        )

        session["last_wordlist"] = wordlist
        session["last_wordlist_inputs"] = f"name='{form_name}', dob='{form_dob}', keywords='{form_keywords}'"

    return render_template(
        "dictionary.html",
        wordlist=wordlist,
        form_name=form_name,
        form_dob=form_dob,
        form_keywords=form_keywords,
        use_leet=use_leet,
        use_common=use_common,
    )


@app.route("/dictionary/download", methods=["POST"])
def dictionary_download():
    words = request.form.get("words", "")
    wordlist = words.split(",") if words else []
    buffer = io.BytesIO("\n".join(wordlist).encode())
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="wordlist.txt", mimetype="text/plain")


# ---------- Strength analyzer ----------

@app.route("/analyzer", methods=["GET", "POST"])
def analyzer_page():
    result = None
    submitted = None

    if request.method == "POST":
        submitted = request.form.get("password", "")
        if submitted:
            result = password_analyzer.analyze(submitted)
            session["last_analysis"] = result

    return render_template("analyzer.html", result=result, submitted=submitted)


# ---------- Hash + crack demo ----------

@app.route("/cracker", methods=["GET"])
def cracker_page():
    return render_template(
        "cracker.html",
        generated_hash=session.get("last_hash"),
        algo_used=session.get("last_algo"),
        attack_result=session.get("last_attack"),
    )


@app.route("/cracker/hash", methods=["POST"])
def cracker_hash():
    password = request.form.get("password", "")
    algo = request.form.get("algo", "sha256")

    if password:
        hashed = cracker_demo.hash_a_password(password, algo=algo)
        session["last_hash"] = hashed
        session["last_algo"] = algo

    return render_template(
        "cracker.html",
        generated_hash=session.get("last_hash"),
        algo_used=session.get("last_algo"),
        attack_result=session.get("last_attack"),
    )


@app.route("/cracker/attack", methods=["POST"])
def cracker_attack():
    target_hash = request.form.get("target_hash", "").strip()
    algo = request.form.get("algo", "sha256")

    wordlist = session.get("last_wordlist") or FALLBACK_WORDLIST

    attack_result = None
    if target_hash:
        found, attempts, elapsed = cracker_demo.dictionary_attack(target_hash, wordlist, algo=algo)
        attack_result = {"found": found, "attempts": attempts, "elapsed": elapsed}
        session["last_attack"] = attack_result

    return render_template(
        "cracker.html",
        generated_hash=session.get("last_hash"),
        algo_used=session.get("last_algo"),
        attack_result=attack_result,
    )


# ---------- Sample shadow file viewer ----------

@app.route("/shadow-demo")
def shadow_demo():
    entries = cracker_demo.parse_sample_shadow(SAMPLE_SHADOW_PATH)
    return render_template("shadow_demo.html", entries=entries)


# ---------- Report ----------

@app.route("/report")
def report_page():
    session_data = {
        "wordlist_count": len(session.get("last_wordlist", [])),
        "wordlist_inputs": session.get("last_wordlist_inputs", ""),
        "last_analysis": session.get("last_analysis"),
        "last_attack": session.get("last_attack"),
    }
    return render_template("report.html", session_data=session_data)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
