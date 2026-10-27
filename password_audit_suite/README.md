# Password & Credential Attack Suite

A Flask app for a password-policy coursework project. It covers four pieces:

1. **Dictionary generator** - builds a wordlist from a name, birth year and keywords, with leet-speak and suffix mutations.
2. **Strength analyzer** - entropy estimate, rough offline crack-time estimate, specific weaknesses flagged.
3. **Hash & crack demo** - hash a test password, then run a dictionary attack against that hash and see how fast it falls.
4. **Shadow-file format viewer** - reads a bundled, fabricated sample file in the same layout as a real `/etc/shadow`, to explain the field format.

## Scope note

This project does **not** pull live credentials off a real machine. It
doesn't read an actual `/etc/shadow`, and it doesn't export a Windows
SAM/SYSTEM hive. Everything the cracker and shadow-viewer touch is
either a password you typed in yourself or a sample file bundled in
`sample_data/`. That's a deliberate scope cut: real hash-dumping
tooling is something you run in an isolated VM lab with your
instructor's sign-off, not something to hand out as downloadable code.
If your assignment specifically requires live extraction, do that part
manually in your lab environment and screenshot it for the report,
the rest of the suite (wordlists, strength checks, dictionary-attack
timing) still gives you real data to write up.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000`.

## Project layout

```
app.py                     Flask routes
modules/
  dictionary_gen.py        wordlist generation + mutations
  password_analyzer.py     entropy, rating, crack-time estimate
  cracker_demo.py          hashing + dictionary attack + shadow parser
templates/                 Jinja2 templates
static/style.css           styling
sample_data/demo_shadow.txt  fabricated sample shadow file
```
