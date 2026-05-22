"""
target_app/app.py — simple dummy target application.
Represents the service the WAF is protecting.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/")
def index():
    return """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Target App</title>
<style>
  body { font-family: sans-serif; max-width: 640px; margin: 4rem auto; padding: 0 1rem; }
  h1 { font-size: 1.5rem; margin-bottom: 1rem; }
  p  { color: #555; }
  form { margin-top: 2rem; display: flex; flex-direction: column; gap: 8px; max-width: 320px; }
  input { padding: 8px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; }
  button { padding: 8px 16px; background: #4f46e5; color: #fff; border: none;
           border-radius: 6px; cursor: pointer; font-size: 14px; }
</style>
</head>
<body>
  <h1>🎯 Target Application</h1>
  <p>This app is protected by <strong>WAFisGoingOn</strong>.</p>
  <p>Try submitting a normal login, then try an injection payload — the WAF will block it.</p>
  <form method="POST" action="/login">
    <input name="userName" placeholder="Username" />
    <input name="password" type="password" placeholder="Password" />
    <button type="submit">Log in</button>
  </form>
</body>
</html>"""


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("userName", "")
    password = request.form.get("password", "")
    # Deliberately naive — the WAF should catch attacks before they reach here
    if username == "admin" and password == "secret":
        return jsonify({"status": "ok", "message": "Welcome, admin!"})
    return jsonify({"status": "fail", "message": "Invalid credentials"}), 401


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"query": q, "results": [f"Result for: {q}"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
