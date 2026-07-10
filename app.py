from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from google import genai

import json
import os
import re
import traceback

# ------------------------
# Flask App
# ------------------------

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static"
)

CORS(app)

# ------------------------
# Home Route
# ------------------------

@app.route("/")
def home():
    return send_from_directory("static", "index.html")

# ------------------------
# Gemini Client
# ------------------------

def get_gemini_client():

    env_key = os.getenv("GEMINI_API_KEY")

    if not env_key:
        raise Exception("Environment API key not found.")

    print("✅ Using Environment API Key")

    return genai.Client(api_key=env_key)
# ------------------------
# JSON Extractor
# ------------------------

def extract_json(text):

    text = text.replace("```json", "")
    text = text.replace("```", "")
    text = text.strip()

    try:
        return json.loads(text)

    except:

        start = text.find("{")
        end = text.rfind("}")

        if start != -1 and end != -1:

            return json.loads(
                text[start:end+1]
            )

        raise Exception(
            "Gemini returned invalid JSON."
        )

# ------------------------
# Analyze Route
# ------------------------

@app.route("/analyze", methods=["POST"])
def analyze_code():

    try:

        data = request.get_json()

        code = data.get("code", "").strip()
        language = data.get("language", "python")

        # Force latest model for now
        model = "gemini-2.5-flash"

        if not code:
            return jsonify({
                "error": "No code provided."
            }), 400

        prompt = f"""
        You are a Senior Application Security Engineer.

        Analyze the following {language} code for security vulnerabilities.

        CODE:
        {code}

        Find the TOP 3 most critical vulnerabilities.

        Return ONLY valid JSON.

        DO NOT use markdown.

        DO NOT explain outside JSON.

        Return EXACTLY this format:

        {{
        "overall_risk":"CRITICAL | HIGH | MEDIUM | LOW",

        "summary":"Overall security summary",

        "vulnerabilities":[
            {{
            "id":1,

            "title":"SQL Injection",

            "severity":"CRITICAL",

            "cwe":"CWE-89",

            "owasp":"A03:2021 Injection",

            "confidence":"98%",

            "line_reference":"query = ...",

            "description":"Explain why this is dangerous.",

            "impact":"What can happen if exploited.",

            "suggestion":"Short fix.",

            "mitigations":[
                "Mitigation 1",
                "Mitigation 2",
                "Mitigation 3"
            ],

            "fixed_code":"FULL corrected source code"
            }}
        ]
        }}

        Rules:

        1. Return maximum 3 vulnerabilities.

        2. fixed_code MUST contain the ENTIRE corrected source code.

        3. If there are fewer than 3 vulnerabilities,
        return only those found.

        4. JSON only.
        """
        client = get_gemini_client()

        print("=" * 80)
        print("Using Model:", model)
        print("=" * 80)

        response = client.models.generate_content(
            model=model,
            contents=prompt
        )

        print("=" * 80)
        print(response.text)
        print("=" * 80)

        result = extract_json(response.text)

        return jsonify(result)

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "error": str(e)
        }), 500
    
# ------------------------
# Apply Fix Route
# ------------------------

@app.route("/apply-fix", methods=["POST"])
def apply_fix():

    try:

        data = request.get_json()

        accepted_ids = data.get("accepted_ids", [])
        all_fixes = data.get("all_fixes", [])
        original_code = data.get("original_code", "")
        language = data.get("language", "python")

        # If only one vulnerability is accepted,
        # simply return its fixed code.
        if len(accepted_ids) == 1:

            for vuln in all_fixes:
                if vuln["id"] == accepted_ids[0]:
                    return jsonify({
                        "fixed_code": vuln["fixed_code"]
                    })

            return jsonify({
                "error": "Selected fix not found."
            }), 404

        # Multiple fixes accepted
        accepted = [
            v for v in all_fixes
            if v["id"] in accepted_ids
        ]

        prompt = f"""
You are a senior secure software engineer.

Merge all of the following security fixes into ONE final version.

Original {language} code:

{original_code}

Accepted fixes:

{json.dumps(accepted, indent=2)}

Rules:

1. Apply ALL fixes.
2. Keep the program working.
3. Do not remove functionality.
4. Return ONLY the complete fixed source code.
5. Do not use markdown.
"""

        client = get_gemini_client()

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )

        fixed = response.text.strip()

        fixed = fixed.replace("```python", "")
        fixed = fixed.replace("```", "").strip()

        return jsonify({
            "fixed_code": fixed
        })

    except Exception as e:

        traceback.print_exc()

        return jsonify({
            "error": str(e)
        }), 500
    
# ------------------------
# Run Server
# ------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("🚀 CodeGuard AI Started")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )