from flask import Flask, request, render_template_string
import json

app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>CloudGuard Security Scanner</title>

    <style>
    body {
        font-family: "Segoe UI", Arial, sans-serif;
        color: #e5e7eb;
        min-height: 100vh;
        margin: 0;
        padding: 0;
        overflow-x: hidden;
        letter-spacing: 0.3px;
    }

    /* Video Background */
    #bg-video {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        object-fit: cover;
        z-index: -1;
        filter: brightness(0.6) contrast(1.2);
    }

    /* Glass Container */
    .container {
        width: 80%;
        max-width: 760px;
        margin: 80px auto;
        background: rgba(0, 0, 0, 0.65);
        backdrop-filter: blur(8px);
        padding: 35px;
        border-radius: 16px;
        box-shadow: 0 0 25px rgba(255, 0, 0, 0.15);
        border: 1px solid rgba(255, 0, 0, 0.25);
        animation: fadeIn 1.2s ease;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(30px); }
        to { opacity: 1; transform: translateY(0); }
    }

    h2 {
    text-align: center;
    margin-bottom: 30px;
    font-size: 40px;
    /* Old red gradient */
    /* background: linear-gradient(90deg, #ff4d4d, #ff0000, #ff4d4d); */

    /* New blue gradient */
    background: linear-gradient(90deg, #4fd1fe, #3b82f6, #60a5fa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    text-shadow: 0 0 12px rgba(63, 132, 246, 0.6); /* soft blue glow */
    letter-spacing: 1.5px;
}

    h1{
        text-align: center;
        margin-bottom: 30px;
        font-size: 60px;
        background: linear-gradient(90deg, #ff4d4d, #ff0000, #ff4d4d);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 0 0 12px rgba(255, 0, 0, 0.6);
        letter-spacing: 1.5px;
    }

    .upload-box {
        text-align: center;
        margin-bottom: 25px;
    }

    input[type="file"] {
        background: rgba(0,0,0,0.6);
        color: #fff;
        padding: 10px;
        border-radius: 6px;
        border: 1px solid rgba(255,0,0,0.3);
    }

    button {
        background: linear-gradient(135deg, #ff1a1a, #b30000);
        color: #fff;
        border: none;
        padding: 11px 28px;
        margin-left: 10px;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
        letter-spacing: 0.5px;
        box-shadow: 0 0 10px rgba(255,0,0,0.6);
        transition: 0.3s ease;
    }

    button:hover {
        transform: scale(1.08);
        box-shadow: 0 0 18px rgba(255,0,0,0.9);
    }

    h3 {
        margin-top: 35px;
        padding-bottom: 10px;
        border-bottom: 1px solid rgba(255,255,255,0.2);
        color: #fca5a5;
        letter-spacing: 1px;
    }

    ul {
        list-style: none;
        padding: 0;
        margin-top: 15px;
    }

    li {
        background: rgba(0,0,0,0.55);
        margin: 14px 0;
        padding: 16px;
        border-radius: 10px;
        border: 1px solid rgba(255,255,255,0.08);
        box-shadow: inset 0 0 8px rgba(255,255,255,0.05);
        animation: slideUp 0.4s ease;
    }

    @keyframes slideUp {
        from { opacity: 0; transform: translateY(15px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .HIGH {
        border-left: 6px solid #ff1a1a;
        box-shadow: 0 0 12px rgba(255, 26, 26, 0.6);
    }

    .MEDIUM {
        border-left: 6px solid #facc15;
        box-shadow: 0 0 10px rgba(350, 204, 21, 0.6);
    }

    .SAFE {
        border-left: 6px solid #22c55e;
        box-shadow: 0 0 10px rgba(34, 197, 94, 0.6);
    }

    footer {
        text-align: center;
        margin-top: 25px;
        font-size: 13px;
        color: #9ca3af;
        letter-spacing: 0.6px;
    }
</style>

</head>

<body>

<!-- Video Background -->
<video autoplay muted loop id="bg-video">
    <source src="/static/background.mp4" type="video/mp4">
</video>

<div class="container">
  
    <h1>
        <img src="/static/cloudgaurd_logo.png" alt="CloudGuard Logo" style="width:500px; height:500px; vertical-align:middle; margin-right:10px;">
        
    </h1>
   



    <h2>Cloud Misconfiguration Scanner</h2>

    <div class="upload-box">
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" required>
            <button type="submit">Scan</button>
        </form>
    </div>

    {% if results %}
        <h3>🔍 Scan Results</h3>
        <ul>
        {% for r in results %}
            <li class="{{r['severity']}}">
                <b>{{r["severity"]}}</b> - {{r["issue"]}}
                <br>✅ Fix: {{r["fix"]}}
            </li>
        {% endfor %}
        </ul>
    {% endif %}

    <footer>
        Made with ❤️ by Tomhacker69
    </footer>
</div>

</body>
</html>
"""

def scan_config(data):
    issues = []

    if data.get("storage_public") == True:
        issues.append({
            "severity": "HIGH",
            "issue": "Storage bucket is public",
            "fix": "Disable public access"
        })

    open_ports = data.get("open_ports", [])
    if 22 in open_ports or 80 in open_ports:
        issues.append({
            "severity": "MEDIUM",
            "issue": "Sensitive ports are open",
            "fix": "Restrict firewall rules"
        })

    if data.get("admin_access") == True:
        issues.append({
            "severity": "HIGH",
            "issue": "Admin access enabled",
            "fix": "Apply least privilege policy"
        })

    if data.get("encryption_enabled") == False:
        issues.append({
            "severity": "MEDIUM",
            "issue": "Encryption disabled",
            "fix": "Enable encryption"
        })

    if not issues:
        issues.append({
            "severity": "SAFE",
            "issue": "No misconfiguration detected",
            "fix": "System is secure"
        })

    return issues


@app.route("/", methods=["GET", "POST"])
def index():
    results = None

    if request.method == "POST":
        file = request.files["file"]
        data = json.load(file)
        results = scan_config(data)

    return render_template_string(HTML_PAGE, results=results)


if __name__ == "__main__":
    app.run(debug=True)
