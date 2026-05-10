from flask import Flask, request, render_template_string
import json

app = Flask(__name__)

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
