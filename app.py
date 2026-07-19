import os
from flask import Flask, redirect, url_for, session, render_template_string, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import datetime

# Load environmental configurations
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Initialize Authlib OAuth/OIDC client
oauth = OAuth(app)
oauth.register(
    name="oidc_provider",
    client_id=os.getenv("OIDC_CLIENT_ID"),
    client_secret=os.getenv("OIDC_CLIENT_SECRET"),
    server_metadata_url=os.getenv("OIDC_CONF_URL"),
    client_kwargs={
        "scope": "openid profile email" , 
        "verify": False },
)

# ----------------- HTML TEMPLATES -----------------
INDEX_TEMPLATE = """
<h1>Welcome to the Flask OIDC App</h1>
{% if user %}
    <p>Logged in as: <strong>{{ user.name }}</strong> ({{ user.email }})</p>
    <a href="{{ url_for('profile') }}"><button>View Claims Profile</button></a> | 
    <a href="{{ url_for('logout') }}"><button>Logout</button></a>
{% else %}
    <p>You are not logged in.</p>
    <a href="{{ url_for('login') }}"><button>Sign In via OIDC</button></a>
{% endif %}
"""

PROFILE_TEMPLATE = """
<h1>User OIDC Claims Information</h1>
<p>Below are the claims decoded and validated directly from your ID token:</p>

<img src={{ claims['picture'] }} >

<table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse;">
    <thead>
        <tr style="background-color: #f2f2f2;">
            <th>Claim</th>
            <th>Value</th>
        </tr>
    </thead>
    <tbody>
        {% for key, val in claims.items() %}
        <tr>
            <td><strong>{{ key }}</strong></td>
            <td>{{ val }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
<br>
<a href="{{ url_for('index') }}">Back to Home</a>
"""

# ----------------- APPLICATIONS ROUTES -----------------

@app.route("/")
def index():
    user = session.get("user")
    return render_template('index.html', user=user)
#    return render_template_string(INDEX_TEMPLATE, user=user)


@app.route("/login")
def login():
    # Generate redirect URI targeting our authorized callback route
    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.oidc_provider.authorize_redirect(redirect_uri)


@app.route("/callback")
def auth_callback():
    # Exchange code for tokens and automatically validate signatures and claims
    token = oauth.oidc_provider.authorize_access_token()
    
    # Extract the validated ID Token data containing user profile claims
    user_claims = token.get("userinfo")
    
    if user_claims:
        session["user"] = user_claims  # Safely persist claims inside server-signed session cookie
        
    return redirect(url_for("index"))


@app.route("/profile")
def profile():
    user_claims = session.get("user")
    if not user_claims:
        return redirect(url_for("login"))  # Protect endpoint against unauthenticated traffic
        
    return render_template("profile.html", claims=user_claims, datetime=datetime.datetime)
#    return render_template_string(PROFILE_TEMPLATE, claims=user_claims)


@app.route("/logout")
def logout():
    session.pop("user", None)  # Wipe user claims from session storage
    return redirect(url_for("index"))


if __name__ == "__main__":
    # Ensure application runs securely over HTTPS locally or using development defaults
    app.run(host="127.0.0.1", port=5000, debug=True)

