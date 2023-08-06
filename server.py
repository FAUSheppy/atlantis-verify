import hashlib                                                                                      
import os
import flask
import werkzeug
import argparse
import sys
import json
import datetime
import ldaptools

from keycloak import KeycloakAdmin

import sqlalchemy
from sqlalchemy import Column, Integer, String, Boolean, or_, and_, asc, desc
from flask_sqlalchemy import SQLAlchemy

app = flask.Flask("Atlantis Verfication")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLITE_LOCATION") or "sqlite:///sqlite.db"
db = SQLAlchemy(app)

class Verification(db.Model):
    
    __tablename__ = "verification"

    challenge_id = Column(String, primary_key=True)
    challenge_secret = Column(String, primary_key=True)
    dispatch_id = Column(String)
    ldap_user = Column(String)
    phone_number = Column(String)
    verification_type = Column(String) # signal, email

    # waiting_for_dispatch, received, waiting_for_response, bad_response, finished
    status = Column(String)

def update_status(verification):

    if verification.verification_type == "signal":
        if verification.status == "waiting_for_response":
            return
        elif verification.status == "waiting_for_dispatch":
            r = request.get(app.config["DISPATCH_SERVER"] + "?id={}".format(v.dispatch_id))
            if r.status == 404:
                v.status = "waiting_for_response"
                db.session.commit()
            else:
                return
        else:
            return # nothing to do
    else:
        raise NotImplementedError(verification.verification_type)


def email_challenge():
    pass
    # query keycloak api here:
    # # PUT https://keycloak.atlantishq.de/admin/realms/master/users/d1be393e-2fdf-40a5-9748-35bad4ebb7ed/execute-actions-email?lifespan=43200
    # # JSON Payload ["VERIFY_EMAIL"]

def signal_challenge():

    # add uid to db #
    challenge_id = secrets.token_url_safe(20)
    secret = secrets.token_url_safe(3)
    verification = Verification(challenge_id=challenge_id,
                                    challenge_secret=secret,
                                    ldap_user=user,
                                    phone_number=phone_number,
                                    verification_type="signal",
                                    status="waiting_for_dispatch")
    db.session.add(verification)
    db.session.commit()

    # send to event dispatcher #
    message = "Your verification code is {}.\n"
    message += "If you did not request this code please ignore this message "
    message += "or report it to root@atlantishq.de."
    payload = { "users": [user], "message" : message }
    request.post(app.config["DISPATCH_SERVER"], json=payload )

def verify_email(user):

    keycloak_admin = KeycloakAdmin(server_url=app.config["KEYCLOAK_URL"],
                            realm_name=app.config["KEYCLOAK_REALM"],
                            username=app.config["KEYCLOAK_ADMIN_USER"],
                            password=app.config["KEYCLOAK_ADMIN_PASS"])

    keycloak_users = keycloak_admin.get_users({ "username" : user })
    if len(keycloak_users) <= 0:
        raise ValueError("User not found: {}".format(user))
    else:
        user_id = keycloak_users[0].get("id")
        response = keycloak_admin.send_verify_email(user_id=user_id)
        print("Email Verification send for {}".format(user))

@app.route("/verify")
def verify_route():

    user = flask.request.headers.get("X-Forwarded-Preferred-Username")
   
    verify_type = flask.request.args.get("type")
    if not verify_type:
        return ("Missing mandetory parameter 'type' for verification", 500)
    elif verify_type == "signal":
        return flask.render_template("verify_email.html", user=user)
    elif verify_type == "email":
        verify_email(user)
        return ("", 204)
    else:
        return ("Unknown verification type {}".format(flask.request.args.type), 500)

@app.route("/challenge-response", methods=["GET", "POST"])
def c_response():

    if flask.request.method == "GET":

        cid = flask.request.args.get("cid")
        if not cid:
            return ("Missing cid (challenge_id)", 400)
        else:
            c = db.session.query(Verification).filter(Verification.challenge_id==cid).first()
            if not c:
                return ("Challenge not found", 404)
            else:
                update_status(c)
                return (c.status, 200)

    elif flask.request.method == "POST":

        cid = flask.request.args.get("cid")
        secrets = flask.request.args.get("secret")

        c = db.session.query(Verification).filter(Verification.challenge_id==cid).first()
        if not c:
            return ("Challenge not found", 404)
        elif secret != c.challenge_secret:
            return ("Secret Missmatch", 400)
        else:
            ldaptools.ldap_accept_verification(c)
            db.session.delete(c)
            db.session.commit()


@app.route("/")
def index():
    # query configured ldap email + phone
    # query email + phone verification status
    # display as [ email ] [ example@atlantishq.com ] [ verified? ] [ verify now ]

    user = flask.request.headers.get("X-Forwarded-Preferred-Username")
    if not user:
        return ("X-Forwarded-Preferred-Username header is empty or does not exist", 500)
    verifications = ldaptools.get_verifications_for_user(user, app)
    if not verifications:
        return ("User object for this user not found.", 500)

    print(verifications)

    return flask.render_template("index.html", verifications=verifications)

@app.route("/status")
def status():

    user = flask.request.headers.get("X-Forwarded-Preferred-Username")
    verifications = ldaptools.get_verifications_for_user(user, app)

    return json.dumps(verifications, indent=2)

def create_app():

    db.create_all()

    if not app.config.get("LDAP_NO_READ_ENV"):
        ldap_args = {
            "LDAP_SERVER"  : os.environ["LDAP_SERVER"],
            "LDAP_BIND_DN" : os.environ["LDAP_BIND_DN"],
            "LDAP_BIND_PW" : os.environ["LDAP_BIND_PW"],
            "LDAP_BASE_DN" : os.environ["LDAP_BASE_DN"]
        }
        app.config["LDAP_ARGS"] = ldap_args
        print("Setting LDAP_ARGS...")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='TM Replay Server',
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # general parameters #
    parser.add_argument("-i", "--interface", default="127.0.0.1", help="Interface to listen on")
    parser.add_argument("-p", "--port",      default="5000",      help="Port to listen on")
    parser.add_argument("--dispatch-server", required=True,       help="Dispatche Server")
    parser.add_argument('--engine', default="sqlite://",
                              help="e.g. postgresql+psycopg2://user:pass@localhost/dbname")

    parser.add_argument('--keycloak-url')
    parser.add_argument('--keycloak-realm', default="master")
    parser.add_argument('--keycloak-admin-pass')
    parser.add_argument('--keycloak-admin-user')

    parser.add_argument('--ldap-server')
    parser.add_argument('--ldap-base-dn')
    parser.add_argument('--ldap-manager-dn')
    parser.add_argument('--ldap-manager-password')

    args = parser.parse_args()

    # set app config #
    app.config["SQLALCHEMY_DATABASE_URI"] = args.engine
    app.config["KEYCLOAK_URL"] = args.keycloak_url
    app.config["KEYCLOAK_REALM"] = args.keycloak_realm
    app.config["KEYCLOAK_ADMIN_USER"] = args.keycloak_admin_user
    app.config["KEYCLOAK_ADMIN_PASS"] = args.keycloak_admin_pass

    # define ldap args #
    ldap_args = {
        "LDAP_SERVER" : args.ldap_server,
        "LDAP_BIND_DN" : args.ldap_manager_dn,
        "LDAP_BIND_PW" : args.ldap_manager_password,
        "LDAP_BASE_DN" : args.ldap_base_dn,
    }
    app.config["LDAP_NO_READ_ENV"] = True

    if not any([value is None for value in ldap_args.values()]):
        app.config["LDAP_ARGS"] = ldap_args
    else:
        app.config["LDAP_ARGS"] = None

    with app.app_context():
        create_app()

    app.run(host=args.interface, port=args.port, debug=True)
