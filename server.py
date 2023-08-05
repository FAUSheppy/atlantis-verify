class Verification(db.model):
    
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
                                    verification_type="signal"
                                    status="waiting_for_dispatch")
    db.session.add(verification)
    db.session.commit()

    # send to event dispatcher #
    message = "Your verification code is {}.\n"
    message += "If you did not request this code please ignore this message "
    message += "or report it to root@atlantishq.de."
    payload = { "users": [user], "message" : message }
    request.post(app.config["DISPATCH_SERVER"], json=payload )

@route("/challenge-response", method=["GET", "POST"])
def index():

    if flask.request.method = "GET":

        cid = flask.request.args.get("cid")
        if not challenge_id:
            return (400, "Missing cid")
        else:
            c = db.session.query(Verification).filter(Verification.challenge_id==cid).first()
            if not c:
                return (404, "Challenge not found")
            else:
                update_status(c)
                return (200, c.status)

    elif flask.request.method == "POST":

        cid = flask.request.args.get("cid")
        secrets = flask.request.args.get("secret")

        c = db.session.query(Verification).filter(Verification.challenge_id==cid).first()
        if not c:
            return (404, "Challenge not found")
        elif secret != c.challenge_secret:
            return (400, "Secret Missmatch")
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
    verifications = ldaptools.get_verifications_for_user(user, app)

    return flask.render_template("index.html", verifications=verifications)

@app.route("/status")
def status():

    user = flask.request.headers.get("X-Forwarded-Preferred-Username")
    verifications = ldaptools.get_verifications_for_user(user, app)

    return json.dumps(verifications, indent=2)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='TM Replay Server',
                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # general parameters #
    parser.add_argument("-i", "--interface", default="127.0.0.1", help="Interface to listen on")
    parser.add_argument("-p", "--port",      default="5000",      help="Port to listen on")
    parser.add_argument("--dispatch-server", required=True,       help="Dispatche Server")
    parser.add_argument('--engine', default="sqlite://",
                              help="e.g. postgresql+psycopg2://user:pass@localhost/dbname")
    args = parser.parse_args()

    # startup #
    with app.app_context():
        create_app()

    app.run(host=args.interface, port=args.port)
