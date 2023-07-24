class Verification(db.model):
    
    __tablename__ = "verification"

    challenge_secret = Column(String, primary_key=True)
    ldap_user = Column(String)
    phone_number = Column(String)
    verification_type = Column(String) # signal
    status = Column(String) # requesting, dispatching, waiting_for_response, bad_response, finished


def signal_challenge():
    # add uid to db
    # dispatch signal message

@route("/challenge-response")
def index():
    # queried from the signal log watcher


@route("/")
def index():
    # query configured ldap email + phone
    # query email + phone verification status
    # display as [ email ] [ example@atlantishq.com ] [ verified? ] [ verify now ]
