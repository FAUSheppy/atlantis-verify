import ldap
def ldap_accept_verification(verification, app):

    ldap_args = app.config["LDAP_ARGS"]
    print(verification.ldap_user)

    if verification.verification_type == "signal":

        ldap_server = ldap_args["LDAP_SERVER"]
        manager_dn = ldap_args["LDAP_BIND_DN"]
        manager_pw = ldap_args["LDAP_BIND_PW"]
        base_dn = ldap_args["LDAP_BASE_DN"]

        # estabilish connection 
        conn = ldap.initialize(ldap_server) 
        conn.simple_bind_s(manager_dn, manager_pw) 
 
        user = verification.ldap_user
        search_filter = "(&(objectClass=inetOrgPerson)(uid={username}))".format(username=user)
        search_scope = ldap.SCOPE_SUBTREE 
        search_results = conn.search_s(base_dn, search_scope, search_filter) 

        # check and modify #
        if len(search_results) == 0:
            raise ValueError("User {} not found in LDAP, cannot modify".format(user))
        else:
            user_cn, entry = search_results[0]

        modified_entry = [(ldap.MOD_ADD, "signalVerified", b"TRUE")]
        conn.modify_s(user_cn, modified_entry)

        modified_entry = [(ldap.MOD_REPLACE, "signalVerified", b"TRUE")]
        conn.modify_s(user_cn, modified_entry)

        # unbind from connection and return # 
        conn.unbind_s() 
        return search_results 

    else:
        raise NotImplementedError(verification.verification_type)

def get_verifications_for_user(user, app):

    ldap_args = app.config["LDAP_ARGS"]
    search_filter = "(&(objectClass=inetOrgPerson)(uid={username}))".format(username=user)

    ldap_server = ldap_args["LDAP_SERVER"]
    manager_dn = ldap_args["LDAP_BIND_DN"]
    manager_pw = ldap_args["LDAP_BIND_PW"]
    base_dn = ldap_args["LDAP_BASE_DN"]

    print(ldap_args)
    print(user)

    # estabilish connection 
    conn = ldap.initialize(ldap_server) 
    conn.simple_bind_s(manager_dn, manager_pw) 
  
    # search in scope # 
    search_scope = ldap.SCOPE_SUBTREE 
    search_results = conn.search_s(base_dn, search_scope, search_filter) 
    
    # unbind from connection and return # 
    conn.unbind_s() 

    if len(search_results) == 0:
        return None
    else:
        cn, entry = search_results[0]
    
    print(cn, entry)

    # check email_verified boolean #
    email_verified = entry.get("emailVerified")
    if email_verified and len(email_verified) >= 0 and email_verified[0]:
        email_verified = True

    # check signal verified boolean #
    signal_verified = entry.get("signalVerified")
    if signal_verified and len(signal_verified) >= 0 and signal_verified[0]:
        signal_verified = True

    # get email address #
    email_address = entry.get("mail")
    if email_address and len(email_address) >= 0 and email_address[0]:
        email_address = email_address[0].decode("utf-8")

    # get phone number address #
    phone_number = entry.get("telephoneNumber")
    if phone_number and len(phone_number) >= 0 and phone_number[0]:
        phone_number = phone_number[0].decode("utf-8")

    # build response #
    verifications = { "email" : email_verified, "signal" : signal_verified }
    data = { "email_address" : email_address, "phone_number" : phone_number }
    keywords = { "verifications" : verifications, "data" : data }

    return keywords
