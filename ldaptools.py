import ldap
def ldap_accept_verification(verification, app):

    ldap_args = app.config["LDAP_ARGS"]

    if verification.verification_type == "signal":

        ldap_server = ldap_args["LDAP_SERVER"]
        manager_dn = ldap_args["LDAP_BIND_DN"]
        manager_pw = ldap_args["LDAP_BIND_PW"]
        base_dn = ldap_args["LDAP_BASE_DN"]

        # estabilish connection 
        conn = ldap.initialize(ldap_server) 
        conn.simple_bind_s(manager_dn, manager_password) 
  
        # search in scope # 
        # TODO: update LDAP here
        # search_scope = ldap.SCOPE_SUBTREE 
        # search_results = conn.search_s(base_dn, search_scope, search_filter) 
        
        # unbind from connection and return # 
        conn.unbind_s() 
        return search_results 

    else:
        raise NotImplementedError(verification.verification_type)

def get_verifications_for_user(user, app):

    ldap_args = app.config["LDAP_ARGS"]
    search_filter = "(&(objectClass=inetOrgPerson)(uid={username}))".format(username=user)

    if verification.verification_type == "signal":

        ldap_server = ldap_args["LDAP_SERVER"]
        manager_dn = ldap_args["LDAP_BIND_DN"]
        manager_pw = ldap_args["LDAP_BIND_PW"]
        base_dn = ldap_args["LDAP_BASE_DN"]

        # estabilish connection 
        conn = ldap.initialize(ldap_server) 
        conn.simple_bind_s(manager_dn, manager_password) 
  
        # search in scope # 
        search_scope = ldap.SCOPE_SUBTREE 
        search_results = conn.search_s(base_dn, search_scope, search_filter) 
        
        # unbind from connection and return # 
        conn.unbind_s() 

        if len(search_filter) == 0:
            return None
        else:
            cn, entry = search_results[0]
       
        print(cn, entry)
        return entry.status

    else:
        raise NotImplementedError(verification.verification_type)
