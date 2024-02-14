import requests

def create(target, token, user_obj):
    '''Create user with a topic ACL'''

    params = {
        "user" : user_obj.user,
        "topic" : user_obj.topic,
        "password" : user_obj.password,
        "token" : token,
    }

    r = requests.put(target + "/access-and-user", params=params)
    r.raise_for_status()
