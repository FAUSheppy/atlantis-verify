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

def topic(target, token, user):
    '''Create user with a topic ACL'''

    params = {
        "user" : user,
        "token" : token,
    }

    r = requests.get(target + "/topic", params=params)
    if r.status_code == 404:
        rp = requests.put(target + "/topic", params=params)
        rp.raise_for_status()
        r = requests.get(target + "/topic", params=params)

    r.raise_for_status()
    print(r.content)
    topic_name = r.json()["topic"]
    return topic_name
