# Debug

    # first terminal
    ssh -L 5005:localhost:389 usermanagement.atlantishq.de

    # second terminal
    cd ~/reps/atlantis-hub/
    docker run -v $(pwd)/nginx-dev-helper/nginx.conf:/etc/nginx/nginx.conf --add-host host.docker.internal:host-gateway -p 5001:5001 nginx

# Compose

    atlantis-verify:
        image: harbor-registry.atlantishq.de/atlantishq/atlantis-verify:latest
        restart: always
        env:

            LDAP_SERVER=
            LDAP_BIND_DN=
            LDAP_BIND_PW=
            LDAP_BASE_DN=

            DISPATCH_SERVER=

            SQLALCHEMY_DATABASE_URI="instance/database.sqlite"

            KEYCLOAK_URL=
            KEYCLOAK_REALM=
            KEYCLOAK_ADMIN_USER=
            KEYCLOAK_ADMIN_PASS=

            MAIN_HOME=

            DISPATCH_AUTH_USER=
            DISPATCH_AUTH_PASSWORD=

            NTFY_ACCESS_TOKEN=
            NTFY_API_TARGET=
            NTFY_PUSH_TARGET=

        ports:
            - 6012:5000
        volumes:
            - /data/atlantis-verify/instance/:/app/instance/
