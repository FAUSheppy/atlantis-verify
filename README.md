# Debug
    
    # first terminal
    ssh -L 5005:localhost:389 usermanagement.atlantishq.de
    
    # second terminal
    cd ~/reps/atlantis-hub/
    docker run -v $(pwd)/nginx-dev-helper/nginx.conf:/etc/nginx/nginx.conf --add-host host.docker.internal:host-gateway -p 5001:5001 nginx
