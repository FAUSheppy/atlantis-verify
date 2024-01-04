FROM alpine

RUN apk add --no-cache py3-pip py3-ldap

RUN mkdir /app
WORKDIR /app
COPY ./ .

RUN python3 -m pip install --no-cache-dir --break-system-packages waitress

COPY req.txt .

# remove python-ldap (installed via apk) #
RUN sed -i '/^python-ldap.*$/d' req.txt

RUN python3 -m pip install --no-cache-dir --break-system-packages -r req.txt

EXPOSE 5000/tcp

ENTRYPOINT ["waitress-serve"] 
CMD ["--host", "0.0.0.0", "--port", "5000", "--call", "app:createApp"]
