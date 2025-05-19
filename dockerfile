FROM httpd:2.4.49-alpine
COPY ./vulnerable-httpd.conf /usr/local/apache2/conf/httpd.conf
RUN apk update && apk add bash
RUN apk add shadow
RUN apk add sudo
# RUN apk add python3
# RUN apk add py3-pip
# RUN apk add build-base
# RUN apk add libffi-dev
# RUN apk add openssl-dev
# RUN apk add cargo
# RUN apk add python3-dev
# RUN pip install pycryptodome
# RUN pip install "cryptography==36.0.2"

RUN adduser www-data root
RUN echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers