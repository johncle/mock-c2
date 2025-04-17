FROM httpd:2.4.49-alpine
COPY ./vulnerable-httpd.conf /usr/local/apache2/conf/httpd.conf
RUN apk update && apk add bash
RUN apk add --no-cache python3 py3-pip