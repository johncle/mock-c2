FROM httpd:2.4.50
RUN sed -i '1s|.*|#!/bin/bash|' /usr/local/apache2/cgi-bin/test-cgi
RUN chmod -R +x /usr/local/apache2/cgi-bin
CMD httpd-foreground -c "LoadModule cgid_module modules/mod_cgid.so"
EXPOSE 80
 