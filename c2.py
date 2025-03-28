"""Command and Control HTTP server for communicating with implant"""

from http.server import HTTPServer, BaseHTTPRequestHandler


def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler):
    server_address = ("", 8000)
    httpd = server_class(server_address, handler_class)
    httpd.serve_forever()


def send_command(cmd):
    pass


def main():
    pass


if __name__ == "__main__":
    main()
