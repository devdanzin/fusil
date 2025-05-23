from fusil.network.http_request import HttpRequest
from fusil.network.server_client import ServerClientDisconnect
from fusil.network.tcp_server import TcpServer


class HttpServer(TcpServer):
    def __init__(self, *args):
        TcpServer.__init__(self, *args)
        self.http_version = "1.0"

    def clientRead(self, client):
        # Read data
        try:
            data = client.recvBytes()
        except ServerClientDisconnect:
            self.clientDisconnection(client)
            return
        if not data:
            return

        # Process data
        request = HttpRequest(data)
        self.serveRequest(client, request)

    def serveRequest(self, client, request):
        url = request.uri[1:]
        if not url:
            url = "index.html"
        if url == "index.html":
            self.serveData(
                client, 200, "OK", "<html><body><p>Hello World!</p></body></html>"
            )
        else:
            self.error404(client, url)

    def error404(self, client, url):
        self.warning("Error 404: %r" % url)
        self.serveData(client, 404, "Not Found")

    def serveData(self, client, code, code_text, data=None, content_type="text/html"):
        if data:
            data_len = len(data)
        else:
            data_len = 0
        http_headers = [
            ("Server", "Fusil"),
            ("Pragma", "no-cache"),
            ("Content-Type", content_type),
            ("Content-Length", str(data_len)),
        ]
        try:
            header = "HTTP/%s %s %s\r\n" % (self.http_version, code, code_text)
            for key, value in http_headers:
                header += "%s: %s\r\n" % (key, value)
            header += "\r\n"
            if data:
                data = header + data
            else:
                data = header
            client.sendBytes(data)
            client.close()
        except ServerClientDisconnect:
            self.clientDisconnection(client)
