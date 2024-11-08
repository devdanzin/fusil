from socket import AF_INET
from fusil.network.server import NetworkServer
from fusil.network.tools import formatAddress

class TcpServer(NetworkServer):
    def __init__(self, project, port, host=''):
        name = "tcp_server:" + formatAddress(AF_INET, (host, port), short=True)
        NetworkServer.__init__(self, project, name)
        self.host = host
        self.port = port

    def init(self):
        if self.socket:
            return
        self.bind(address=(self.host, self.port))

