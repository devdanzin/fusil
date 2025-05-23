from socket import SHUT_RDWR
from socket import error as socket_error
from socket import timeout as socket_timeout
from weakref import ref as weakref_ref

from ptrace.error import formatError

from fusil.network.tools import formatAddress
from fusil.session_agent import SessionAgent


class ServerClientDisconnect(Exception):
    pass


class ServerClient(SessionAgent):
    def __init__(self, session, server, socket, address, family):
        self.server = weakref_ref(server)
        self.socket = socket
        self.address = address
        self.family = family
        name = "net_client:" + formatAddress(self.family, self.address, short=True)
        SessionAgent.__init__(self, session, name)
        self.tx_bytes = 0
        self.rx_bytes = 0

    def recvBytes(self, buffer_size=1024):
        log_data_exchange = self.server().log_data_exchange
        datas = []
        while True:
            try:
                self.socket.settimeout(0.010)
                data = self.socket.recv(buffer_size)
            except socket_timeout:
                break
            except socket_error as err:
                errcode = err[0]
                if errcode == 11:  # Resource temporarily unavailable
                    break
                else:
                    self.close()
                    break
            if not data:
                break
            data_len = len(data)
            self.rx_bytes += data_len
            if log_data_exchange:
                self.warning("Read bytes: (%s) %r" % (data_len, data))
            datas.append(data)

        if not datas:
            self.close()
            return None
        return "".join(datas)

    def sendBytes(self, data, buffer_size=None):
        log_data_exchange = self.server().log_data_exchange
        index = 0
        while index < len(data):
            if buffer_size:
                chunk = data[index : index + buffer_size]
            else:
                chunk = data[index:]
            if log_data_exchange:
                self.warning("Send bytes: (%s) %r" % (len(chunk), chunk))
            try:
                count = self.socket.send(chunk)
                index += count
                self.tx_bytes += count
            except socket_error as err:
                self.warning("Send error: %s" % formatError(err))
                self.close()
                break

    def close(self, emit_exception=True):
        if not self.socket:
            return
        self.info("Close socket")
        self.socket.shutdown(SHUT_RDWR)
        self.socket.close()
        self.socket = None
        if emit_exception:
            raise ServerClientDisconnect()

    def destroy(self):
        if self.socket:
            self.close(False)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return "<%s %s>" % (
            self.__class__.__name__,
            formatAddress(self.family, self.address),
        )
