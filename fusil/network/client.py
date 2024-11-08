from errno import EAGAIN
from socket import SHUT_RDWR
from socket import error as socket_error
from socket import socket
from socket import timeout as socket_timeout
from time import time

from ptrace.error import formatError, writeError

from fusil.network.tools import formatAddress
from fusil.project_agent import ProjectAgent


class NetworkClient(ProjectAgent):
    def __init__(self, project, name):
        ProjectAgent.__init__(self, project, name)
        self.log_data_exchange = False

    def init(self):
        self.socket = None
        self.tx_bytes = 0
        self.rx_bytes = 0

    def connect(self, address, family, type, timeout=5.0):
        try:
            self.info("Create socket (family %s, type %s)" % (
                family, type))
            self.socket = socket(family, type)
            self.socket.settimeout(timeout)
            self.info("Connect to %s" % formatAddress(family, address))
            self.socket.connect(address)
        except socket_error as err:
            writeError(self, err, "Unable to connect to %s" %
                formatAddress(family, address))
            self.socket = None
            self.send('application_error', 'Network connection failure')

    def deinit(self):
        if self.socket:
            self.socket.close()
        info = []
        if self.tx_bytes:
            info.append("TX bytes:%s" % self.tx_bytes)
        if self.rx_bytes:
            info.append("RX bytes:%s" % self.rx_bytes)
        if info:
            self.warning(", ".join(info))

    def on_session_stop(self):
        self.closeSocket()

    def closeSocket(self):
        if self.socket:
            try:
                self.socket.shutdown(SHUT_RDWR)
            except socket_error:
                pass
            self.socket.close()
        self.socket = None

    def sendBytes(self, data, timeout=0):
        if self.socket is None:
            self.error("Error: socket is not initialized!")
            return False
        self.tx_bytes += len(data)
        if self.log_data_exchange:
            self.warning("Send bytes: (%s) %r (timeout=%s)" % (
                len(data), data, timeout))
        try:
            self.socket.settimeout(timeout)
            self.socket.send(data)
        except socket_error as err:
            self.warning("Send error: %s" % formatError(err))
            self.closeSocket()
            self.send('session_stop')
            return False
        return True

    def recvBytes(self, max_size=None, timeout=0.250, buffer_size=1024):
        if self.socket is None:
            self.error("Error: socket is not initialized!")
            return None

        datas = []
        data_len = 0
        time_end = time() + timeout
        while True:
            if (not datas) and (not timeout):
                # First step in non blocking mode
                time_diff = 0
            else:
                time_diff = time_end - time()
                if time_diff < 0:
                    break
            if max_size is not None and max_size <= data_len:
                break
            try:
                self.socket.settimeout(time_diff)
                data = self.socket.recv(buffer_size)
            except socket_timeout:
                break
            except socket_error as err:
                code = err.args[0]
                if not time_diff and code == EAGAIN:
                    break
                self.warning("Receive error: %s" % formatError(err))
                self.closeSocket()
                self.send('session_stop')
                break
            if not data:
                break
            if self.log_data_exchange:
                self.warning("Receive bytes: (%s) %r" % (len(data), data))
            datas.append(data)
            data_len += len(data)
            self.rx_bytes += data_len

        if datas:
            data = ''.join(datas)
            return data
        else:
            return None

