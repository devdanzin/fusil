Network server
==============

 - from fusil.network.server import NetworkServer
 - from fusil.network.tcp_server import TcpServer
 - from fusil.network.http_server import HttpServer

On new client connection, a ServerClient object is created.

Network client
==============

 - from fusil.network.client import NetworkClient
 - from fusil.network.tcp_client import TcpClient
 - from fusil.network.unix_client import UnixClient

TpcClient methods:

 * __init__(project, host, port, timeout=10.0): constructor
 * recvBytes(max_size=None, timeout=0.250, buffer_size=1024): Read max_size
   bytes by chunks of buffer_size bytes, stop after timeout seconds
 * sendBytes(bytes): send bytes on socket. Return False on error, True
   on success

TpcClient attributes:

 * host: host name/IP address
 * port: port number
 * timeout: socket timeout (in second)
 * tx_bytes: number of bytes sent to host
 * socket: socket object (set to None on error)

