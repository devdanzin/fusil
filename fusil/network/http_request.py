import re

class HttpRequest:
    def __init__(self, data):
        self.method = None
        self.uri = None
        self.http_version = "1.0"
        self.host = None
        self.headers = []
        self.parse(data)

    def parse(self, data):
        state = "init"
        for line in data.splitlines():
            if state == "init":
                self.parseRequest(line)
                state = "host"
                continue
            if state == "host":
                match = re.match("host: (.*)$", line, re.IGNORECASE)
                if match:
                    self.host = match.group(1)
                    state = "keys"
                    continue
            if not line:
                continue
            line = line.split(":", 1)
            if len(line) == 1:
                raise SyntaxError("Unable to parse client header: %r" % line[0])
            key, value = line
            self.headers.append( (key, value) )

    def parseRequest(self, line):
        # Extract method
        match = re.match("^(GET|POST) (.*)$", line)
        if not match:
            raise SyntaxError("Unable to parse request method: %r" % line)
        line = match.group(2)
        self.method = match.group(1)

        # Extract HTTP version if present
        match = re.match("^(.*) HTTP/(1.[01])$", line)
        if match:
            line = match.group(1)
            self.http_version = match.group(2)

        # Rest is the URI
        self.uri = line

