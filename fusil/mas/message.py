class Message:
    def __init__(self, event, arguments):
        self.event = event
        self.arguments = arguments

    def __repr__(self):
        return '<Message event=%r arguments#=%s>' % (
            self.event, len(self.arguments))

    def __call__(self, agent):
        try:
            function = "on_%s" % self.event
            function = getattr(agent, function)
        except AttributeError:
            return
        function(*self.arguments)

