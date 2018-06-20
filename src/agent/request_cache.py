

class Request(object):

    def __init__(self, address):

        self.address = address

    def __repr__(self):
        return "Request with %s" % self.address


class InitiatorRequest(Request):
    """The Request keeps track of one open interaction.
    """
    def __init__(self, address):
        super(InitiatorRequest, self).__init__(address)
        self.transfer_up = None


class ResponderRequest(Request):

    def __init__(self, address, chain):
        super(ResponderRequest, self).__init__(address)
        self.chain = chain
        self.index = None
        self.transfer_down = None


class RequestCache(object):
    """The request cache keeps track of started interactions with other agents. At the core is the
    dictionary of requests which contains the chain, the blocks exchanged etc.
    """

    def __init__(self):
        self.requests = []

    def new(self, address, chain=None):
        if chain is None:
            self.requests.append(InitiatorRequest(address))
        else:
            self.requests.append(ResponderRequest(address, chain))

    def get(self, address):
        return next((request for request in self.requests if request.address == address), None)

    def remove(self, address):
        self.requests = [request for request in self.requests if request.address != address]

    def __repr__(self):
        return "%s" % self.requests
