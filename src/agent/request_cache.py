

class Request(object):

    def __init__(self, initial_state, address):

        self.address = address
        self.state = initial_state

    def __repr__(self):
        return "Request with %s" % self.address

    def update_state(self, state):
        self.state = state

    def in_state(self, state):
        return self.state == state


class InitiatorRequest(Request):
    """The Request keeps track of one open interaction.
    """
    def __init__(self, initial_state, address):
        super(InitiatorRequest, self).__init__(initial_state, address)
        self.transfer_up = None


class ResponderRequest(Request):

    def __init__(self, initial_state, address, chain):
        super(ResponderRequest, self).__init__(initial_state, address)
        self.chain = chain
        self.index = None
        self.transfer_down = None


class RequestState:

    NONE = 0
    PROTECT_INIT = 1
    PROTECT_INDEX = 2
    PROTECT_EXCHANGE = 3
    PROTECT_BLOCK = 4
    PROTECT_DONE = 5
    PROTECT_EXCHANGE_CLARIFICATION_RESPONDER = 6
    PROTECT_EXCHANGE_CLARIFICATION_INITIATOR = 7


class RequestCache(object):
    """The request cache keeps track of started interactions with other agents. At the core is the
    dictionary of requests which contains the chain, the blocks exchanged etc.
    """

    def __init__(self):
        self.requests = []

    def new(self, address, initial_state, chain=None):
        if chain is None:
            self.requests.append(InitiatorRequest(initial_state, address))
        else:
            self.requests.append(ResponderRequest(initial_state, address, chain))

    def get(self, address):
        return next((request for request in self.requests if request.address == address), None)

    def remove(self, address):
        self.requests = [request for request in self.requests if request.address != address]

    def __repr__(self):
        return "%s" % self.requests
