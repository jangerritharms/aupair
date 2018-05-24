"""
Module defining messages that agents can send to each other.
"""
import json

class MessageTypes(object):
    REGISTER = 1
    UNREGISTER = 2
    AGENT_REQUEST = 3
    AGENT_REPLY = 4
    BLOCK = 5
    BLOCK_REPLY = 6
    BLOCK_PAIR = 7
    CRAWL_REQUEST = 8
    CRAWL_REPLY = 9
    PA_REQUEST = 10
    PA_REPLY = 11
    PA_BLOCK_PROPOSAL = 12
    PA_BLOCK_ACCEPT = 13

class Message(object):
    """
    Message class defining an exchange of data between two agents.
    """

    def __init__(self, message_type, payload=None, sender=None):
        """
        Creates a message of given type and with the given payload.
        """

        self.type = message_type
        self.payload = payload
        self.sender = None

    def set_sender(self, sender):
        """Usually we would like to set the sender separate from the content.
        This function sets the origin of the message which can be useful for the
        replying agent.
        
        Arguments:
            sender {string} -- Address string of the receiving device of the 
                               sending agent.
        """
        self.sender = sender

    def to_json(self):
        """
        Converts the method to a json compatible format.
        """

        return json.dumps({
            "type": self.type,
            "payload": self.payload,
            "sender": self.sender
        })
