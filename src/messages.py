"""
Module defining messages that agents can send to each other.
"""
import json

class MessageTypes(object):
    REGISTER = 1
    UNREGISTER = 2

class Message(object):
    """
    Message class defining an exchange of data between two agents.
    """

    def __init__(self, message_type, sender, payload=None):
        """
        Creates a message of given type and with the given payload.
        """

        self.type = message_type
        self.payload = payload
        self.sender = sender 

    def to_json(self):
        """
        Converts the method to a json compatible format.
        """

        return json.dumps({
            "type": self.type,
            "payload": self.payload,
            "sender": self.sender.encode('hex')
        })
