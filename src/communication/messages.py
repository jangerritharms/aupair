"""
Module defining messages that agents can send to each other.
"""
import json
import src.communication.messages_pb2 as msg


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

type_to_attribute = {
    msg.REGISTER: "register",
    msg.AGENT_REPLY: "agent_reply",
    msg.AGENT_REQUEST: "empty",
    msg.UNREGISTER: "unregister",
    msg.BLOCK_PROPOSAL: "block",
    msg.BLOCK_AGREEMENT: "block",
    msg.PROTECT_CHAIN: "db",
    msg.PROTECT_BLOCKS_REQUEST: "index",
    msg.PROTECT_BLOCKS_REPLY: "db",
    msg.PROTECT_CHAIN_BLOCKS: "db",
    msg.PROTECT_BLOCK_PROPOSAL: "block",
    msg.PROTECT_BLOCK_AGREEMENT: "block"
}


class NewMessage(object):

    def __init__(self, message_type, payload):
        """Creates a message of given type and with the given payload.
        """

        self.message = msg.WrapperMessage()
        self.message.type = message_type

        self.message.__getattribute__(type_to_attribute[message_type]).CopyFrom(payload)

    def set_sender(self, address):
        self.message.address = address

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
