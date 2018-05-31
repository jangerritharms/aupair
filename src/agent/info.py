import src.communication.messages_pb2 as msg
from src.public_key import PublicKey


class AgentInfo(object):
    """The AgentInfo class stores the information neccessary for identifying and connecting to the
    agent it describes.
    """

    def __init__(self, public_key, address):
        """Creates a new AgentInfo object by passing the neccessary information.

        Arguments:
            public_key {PublicKey} -- Public key of the agent this object describes
            address {Address} -- Address of the receiving socket of the agent this object describes
        """

        self.public_key = public_key
        self.address = address

    def as_message(self):
        """Creates a protobuf message representation of the given AddInfo instance.

        Returns:
            msg.AddInfo -- AddInfo message which can be sent over the network.
        """

        message = msg.AgentInfo()
        message.public_key = self.public_key.as_hex()
        message.address = self.address

        return message

    @classmethod
    def from_agent(cls, agent):
        """Creates a new AgentInfo object which describes the passed agent.

        Arguments:
            agent {BaseAgent} -- Agent which shall be described by the return AddInfo object.

        Returns:
            AddInfo -- AddInfo object describing agent.
        """

        return cls(agent.public_key, agent.com.address)

    @classmethod
    def from_message(cls, message):
        """Creates a new AgentInfo object from a passed message.

        Arguments:
            message {msg.AddInfo} -- AddInfo protobuf message object.

        Returns:
            AddInfo -- AddInfo object describing the same agent as the message.
        """
        return cls(PublicKey.from_hex(message.public_key), message.address)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__
