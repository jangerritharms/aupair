"""This module defines the classes used for handling messages.
"""
import logging


class MessageHandler:
    """Decorator that defines the decorated function as a handler for a certain
    message type. This works in conjunction with the MessageProcessor class which
    registers the handlers and handles incoming messages.

    Example:

        @MessageHandler('hello')
        def hello_handler():
            [...]

    """
    def __init__(self, message_type):
        """Creates a handler for the given type of message.

        Arguments:
            message_type {MessageTypes} -- Type of the message to handle.
        """

        self.handler_data = message_type

    def __call__(self, func):
        func._message_handler = self.handler_data
        return func


class MessageHandlerType(type):
    """Metaclass which registers all functions marked by the MessageHandler decorator
    as handlers for message types. The dictionary _message_handlers stores those and
    can be accessed by classes implementing this metaclass.
    """

    def __init__(cls, name, bases, attrs):
        if not hasattr(cls, '_message_handlers'):
            cls._message_handlers = {}

        for key, method in attrs.iteritems():
            if hasattr(method, '_message_handler'):
                message_key = method._message_handler
                cls._message_handlers[message_key] = method


class MessageProcessor(object):
    """Basic class for processing messages. Agents can have different strategies of
    replying to messages so variations of MessageProcessors can be defined. The main
    function is the handle function which selects the right message handler for the
    incoming message. The MessageProcessor requires a Queue object to which actions
    are appended for the agent to execute in response to the handled message. Without
    any MessageHandlers this class does not handle any type of message, so this class
    should be extended with actual message handlers.
    """

    __metaclass__ = MessageHandlerType

    def add_action(self, action):
        """Adds a new action to the action queue.

        Arguments:
            action {Action} -- Action to be added to the queue.
        """

        self.action_queue.put(action)

    def handle(self, message, msg_wrapper=None):
        """Selects a handler for the type of the received message. If no handler is
        defined by the class for the given message type, the message will be ignored.

        Arguments:
            message {[type]} -- [description]
        """
        if type(message) == dict:
            handler = self._message_handlers.get(message['type'], None)
        else:
            handler = self._message_handlers.get(msg_wrapper.type, None)

        if handler is not None:
            if type(message) == dict:
                handler(self, message['sender'], message['payload'])
            else:
                handler(self, msg_wrapper.address, message)
