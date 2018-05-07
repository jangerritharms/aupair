import os
import unittest
import json
from src.agent import Agent

TEST_OPTIONS = {
    "emulation_duration": 0,
    "emulation_step_length": 0,
    "discovery_server_port": 0
}


class TestAgent(unittest.TestCase):

    def setUp(self):
        files = os.listdir('sqlite/')
        for db_file in files:
            file_path = os.path.join('sqlite', db_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                print(e)
        self.A = Agent()
        self.A.configure(TEST_OPTIONS, 10000)
        self.B = Agent()
        self.B.configure(TEST_OPTIONS, 10001)
        self.C = Agent()
        self.C.configure(TEST_OPTIONS, 10002)
        
        self.messagesA = []
        self.messagesB = []
        self.messagesC = []


        def send(address, message):
            if address == 'tcp://127.0.0.1:10000':
                self.messagesA.append([message.encode('string-escape')])
                # self.A.handle_message([message.encode('string-escape')])
            elif address == 'tcp://127.0.0.1:10001':
                self.messagesB.append([message.encode('string-escape')])
                # self.B.handle_message([message.encode('string-escape')])
            elif address == 'tcp://127.0.0.1:10002':
                self.messagesC.append([message.encode('string-escape')])
                # self.C.handle_message([ressage.encode('string-escape')])

        self.A.send = send
        self.B.send = send
        self.C.send = send

    def test1(self):
        "Successful interaction between two nodes."        
        self.A.request_interaction([self.B.public_key.key_to_bin().encode('hex'),
                                    {'address': self.B.address}])
        self.B.handle_message(self.messagesB.pop())
        self.A.handle_message(self.messagesA.pop())
        self.assertEqual(len(self.A.database._getall('', ())), 3)
        self.assertEqual(len(self.B.database._getall('', ())), 3)
        self.assertEqual(len(self.messagesA), 0)
        self.assertEqual(len(self.messagesB), 0)
        self.assertEqual(len(self.messagesC), 0)

    def test2(self):
        "Asynchronous interaction between two nodes."        
        self.B.request_interaction([self.A.public_key.key_to_bin().encode('hex'),
                                    {'address': self.A.address}])
        self.A.handle_message(self.messagesA.pop())
        self.C.request_interaction([self.A.public_key.key_to_bin().encode('hex'),
                                    {'address': self.A.address}])
        self.A.handle_message(self.messagesA.pop())
        self.C.handle_message(self.messagesC.pop())
        self.B.handle_message(self.messagesB.pop())
        self.C.request_interaction([self.A.public_key.key_to_bin().encode('hex'),
                                    {'address': self.A.address}])
        self.A.handle_message(self.messagesA.pop())
        self.C.handle_message(self.messagesC.pop())
        self.assertEqual(len(self.A.database._getall('', ())), 7)
        self.assertEqual(len(self.B.database._getall('', ())), 3)
        self.assertEqual(len(self.C.database._getall('', ())), 5)
        self.assertEqual(len(self.messagesA), 0)
        self.assertEqual(len(self.messagesB), 0)
        self.assertEqual(len(self.messagesC), 0)


    def test3(self):
        "Crawl does not add genesis block"
        self.B.request_crawl([self.A.public_key.key_to_bin().encode('hex'),
                              {'address': self.A.address}])
        self.A.handle_message(self.messagesA.pop())
        self.B.handle_message(self.messagesB.pop())
        self.assertEqual(len(self.B.database._getall('', ())), 1)

    def test4(self):
        "Crawl shares blocks successfully"
        self.A.request_interaction([self.C.public_key.key_to_bin().encode('hex'),
                                    {'address': self.C.address}])
        self.C.handle_message(self.messagesC.pop())
        self.A.handle_message(self.messagesA.pop())
        self.B.request_crawl([self.A.public_key.key_to_bin().encode('hex'),
                              {'address': self.A.address}])
        self.A.handle_message(self.messagesA.pop())
        self.B.handle_message(self.messagesB.pop())
        self.assertEqual(len(self.B.database._getall('', ())), 3)


    # def test5(self):
    #     "Audit shares all blocks"
    #     self.A.request_audit

    def test5(self):
        "Difference calculation"
        self.A.request_interaction([self.C.public_key.key_to_bin().encode('hex'),
                                    {'address': self.C.address}])
        self.C.handle_message(self.messagesC.pop())
        self.A.handle_message(self.messagesA.pop())
        dif = self.A.calculate_difference(self.B.database._getall('WHERE public_key = ?',
                                                                  (buffer(self.B.public_key.key_to_bin()),)))
        self.assertEqual(len(dif), [[self.A.public_key.key_to_bin(),[2]],
                                    [self.C.public_key.key_to_bin(),[2]]])
        

    # def test6(self):
    #     "Difference calculation"
    #     self.A.request_interaction([self.C.public_key.key_to_bin().encode('hex'),
    #                                 {'address': self.C.address}])
    #     self.C.handle_message(self.messagesC.pop())
    #     self.A.handle_message(self.messagesA.pop())
    #     dif = self.A.calculate_difference(self.B.database._getall('WHERE public_key = ?',
    #                                                               (buffer(self.B.public_key.key_to_bin()),)))
    #     self.assertEqual(len(dif), 0)

