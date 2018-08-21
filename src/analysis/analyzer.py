import os
import numpy as np
import time
import datetime
import matplotlib.pyplot as plt
from matplotlib import cm as cm
import seaborn as sns

from src.analysis.agent import Agent

from src.agent.base import BaseAgent
from src.agent.protect import ProtectAgent
from src.agent.simple_protect import ProtectSimpleAgent
from src.agent.no_verification import NoVerificationAgent
from src.agent.double_spend import DoubleSpendAgent
from src.agent.bad_chain import BadChainProtectAgent
from src.agent.advanced_protect import ProtectAdvancedAgent
from src.agent.empty_exchanges import EmptyExchangeAgent
from src.agent.self_request import SelfRequestAgent
from src.agent.collaborator import CollaboratingAgent

AGENT_CLASSES = [
    BaseAgent,
    # ProtectAgent,
    ProtectSimpleAgent,
    BadChainProtectAgent,
    NoVerificationAgent,
    DoubleSpendAgent,
    ProtectAdvancedAgent,
    EmptyExchangeAgent,
    SelfRequestAgent,
    CollaboratingAgent
]

AGENT_CLASS_TYPES = {agent_cls._type: agent_cls for agent_cls in AGENT_CLASSES}
AGENT_TYPE_LIST = [agent_cls._type for agent_cls in AGENT_CLASSES]
AGENT_CLASS_COLOR = ["r", "g", "r", "b", "r", "g", "r",
                     "r", "r"]
AGENT_LABELS = [
    "Colluding free-rider",
    "Honest agent without auditing",
    "Block withholder",
    "Verification free-rider",
    "Double spender",
    "Honest agent with auditing",
    "Honest agent",
    "Honest agent",
    "Collaborator"
]
AGENT_CLASS_LINESTYLES = ['--', '-', '--', '-.', '--', '-', '--', '--', '--']

class Analyzer(object):
    """Defines different graphs for the results visualization.
    """

    def __init__(self, data_directory):
        files = os.listdir(data_directory)
        files = [f for f in files if f[-4:] == '.dat']

        self.agents = {}
        self.agent_list = []
        for db_file in files:
            agent = Agent.from_file(os.path.join(data_directory, db_file))
            self.agents.setdefault(agent.info.type, []).append(agent)
            self.agent_list.append(agent)

        self.agent_list = sorted(self.agent_list, key=lambda agent: agent.info.address)
        self.agent_key_list = [agent.info.public_key.as_bin() for agent in self.agent_list]

    def run_analysis(self, plot):

        if plot == 'bar_plot':
            self.transaction_bar_plot()

        if plot == 'history_plot':
            self.transaction_history()

        if plot == 'interaction_matrix':
            self.interaction_matrix2()

    def transaction_bar_plot(self):
        keys = []
        for typ, group in self.agents.iteritems():
            start = len(keys)
            keys.extend([agent.info.public_key.as_readable() for agent in group])
            transactions = [agent.number_of_transactions() for agent in group]
            plt.bar(range(start, len(keys)), transactions, 0.35,
                    label=typ, color=AGENT_CLASS_COLOR[AGENT_TYPE_LIST.index(typ)])

        plt.title('Database view')
        plt.xlabel('Agent by public key')
        plt.xlim([0, len(keys)])
        plt.xticks(range(len(keys)), keys, rotation="vertical")
        plt.ylabel('Number of transaction')
        plt.legend(loc="upper left")
        plt.tight_layout()
        plt.show()

    def transaction_history(self):

        start_time = time.time()
        end_time = 0
        used_labels = []
        for agent in self.agent_list:
            transactions = agent.transaction_blocks()
            print agent.info.type, len(transactions)
            tx_times = [time.mktime(datetime.datetime.strptime(tx.insert_time, "%Y-%m-%d %H:%M:%S").timetuple()) for tx in transactions]
            if len(tx_times) > 0:
                if max(tx_times) > end_time:
                    end_time = max(tx_times)
            start_time = end_time-200
            tx_times.insert(0, start_time)
            tx_times.append(end_time)
            if len(transactions) == 0:
                plt.step([0, 200], [0, 0], AGENT_CLASS_COLOR[AGENT_TYPE_LIST.index(agent.info.type)],
                label=AGENT_LABELS[AGENT_TYPE_LIST.index(agent.info.type)] if agent.info.type not in used_labels else '', linestyle=AGENT_CLASS_LINESTYLES[AGENT_TYPE_LIST.index(agent.info.type)])
            else:
                y = range(0, len(transactions)+1)
                dashes = []
                if AGENT_CLASS_LINESTYLES[AGENT_TYPE_LIST.index(agent.info.type)] == '--':
                    dashes = [6, 2]
                elif AGENT_CLASS_LINESTYLES[AGENT_TYPE_LIST.index(agent.info.type)] == '-.':
                    dashes = [2, 2, 10, 2]
                y.append(y[-1])
                plt.step([t-start_time for t in tx_times], y, AGENT_CLASS_COLOR[AGENT_TYPE_LIST.index(agent.info.type)],
                label=AGENT_LABELS[AGENT_TYPE_LIST.index(agent.info.type)] if agent.info.type not in used_labels else '', dashes=dashes)
            
            if agent.info.type not in used_labels:
                used_labels.append(agent.info.type)

        plt.xlabel("Time of the experiment[s]")
        plt.ylabel("Number of transactions")
        plt.ylim(ymin=-1)
        plt.legend(loc="upper left")
        plt.tight_layout()
        plt.grid()
        plt.show()

    def interaction_matrix(self):

        matrix = np.zeros((len(self.agent_list), len(self.agent_list)))
        mask = np.tri(matrix.shape[0])
        matrix = np.ma.array(matrix, mask=mask)

        counter = 0
        for agent in self.agent_list:
            for tx in agent.transaction_blocks():
                partner_index = self.agent_key_list.index(tx.link_public_key)
                if partner_index > counter:
                    matrix[counter][partner_index] = matrix[counter][partner_index] + 1
            counter += 1

        fig = plt.figure()
        ax1 = fig.add_subplot(111)
        cmap = cm.get_cmap('jet', 10) # jet doesn't have white color
        cmap.set_bad('w') # default value is 'k'
        ax1.imshow(matrix, interpolation="nearest", cmap=cmap)
        ax1.grid(True)
        plt.show()
        print matrix

    def interaction_matrix2(self):
        matrix = np.zeros((len(self.agent_list), len(self.agent_list)))
        mask = np.tri(matrix.shape[0])
        matrix = np.ma.array(matrix, mask=mask)

        counter = 0
        xlabels = []
        for agent in self.agent_list:
            xlabels.append(AGENT_LABELS[AGENT_TYPE_LIST.index(agent.info.type)])
            for tx in agent.transaction_blocks():
                partner_index = self.agent_key_list.index(tx.link_public_key)
                if partner_index > counter:
                    matrix[counter][partner_index] = matrix[counter][partner_index] + 1
            counter += 1

        cmap = sns.diverging_palette(10, 220, as_cmap=True)
        print matrix

        # Draw the heatmap with the mask and correct aspect ratio
        heat_plot = sns.heatmap(matrix, mask=mask, cmap=cmap, annot=True, linewidths=.5,
                                square=True, xticklabels=xlabels, yticklabels=xlabels)

        heat_plot.set_xticklabels(heat_plot.get_xticklabels(), rotation=45, ha="right")
        heat_plot.set_yticklabels(heat_plot.get_yticklabels(), rotation=0, ha="right")

        # for item in heat_plot.get_xticklabels():
        #     item.set_rotation(45)
        plt.tight_layout()
        plt.show()
        