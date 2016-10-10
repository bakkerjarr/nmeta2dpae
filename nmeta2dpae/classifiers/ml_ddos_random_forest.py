# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This module is part of the nmeta2 suite
.
It defines a custom traffic classifier for detecting DDoS attacks.
Note that it is different to other custom classifiers as it gets
passed config information and a data_miner object.
.
To create your own custom classifier, copy this example to a new
file in the same directory and update the code as required.
Call it from nmeta by specifying the name of the file (without the
.py) in main_policy.yaml
.
Classifiers are called per packet, so performance is important
.
"""

# Logging imports
import logging
import logging.handlers
import coloredlogs


class Classifier(object):
    """
    A custom classifier module for import by nmeta2.
    """

    _RANDOM_FOREST = {
        "n_estimators": 10,
        "criterion": "gini",
        "max_depth": None,
        "min_samples_split": 2,
        "min_samples_leaf": 1,
        "min_weight_fraction_leaf": 0.0,
        "max_features": "auto",
        "max_leaf_nodes": None,
        "bootstrap": True,
        "oob_score": False,
        "n_jobs": 1,
        "random_state": None,
        "verbose": 0,
        "warm_start": False,
        "class_weight": None}
    _DATASET_DIR = "/home/dev/Documents/datasets/iscx2012_ddos"
    _DATASET_FILEs = []


    def __init__(self, config, data_miner):
        """
        Initialise the classifier

        :param config: Logging configuration.
        :param data_miner: An object for mining FCIP database data.
        """
        #*** Get logging config values from config class:
        _logging_level_s = config.get_value \
                                    ('data_miner_logging_level_s')
        _logging_level_c = config.get_value \
                                    ('data_miner_logging_level_c')
        _syslog_enabled = config.get_value('syslog_enabled')
        _loghost = config.get_value('loghost')
        _logport = config.get_value('logport')
        _logfacility = config.get_value('logfacility')
        _syslog_format = config.get_value('syslog_format')
        _console_log_enabled = config.get_value('console_log_enabled')
        _coloredlogs_enabled = config.get_value('coloredlogs_enabled')
        _console_format = config.get_value('console_format')
        #*** Set up Logging:
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False

        #*** Syslog:
        if _syslog_enabled:
            #*** Log to syslog on host specified in config.yaml:
            self.syslog_handler = logging.handlers.SysLogHandler(
                address=(_loghost, _logport), facility=_logfacility)
            syslog_formatter = logging.Formatter(_syslog_format)
            self.syslog_handler.setFormatter(syslog_formatter)
            self.syslog_handler.setLevel(_logging_level_s)
            #*** Add syslog log handler to logger:
            self.logger.addHandler(self.syslog_handler)
        #*** Console logging:
        if _console_log_enabled:
            #*** Log to the console:
            if _coloredlogs_enabled:
                #*** Colourise the logs to make them easier to understand:
                coloredlogs.install(level=_logging_level_c,
                                    logger=self.logger,
                                    fmt=_console_format,
                                    datefmt='%H:%M:%S')
            else:
                #*** Add console log handler to logger:
                self.console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(_console_format)
                self.console_handler.setFormatter(console_formatter)
                self.console_handler.setLevel(_logging_level_c)
                self.logger.addHandler(self.console_handler)

        self._data_miner = data_miner
        self.logger.debug("Initialising Random Forest DDoS "
                          "classifier...")

    def classifier(self, flow):
        """
        Use the Random Forest classifier to determine if the flow is
        part of a DDoS attack.
        .
        This method is passed a Flow class object that holds the
        current context of the flow.
        .
        It returns a dictionary specifying a key/value that the flow
        is part of an attack (or not if no classification
        determination made).
        """
        # Dictionary to hold classification results:
        results = {}

        return results

    def _load_dataset(self):
        """Read data from dataset for training.
        """
        pass
