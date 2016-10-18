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
Note that it is different to other custom classifiers as it uses a
machine learning method (K Nearest Neighbours).
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

# Classifier imports
from sklearn.neighbours import KNeighborsClassifier
from util.iscx_2012_ddos import ISCX2012DDoS

# Imports for processing data
from numpy import float32
import numpy.core.multiarray as np_array

# Other imports
import sys


class Classifier(object):
    """
    A custom classifier module for import by nmeta2.

    Uses the K Nearest Neighbours method along with the following
    features:
        - totalSourceBytes
        - totalDestinationBytes
        - flow duration
    """

    _PARAM = {
        "n_neighbors": 5,
        "weights": "uniform",
        "algorithm": "kd_tree",
        "leaf_size": 30,
        "metric": "minkowski",
        "p": 2,
        "metric_params": None,
        "n_jobs": 1}

    def __init__(self, config):
        """
        Initialise the classifier

        :param config: Logging configuration.
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

        self.logger.info("Initialising ml_ddos_knn classifier...")
        self._iscx = ISCX2012DDoS(logging)
        self._ds_data, self._ds_labels = self._iscx.ddos_knn_data()
        self._cls = KNeighborsClassifier(n_neighbors=self._PARAM[
                                             "n_neighbors"],
                                         weights=self._PARAM["weights"],
                                         algorithm=self._PARAM[
                                             "algorithm"],
                                         leaf_size=self._PARAM[
                                             "leaf_size"],
                                         metric=self._PARAM["metric"],
                                         p=self._PARAM["p"],
                                         metric_params=self._PARAM[
                                             "metric_params"],
                                         n_jobs=self._PARAM["n_jobs"])
        self._train_dataset()

    def classifier(self, flow):
        """
        Use the K Nearest Neighbours classifier to determine if the
        flow is part of a DDoS attack.
        .
        This method is passed a Flow class object that holds the
        current context of the flow.
        .
        It returns a dictionary specifying a key/value that the flow
        is part of an attack or an empty dictionary if the flow is not.
        """
        # Dictionary to hold classification results:
        results = {}
        self.logger.debug("Classifying flow: %s", flow.fcip_hash)
        # Gather the required flow data so that the classifier can make
        # a prediction. NOTE that the ordering of the features for
        # making a prediction must match the order of features that
        # were passed through for training.
        flow_data = flow.fcip_doc
        ip_src = flow.ip_src
        if ip_src == flow_data["ip_A"]:
            src_bytes = flow_data["total_pkt_len_A"]
            dst_bytes = flow_data["total_pkt_len_B"]
        else:
            src_bytes = flow_data["total_pkt_len_B"]
            dst_bytes = flow_data["total_pkt_len_A"]
        start_time = flow_data["packet_timestamps"][0]
        latest_time = flow_data["latest_timestamp"]
        flow_duration = float(latest_time - start_time)
        features = np_array.array([src_bytes, dst_bytes,
                                   flow_duration]).astype(float32)
        # Make the prediction and return any meaningful results.
        attack_pred = self._cls.predict(features)
        if attack_pred:
            results["ddos_attack"] = True
        return results

    def _train_dataset(self):
        """Train the K Nearest Neighbours classifier using data from
        a dataset.
        """
        self.logger.debug("Training classifier with data from a datset.")
        if len(self._ds_data) < 1 or len(self._ds_labels) < 1:
            self.logger.critical("Attempted to train classifier with "
                                 "an empty dataset, aborting.")
            sys.exit("ABORTING: Attempted to train classifier with an "
                     "empty dataset.")
        self._cls.fit(self._ds_data, self._ds_labels)
