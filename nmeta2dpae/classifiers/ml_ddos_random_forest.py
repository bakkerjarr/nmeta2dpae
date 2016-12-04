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
machine learning method (Random Forest).
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
from sklearn.ensemble import RandomForestClassifier
from util.iscx_2012_ddos import ISCX2012DDoS

# Imports for processing data
from numpy import float32
import numpy.core.multiarray as np_array

# Other imports
import sys


class Classifier(object):
    """
    A custom classifier module for import by nmeta2.

    Uses the Random Forest method along with the following features:
        - totalSourceBytes
        - totalSourcePackets
        - totalDestinationBytes
        - totalDestinationPackets
        - flow duration
    """

    _PARAM = {
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

        self.logger.info("Initialising ml_ddos_random_forest "
                         "classifier...")
        self._iscx = ISCX2012DDoS(logging)
        self._ds_data, self._ds_labels = \
            self._iscx.ddos_random_forest_data()
        self._cls = RandomForestClassifier(n_estimators=self._PARAM[
                                                "n_estimators"],
                                           criterion=self._PARAM[
                                                "criterion"],
                                           max_depth=self._PARAM[
                                                "max_depth"],
                                           min_samples_split=self._PARAM[
                                                "min_samples_split"],
                                           min_samples_leaf=self._PARAM[
                                                "min_samples_leaf"],
                                           min_weight_fraction_leaf=self._PARAM[
                                                "min_weight_fraction_leaf"],
                                           max_features=self._PARAM[
                                                "max_features"],
                                           max_leaf_nodes=self._PARAM[
                                                "max_leaf_nodes"],
                                           bootstrap=self._PARAM[
                                                "bootstrap"],
                                           oob_score=self._PARAM[
                                                "oob_score"],
                                           n_jobs=self._PARAM[
                                                "n_jobs"],
                                           random_state=self._PARAM[
                                                "random_state"],
                                           verbose=self._PARAM[
                                                "verbose"],
                                           warm_start=self._PARAM[
                                                "warm_start"],
                                           class_weight=self._PARAM[
                                                "class_weight"])
        self._train_dataset()
        self.logger.info("Random Forest DDoS classifier initialised.")

    def classifier(self, flow):
        """
        Use the Random Forest classifier to determine if the flow is
        part of a DDoS attack.
        .
        This method is passed a Flow class object that holds the
        current context of the flow.
        .
        It returns a dictionary specifying a key/value that the flow
        is part of an attack or an empty dictionary if the flow is not.
        """
        self.logger.debug("Classifying flow: %s", flow.fcip_hash)
        results = {"ddos_attack": False}
        # Gather the required flow data so that the classifier can make
        # a prediction. NOTE that the ordering of the features for
        # making a prediction must match the order of features that
        # were passed through for training.
        flow_data = flow.fcip_doc
        ip_src = flow.ip_src
        if ip_src == flow_data["ip_A"]:
            src_bytes = flow_data["total_pkt_len_A"]
            src_pckts = flow_data["total_pkt_cnt_A"]
            dst_bytes = flow_data["total_pkt_len_B"]
            dst_pckts = flow_data["total_pkt_cnt_B"]
        else:
            src_bytes = flow_data["total_pkt_len_B"]
            src_pckts = flow_data["total_pkt_cnt_B"]
            dst_bytes = flow_data["total_pkt_len_A"]
            dst_pckts = flow_data["total_pkt_cnt_A"]
        start_time = flow_data["packet_timestamps"][0]
        latest_time = flow_data["latest_timestamp"]
        flow_duration = float(latest_time - start_time)
        features = np_array.array([src_bytes, src_pckts, dst_bytes,
                                   dst_pckts, flow_duration]).astype(
                                                                 float32)
        # Make the prediction and return any meaningful results.
        attack_pred = int(self._cls.predict(features.reshape(1, -1))[0])
        if attack_pred:
            results["ddos_attack"] = True
        return results

    def _train_dataset(self):
        """Train the Random Forest classifier using data from a dataset.
        """
        self.logger.debug("Training classifier...")
        if len(self._ds_data) < 1 or len(self._ds_labels) < 1:
            self.logger.critical("Attempted to train classifier with "
                                 "an empty dataset, aborting.")
            sys.exit("ABORTING: Attempted to train classifier with an "
                     "empty dataset.")
        self._cls.fit(self._ds_data, self._ds_labels)
        self.logger.debug("Training complete for Random Forest DDoS "
                          "classifier.")
