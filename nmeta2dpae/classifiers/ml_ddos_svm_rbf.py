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
machine learning method (Support Vector Machine (SVM) with RBF kernel).
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
from sklearn.svm import SVC
from util.iscx_2012_ddos import ISCX2012DDoS

# Imports for processing data
import math
from numpy import float32
import numpy.core.multiarray as np_array

# Other imports
import sys

# Imports for evaluation
from time import time
from util.training_notification import notify_train_complete
import datetime


class Classifier(object):
    """
    A custom classifier module for import by nmeta2.

    Uses the SVM method along with the following
    features:
        - log(totalSourceBytes)
        - totalSourcePackets
        - flow duration
    """

    _PARAM = {
        "C": 1.0,
        "kernel": "rbf",
        "degree": 3,
        "gamma": "auto",
        "coef0": 0.0,
        "shrinking": True,
        "probability": False,
        "tol": 0.001,
        "cache_size": 200,
        "class_weight": None,
        "verbose": False,
        "max_iter": -1,
        "decision_function_shape": None,
        "random_state": None}

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

        dt_now = datetime.datetime.strftime(datetime.datetime.now(),
                                            "D%Y-%m-%d_h%Hm%Ms%S")
        self._fname_train = "train_" + dt_now + "_svm.csv"
        self._fname_predict = "predict_" + dt_now + "_svm.csv"
        self.logger.info("Initialising ml_ddos_svm_rbf classifier...")
        time_start = time()
        self._iscx = ISCX2012DDoS(logging)
        self._ds_data, self._ds_labels = self._iscx.ddos_svm_rbf_data()
        self._cls = SVC(C=self._PARAM["C"],
                        kernel=self._PARAM["kernel"],
                        degree=self._PARAM["degree"],
                        gamma=self._PARAM["gamma"],
                        coef0=self._PARAM["coef0"],
                        shrinking=self._PARAM["shrinking"],
                        probability=self._PARAM["probability"],
                        tol=self._PARAM["tol"],
                        cache_size=self._PARAM["cache_size"],
                        class_weight=self._PARAM["class_weight"],
                        verbose=self._PARAM["verbose"],
                        max_iter=self._PARAM["max_iter"],
                        decision_function_shape=self._PARAM[
                            "decision_function_shape"],
                        random_state=self._PARAM["random_state"])
        self._train_dataset()
        time_stop = time()
        time_duration = time_stop - time_start
        with open(self._fname_train, "a") as f_train:
            dt_now = datetime.datetime.strftime(datetime.datetime.now(),
                                                "%Y-%m-%dT%H:%M:%S")
            f_train.write("{0},{1}\n".format(dt_now, time_duration))
        self.logger.info("SVM (RBF kernel) DDoS classifier initialised.")
        notify_train_complete()

    def classifier(self, flow):
        """
        Use the SVM (RBF kernel) classifier to determine if the flow
        is part of a DDoS attack.
        .
        This method is passed a Flow class object that holds the
        current context of the flow.
        .
        It returns a dictionary specifying a key/value that the flow
        is part of an attack or an empty dictionary if the flow is not.
        """
        self.logger.debug("Classifying flow: %s", flow.fcip_hash)
        time_start = time()
        results = {}
        # Gather the required flow data so that the classifier can make
        # a prediction. NOTE that the ordering of the features for
        # making a prediction must match the order of features that
        # were passed through for training.
        flow_data = flow.fcip_doc
        ip_src = flow.ip_src
        if ip_src == flow_data["ip_A"]:
            src_bytes = flow_data["total_pkt_len_A"]
            src_pckts = flow_data["total_pkt_cnt_A"]
        else:
            src_bytes = flow_data["total_pkt_len_B"]
            src_pckts = flow_data["total_pkt_cnt_B"]
        log_src_bytes = 0
        try:
            log_src_bytes = math.log(float(src_bytes))
        except ValueError:
            # Log (base 10) could not be evaluated, so set it to 0.
            # This has arisen as the number of source bytes is 0.
            # If the number of source bytes as listed in the flow object
            # is not 0, then something is wrong with the gathering of
            # the data.
            pass
        start_time = flow_data["packet_timestamps"][0]
        latest_time = flow_data["latest_timestamp"]
        flow_duration = float(latest_time - start_time)
        features = np_array.array([log_src_bytes, src_pckts,
                                   flow_duration]).astype(float32)
        # Make the prediction and return any meaningful results.
        attack_pred = int(self._cls.predict(features.reshape(1, -1))[0])
        time_stop = time()
        # NOTE We stop recording the time here as we are only
        # concerned with classification time and not the time taken to
        # form a response.
        time_duration = time_stop - time_start
        with open(self._fname_predict, "a") as f_predict:
            dt_now = datetime.datetime.strftime(datetime.datetime.now(),
                                                "%Y-%m-%dT%H:%M:%S")
            # Record the classification time and some flow information
            # that will help in identifying the flow during analysis.
            if flow_data["proto"] != "icmp":
                f_predict.write("{0},{1},{2},{3},{4},{5},{6},{7},"
                                "{8},{9},{10}\n".format(dt_now,
                                                        time_duration,
                                                        flow_data["ip_A"],
                                                        flow_data["ip_B"],
                                                        flow_data["proto"],
                                                        flow_data["port_A"],
                                                        flow_data["port_B"],
                                                        flow_data["client"],
                                                        flow_data["server"],
                                                        attack_pred,
                                                        latest_time))
            else:
                f_predict.write("{0},{1},{2},{3},{4},{5},{6},{7},"
                                "{8},{9},{10}\n".format(dt_now,
                                                        time_duration,
                                                        flow_data["ip_A"],
                                                        flow_data["ip_B"],
                                                        flow_data["proto"],
                                                        0,
                                                        0,
                                                        flow_data["client"],
                                                        flow_data["server"],
                                                        attack_pred,
                                                        latest_time))
        if attack_pred:
            results["ddos_attack"] = True
        return results

    def _train_dataset(self):
        """Train the SVM (RBF kernel) classifier using data from a
        dataset.
        """
        # self.logger.debug("Training classifier...")
        if len(self._ds_data) < 1 or len(self._ds_labels) < 1:
            self.logger.critical("Attempted to train classifier with "
                                 "an empty dataset, aborting.")
            sys.exit("ABORTING: Attempted to train classifier with an "
                     "empty dataset.")
        self._cls.fit(self._ds_data, self._ds_labels)
        # self.logger.debug("Training complete for SVM DDoS classifier.")
