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
It defines a custom traffic classifier
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
    A custom classifier module for import by nmeta2
    """

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

        self.logger.info("Initialising statistical_qos_bandwidth_1 "
                          "classifier...")

    def classifier(self, flow):
        """
        A really basic statistical classifier to demonstrate ability
        to differentiate 'bandwidth hog' flows from ones that are
        more interactive so that appropriate classification metadata
        can be passed to QoS for differential treatment.
        .
        This method is passed a Flow class object that holds the
        current context of the flow
        .
        It returns a dictionary specifying a key/value of QoS treatment to
        take (or not if no classification determination made).
        .
        Only works on TCP.
        """
        #*** Maximum packets to accumulate in a flow before making a
        #***  classification:
        _max_packets = 7
        #*** Thresholds used in calculations:
        _max_packet_size_threshold = 1200
        _interpacket_ratio_threshold = 0.3

        #*** Dictionary to hold classification results:
        _results = {}

        if flow.packet_count >= _max_packets and not flow.finalised:
            #*** Reached our maximum packet count so do some classification:
            self.logger.debug("Reached max packets count, finalising")
            flow.finalised = 1

            #*** Call functions to get statistics to make decisions on:
            _max_packet_size = flow.max_packet_size()
            _max_interpacket_interval = flow.max_interpacket_interval()
            _min_interpacket_interval = flow.min_interpacket_interval()

            #*** Avoid possible divide by zero error:
            if _max_interpacket_interval and _min_interpacket_interval:
                #*** Ratio between largest directional interpacket delta and
                #***  smallest. Use a ratio as it accounts for base RTT:
                _interpacket_ratio = float(_min_interpacket_interval) / \
                                            float(_max_interpacket_interval)
            else:
                _interpacket_ratio = 0
            self.logger.debug("max_packet_size=%s interpacket_ratio=%s",
                        _max_packet_size, _interpacket_ratio)
            #*** Decide actions based on the statistics:
            if (_max_packet_size > _max_packet_size_threshold and
                            _interpacket_ratio < _interpacket_ratio_threshold):
                #*** This traffic looks like a bandwidth hog so constrain it:
                _results['qos_treatment'] = 'constrained_bw'
            else:
                #*** Doesn't look like bandwidth hog so default priority:
                _results['qos_treatment'] = 'default_priority'
            self.logger.debug("Decided on results %s", _results)

        return _results
