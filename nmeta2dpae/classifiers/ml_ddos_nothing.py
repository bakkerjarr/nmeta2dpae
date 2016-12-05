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
It defines a custom traffic classifier that does nothing except
return a dict saying that the flow is not part of DDoS attack.
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

    This classifier just returns an empty dict.
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

        self.logger.info("Initialising empty classifier...")
        self._empty_ddos_dict = {"ddos_attack": False}
        self.logger.info("Empty classifier initialised.")

    def classifier(self, flow):
        """
        Return an empty dict.
        """
        return self._empty_ddos_dict
