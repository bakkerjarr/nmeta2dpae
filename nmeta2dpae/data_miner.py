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
This represents an interface for classifiers to fetch stored flow
data. This class abstracts the storage medium, be it a SQL database,
NoSQL database or Python data structures.

It is the responsibility of a DataMiner object to fetch data,
not process or transform any values. Any operations that need to be
performed on the raw data should be performed by the classifier
requesting the data.
.
Version 2.x Toulouse Code
"""

# Logging imports
import logging
import logging.handlers
import coloredlogs

# MongoDB
from pymongo import MongoClient

_DATA_REQ_TEMPLATE = {"proto": [],       # Transport protocols to fetch
                     "match": [],       # Key:value pairs describing what
                                        # flows should be selected.
                     "features": []}    # Desired data to return


class DataMiner(object):
    """
    This class is instantiated by CLASS_FILE.py and provides methods
    for fetching raw flow data for classifiers.
    """

    def __init__(self, _config):
        """Initialise a data mining object.

        :param _config: Logging configuration.
        """
        #*** Get logging config values from config class:
        _logging_level_s = _config.get_value \
                                    ('data_miner_logging_level_s')
        _logging_level_c = _config.get_value \
                                    ('data_miner_logging_level_c')
        _syslog_enabled = _config.get_value('syslog_enabled')
        _loghost = _config.get_value('loghost')
        _logport = _config.get_value('logport')
        _logfacility = _config.get_value('logfacility')
        _syslog_format = _config.get_value('syslog_format')
        _console_log_enabled = _config.get_value('console_log_enabled')
        _coloredlogs_enabled = _config.get_value('coloredlogs_enabled')
        _console_format = _config.get_value('console_format')
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

        # Get MongoDB connection information
        mongo_addr = _config.get_value("mongo_addr")
        mongo_port = _config.get_value("mongo_port")

        # Start a client with the MongoDB FCIP database
        self.logger.info("Connecting to mongodb database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)
        db_fcip = mongo_client.fcip_database
        # Initialise connections to the various FCIP collections
        self._fcip_icmp = db_fcip.fcip_icmp
        self._fcip_tcp = db_fcip.fcip_tcp
        self._fcip_udp = db_fcip.fcip_udp

    def mine_raw_data(self, req):
        """Mine stored flow data and return the data for the desired
        features.

        :param req: A request for data matching the DATA_REQ_TEMPLATE
        format.
        :return: The requested data as a dict, 0 if an error occurred.
        """
        pass

    def _fetch_icmp_flows(self, match):
        """Fetch data from the fcip_icmp MongoDB collection.

        :param match: The traffic features for MongoDB to match on
        when finding data.
        :return: Flow data as a dict.
        """
        pass

    def _fetch_tcp_flows(self, match):
        """Fetch data from the fcip_tcp MongoDB collection.

        :param match: The traffic features for MongoDB to match on
        when finding data.
        :return: Flow data as a dict.
        """
        pass

    def _fetch_udp_flows(self, match):
        """Fetch data from the fcip_udp MongoDB collection.

        :param match: The traffic features for MongoDB to match on
        when finding data.
        :return: Flow data as a dict.
        """
        pass
