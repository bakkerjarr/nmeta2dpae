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

_DATA_REQ_TEMPLATE = {"proto": [],      # Transport protocols to fetch.
                      "match": {},      # Key:value pairs describing
                                        # what flows should be selected,
                                        # only supports 'hash' value.
                      "features": []}   # Desired data to return
_SUPPORTED_FEATURES = ["hash",
                       "ip_A",
                       "ip_B",
                       "proto",
                       "port_A",
                       "port_B",
                       "tcp_flags",
                       "client",
                       "server",
                       "verified_direction",
                       "packet_directions",
                       "packet_count",
                       "total_pkt_cnt_A",
                       "total_pkt_len_A",
                       "total_pkt_cnt_B",
                       "total_pkt_len_B",
                       "packet_lengths",
                       "packet_timestamps",
                       "latest_timestamp"]
_SUPPORTED_MATCH = ["hash"]
_SUPPORTED_PROTO = ["icmp", "tcp", "udp"]


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
        if not self._check_bad_dm_req(req) or not \
                self._check_unsupported_dm_req(req):
            return 0
        return 0  # Function not complete!

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

    def _check_bad_dm_req(self, req):
        """Check that a data mining request is formatted correctly.

        :param req: Data mining request to check.
        :return: True if formatted correctly, False otherwise.
        """
        # Check the keys in the req dict
        if type(req) is not dict or len(req) != len(
                _DATA_REQ_TEMPLATE) or req.keys() != \
                _DATA_REQ_TEMPLATE.keys():
            self.logger.error("Data request does not contain the "
                              "required keys. Supplied: %s", req)
            return False
        # Check that the values are formatted correctly
        if type(req["proto"]) is not list or len(req["proto"]) < 1:
            self.logger.error("Data request 'proto' should be a "
                              "non-empty list. Supplied: %s",
                              req["proto"])
            return False
        if type(req["features"]) is not list or len(req["features"]) < 1:
            self.logger.error("Data request 'features' should be a "
                              "non-empty list. Supplied: %s",
                              req["features"])
            return False
        if type(req["match"]) is not dict or len(req["match"]) < 1:
            self.logger.error("Data request 'match' should be a "
                              "non-empty dict. Supplied: %s",
                              req["match"])
            return False
        return True  # The format is correct!

    def _check_unsupported_dm_req(self, req):
        """Check we can support the data mining request.

        :param req: Data mining request to check.
        :return: True if the request can be supported, False otherwise.
        """
        # Create a lambda for checking values. This evaluates to True
        # if it finds one item in check that isn't in template.
        lam_check = lambda check, template: any(i not in template for
                                                i in check)
        # Check that supported transport protocols were provided.
        if lam_check(req["proto"], _SUPPORTED_PROTO):
            self.logger.error("Data requested for unsupported "
                              "protocol in: %s. Expected from: %s.",
                              ", ".join(req["proto"]), ", ".join(
                                                       _SUPPORTED_PROTO))
            return False
        # Check that supported features were provided.
        if lam_check(req["features"], _SUPPORTED_FEATURES):
            self.logger.error("Data requested for unsupported "
                              "features in: %s. Expected from: %s.",
                              ", ".join(req["features"]), ", ".join(
                                                    _SUPPORTED_FEATURES))
            return False
        # Check that supported match items were provided.
        if lam_check(req["match"].keys(), _SUPPORTED_MATCH):
            self.logger.error("Unsupported match items provided in: "
                              "%s. Expected from: %s.", ", ".join(req[
                                                               "match"]),
                              ", ".join(_SUPPORTED_MATCH))
            return False
        return True  # The data mining object can support the request.
