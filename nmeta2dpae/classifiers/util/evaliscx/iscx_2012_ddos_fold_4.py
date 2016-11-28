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
This represents an interface for reading in data from the ISCX DDoS
2012 dataset.
.
Version 2.x Toulouse Code
"""

# Imports for reading and processing data
from lxml import etree
import math
from numpy import float32
import numpy.core.multiarray as np_array

# Other imports
from datetime import datetime
import os
import sys


class ISCX2012DDoS(object):

    _DATASET_DIR = "/home/dp1/Documents/iscxddos_train"
    _DATASET_FILES = ["iscx2012ddos_training_set_fold_4.xml"]

    # NOTE: Debug logging has been commented out here so that the
    # function calls do not add to the classifier initialisation time.

    def __init__(self, logging):
        """Initialise.

        :param logging: Object for writing logging information to.
        Note that it will be from the perspective of the parent object.
        """
        self._logging = logging
        self._raw_data = []
        self._raw_labels = []
        files = []
        for f in self._DATASET_FILES:
            files.append(os.path.join(self._DATASET_DIR, f))
        self._read_data(files)

    def ddos_knn_data(self):
        """Prepare data for the ml_ddos_knn classifier.

        The features are totalSourceBytes, totalDestinationBytes,
        and flow duration.

        :return: Tuple of data and labels as NumPy arrays.
        """
        #self._logging.debug("Preparing data for K Nearest Neighbours "
        #                    "DDoS attack classifier.")
        features = ["totalSourceBytes", "totalDestinationBytes",
                    "startDateTime", "stopDateTime"]
        selected_data = self._return_features(self._raw_data, features)
        transformed_data = []
        for flow in selected_data:
            new_entry = flow[0:2]  # copy in the first 2 elements
            start_dt = datetime.strptime(flow[2], "%Y-%m-%dT%H:%M:%S")
            stop_dt = datetime.strptime(flow[3], "%Y-%m-%dT%H:%M:%S")
            duration = (stop_dt-start_dt).seconds
            new_entry.append(duration)
            transformed_data.append(new_entry)
        return (np_array.array(transformed_data).astype(float32),
                np_array.array(self._raw_labels).astype(float32))

    def ddos_random_forest_data(self):
        """Prepare data for the ml_ddos_random_forest classifier.

        The features are totalSourceBytes, totalSourcePackets,
        totalDestinationBytes, totalDestinationPackets and flow duration.

        :return: Tuple of data and labels as NumPy arrays.
        """
        #self._logging.debug("Preparing data for Random Forest DDoS "
        #                    "attack classifier.")
        features = ["totalSourceBytes", "totalSourcePackets",
                    "totalDestinationBytes", "totalDestinationPackets",
                    "startDateTime", "stopDateTime"]
        selected_data = self._return_features(self._raw_data, features)
        transformed_data = []
        for flow in selected_data:
            new_entry = flow[0:4]  # copy in the first 4 elements
            start_dt = datetime.strptime(flow[4], "%Y-%m-%dT%H:%M:%S")
            stop_dt = datetime.strptime(flow[5], "%Y-%m-%dT%H:%M:%S")
            duration = (stop_dt-start_dt).seconds
            new_entry.append(duration)
            transformed_data.append(new_entry)
        return (np_array.array(transformed_data).astype(float32),
                np_array.array(self._raw_labels).astype(float32))

    def ddos_svm_rbf_data(self):
        """Prepare data for the ml_ddos_svm_rbf classifier.

        The features are log(totalSourceBytes), totalSourcePackets,
        and flow duration.

        :return: Tuple of data and labels as NumPy arrays.
        """
        #self._logging.debug("Preparing data for SVM (RBF kernel) "
        #                    "DDoS attack classifier.")
        features = ["totalSourceBytes", "totalSourcePackets",
                    "startDateTime", "stopDateTime"]
        selected_data = self._return_features(self._raw_data, features)
        transformed_data = []
        for flow in selected_data:
            new_entry = []
            src_bytes = 0
            try:
                src_bytes = math.log(float(flow[0]))
            except ValueError:
                # Log (base 10) could not be evaluated, so set it to 0.
                # This has arisen as the number of source bytes is 0.
                # If the number of source bytes as listed in the
                # dataset is not 0, then something is wrong with the
                # data.
                pass
            new_entry.append(src_bytes)
            new_entry.append(flow[1])  # copy in totalSourcePackets
            start_dt = datetime.strptime(flow[2], "%Y-%m-%dT%H:%M:%S")
            stop_dt = datetime.strptime(flow[3], "%Y-%m-%dT%H:%M:%S")
            duration = (stop_dt-start_dt).seconds
            new_entry.append(duration)
            transformed_data.append(new_entry)
        return (np_array.array(transformed_data).astype(float32),
                np_array.array(self._raw_labels).astype(float32))

    def _read_data(self, files):
        """Read data from ISCX dataset XML files.

        :param files: Name of the file to read the data from.
        """
        for fname in files:
            #self._logging.info("Reading data from: %s", fname)
            data_etree = None
            try:
                data_etree = etree.parse(fname)
            except IOError as err:
                self._logging.critical("Unable to open file: %s. "
                                       "Error: %s", fname, err)
                sys.exit(1)
            tmp_data, tmp_labels = self._etree_to_dict(data_etree)
            self._raw_data.extend(tmp_data)
            self._raw_labels.extend(tmp_labels)
            #self._logging.debug("Loading complete for file: %s", fname)

    def _etree_to_dict(self, xml_etree):
        """Convert an XML etree into a list of dicts.

        This method only takes care of elements, not attributes!

        :param xml_etree: Etree object to process
        :return: Data as a list of dict.
        """
        root = xml_etree.getroot()
        data = []
        labels = []
        for flow in root:
            flow_data = {}
            for i in range(len(flow)):
                if flow[i].tag != "Tag":
                    flow_data[flow[i].tag] = flow[i].text
                else:
                    if flow[i].text == "Normal":
                        labels.append(TagValue.Normal)
                    else:
                        labels.append(TagValue.Attack)
            data.append(flow_data)
        return data, labels

    def _return_features(self, data, features):
        """Select specific raw features from the data.

        :param data: The data set to manipulate.
        :param features: A list of ISXC 2012 IDS specific features.
        :return: List of data with just the chosen features in the order
                 they were requested.
        """
        processed_data = []
        for flow in data:
            new_entry = []
            for f in features:
                new_entry.append(flow[f])
            processed_data.append(new_entry)
        return processed_data


class TagValue:
    """Enum for the dataset tag labels.
    """
    Normal = 0
    Attack = 1
