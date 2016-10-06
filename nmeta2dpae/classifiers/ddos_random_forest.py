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


class Classifier(object):
    """
    A custom classifier module for import by nmeta2
    """
    def __init__(self, logger):
        """
        Initialise the classifier
        """
        self.logger = logger

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
