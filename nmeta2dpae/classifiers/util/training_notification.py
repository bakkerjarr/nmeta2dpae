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
This module is used for sending a notification to TCP socket server
informing them that a classifier has finished its training or learning
phase.
"""

import socket
import sys

_DPAE_DONE = "Training complete."
_HOST_ADDR = "172.16.0.10"
_HOST_PORT = 8088


def notify_train_complete():
    sckt = None
    try:
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        sys.exit("Unable to create socket: {0}".format(err))
    try:
        sckt.connect((_HOST_ADDR, _HOST_PORT))
    except socket.error as err:
        sckt.close()
        sys.exit("Unable to connect to connect to test server: {"
                 "0}".format(err))
    sckt.send(_DPAE_DONE)
    sckt.close()
