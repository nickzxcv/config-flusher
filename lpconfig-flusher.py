#!/usr/bin/python

import pyinotify
import sys
import re
import time
from optparse import OptionParser
import logging

# This is done for packaging reasons,
# since this script will be run from elsewhere.
# To run manually from config-flusher dir,
# delete or comment out the next line.
sys.path.append('@PREFIX@/config-flusher')

import cdnflushers
import status
import lib
import config

opt_parser = OptionParser()
opt_parser.add_option("--instanceId", type="int", action="store", dest="instanceid")
opt_parser.add_option("--status-port", type="int", action="store", dest="status_port")
(options, args) = opt_parser.parse_args()

if not options.instanceid or not options.status_port:
    logging.error("Missing --instanceId or --status-port option.")
    sys.exit(1)

version = '@VERSION@'

logging.basicConfig(level=logging.INFO)

wm = pyinotify.WatchManager()
notifier = pyinotify.Notifier(wm)

status.start_status_server(options.status_port, version, options.instanceid)

# flush before the loop starts in case the process was down for a while
if lib.doesconfigmatchfileversion():
    cdnflushers.flushallcdns()

wm.add_watch(config.configdir, pyinotify.IN_MOVED_TO, lib.changed)
notifier.loop()
