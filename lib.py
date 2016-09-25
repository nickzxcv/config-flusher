import re
import time
import requests
import logging

import status
import config
import cdnflushers


def getserviceConfigVersion(serviceconfigfile):
    configversionlineregex = re.compile('^<config timestamp=".*?" version="([\d]+)">$')
    try:
        found = False
        with open(serviceconfigfile) as filehandle:
            for line in filehandle:
                if re.match(configversionlineregex, line):
                    serviceconfigversion = re.match(configversionlineregex, line).group(1)
                    found = True
        if not found:
            raise Exception('Could not read service config version from {}'.format(serviceconfigfile))
    except Exception as error:
        status.serviceconfigfailcount += 1
        logging.exception(error)
        return None
    else:
        logging.info("Read service config version {} from {}.".format(serviceconfigversion, config.configfile))
        return serviceconfigversion


def getconfigVersion(configurl):
    try:
        config = requests.get(configurl)
        config.raise_for_status()
    except requests.exceptions.RequestException as error:
        status.configfailcount += 1
        logging.error("Could not get {}:\n{}".format(configurl, error))
        return None
    else:
        configversion = re.findall('<lpConfig WallTimeSec="\d+" serviceConfigVersion="(\d+)" >', config.content)[0]
        logging.info("Read service config version {} from {}.".format(configversion, configurl))
        return configversion


def doesconfigmatchfileversion():
    match = False
    while not match:
        serviceconfigversion = getserviceConfigVersion(config.configdir + config.configfile)
        configversion = getconfigVersion(config.configurl)
        if serviceconfigversion == configversion:
            status.serviceconfigfailcount = 0
            status.configfailcount = 0
            status.serviceconfigversion = serviceconfigversion
            logging.info("Service config version from {} matched version from {}.".format(config.configurl, config.configfile))
            match = True
        else:
            status.configfailcount += 1
            logging.warning("Service config version from {} doesn't match version from {}. Sleeping {} second.".format(
                config.configurl,
                config.configfile,
                config.failwaits['versionmismatch']),
            )
            time.sleep(config.failwaits['versionmismatch'])
    return match


def changed(event):
    if (event.name == config.configfile):
        logging.info("Updated {} detected.".format(config.configfile))
        oldserviceconfigversion = status.serviceconfigversion  # this is about to be updated
        if doesconfigmatchfileversion():
            # only flush if we didn't see this serviceConfigVersion yet
            if status.serviceconfigversion > oldserviceconfigversion:
                cdnflushers.flushallcdns()
            else:
                logging.warning("Already saw serviceConfigVersion {}. Not flushing.".format(status.serviceconfigversion))
