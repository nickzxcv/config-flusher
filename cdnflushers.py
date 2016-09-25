import requests
import time
import re
import logging
import hashlib
import hmac
import boto
import threading

import status
import config


def log_requestsent(cdn, flushpath, requesturl):
    logging.info("Flush request to {} for {} -> {}...".format(cdn, flushpath, requesturl))


def log_requestfailed(cdn, error):
    logging.warning("Flush request to {} failed:".format(cdn))
    logging.warning(error)


def log_badresponse(cdn, status_code, content):
    logging.warning("Flush request to {} received bad response - {}:".format(cdn, status_code))
    logging.warning(content)


def log_success(cdn, flushpath, flushid):
    logging.info("Flush request to {} for {} succeeded: received flush id {}".format(cdn, flushpath, flushid))


def flushacdn(cdn, flushpath):
    try:
        if cdn == 'Level3':
            flushlevel3(flushpath)
        elif cdn == 'Edgecast':
            flushedgecast(flushpath)
        elif cdn == 'Cloudfront':
            flushcloudfront(flushpath)
    except Exception as error:
        status.flushfailcount += 1
        status.lastfailedflush = time.strftime('%s', time.gmtime())
        logging.error("A flush request to {} failed. Sleeping {} seconds.".format(
            cdn,
            config.failwaits['flush'])
        )
        logging.exception(error)
        time.sleep(config.failwaits['flush'])


def trytojoinflushthread(thread):
    thread.join(config.failwaits['threadtimer'])
    if thread.is_alive():
        logging.warning("Thread to flush {} is still alive after {} more seconds.".format(thread.name, config.failwaits['threadtimer']))
    return


def flushallcdns():
    for CDNname in config.CDNconfig.keys():
        status.flushSuccess[CDNname] = False  # gets set to True in the flush functions

    while not all(status.flushSuccess.values()):
        for CDNname in config.CDNconfig.keys():
            if not status.flushSuccess[CDNname]:  # check that the request to this CDN didn't already succeed
                if CDNname not in [athread.name for athread in threading.enumerate()]:  # check its not still running
                    t = threading.Thread(target=flushacdn, args=(CDNname, config.configpath), name=CDNname)
                    t.start()
        [trytojoinflushthread(athread) for athread in threading.enumerate() if athread.name in config.CDNconfig.keys()]  # join until they finish

    logging.info("All flush requests succeeded.")
    status.lastsuccessfulflush = time.strftime('%s', time.gmtime())
    status.flushfailcount = 0


def trytosendrequest(CDNname, flushpath, requesturl, requestheaders, requestbody, requestmethod, flushidpattern):
    try:
        log_requestsent(CDNname, flushpath, requesturl)
        if requestmethod == 'POST':
            request = requests.post(requesturl, headers=requestheaders, data=requestbody)
        elif requestmethod == 'PUT':
            request = requests.put(requesturl, headers=requestheaders, data=requestbody)
    except requests.exceptions.RequestException as error:
        log_requestfailed(CDNname, error)
        raise
    else:
        try:
            request.raise_for_status()
        except:
            log_badresponse(CDNname, request.status_code, request.content)
            raise
        else:
            flushid = re.findall(flushidpattern, request.content)[0]
            log_success(CDNname, flushpath, flushid)
            status.flushids[CDNname] = flushid
            status.flushSuccess[CDNname] = True
            return


def flushlevel3(flushpath):
    CDNname = 'Level3'
    # our api key
    apikeyid = config.CDNconfig[CDNname]['apikeyid']
    apisecret = config.CDNconfig[CDNname]['apisecret']

    # details of the flushing
    apiserver = 'https://ws.level3.com'
    apipath = '/invalidations/v1.0'
    accessgroupid = config.CDNconfig[CDNname]['accessgroupid']
    scid = config.CDNconfig[CDNname]['scid']
    propertyname = config.CDNconfig[CDNname]['propertyname']

    # details of the request
    requestdate = time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())
    requestpath = "{}/{}/{}/{}".format(apipath, accessgroupid, scid, propertyname)
    requesturl = "{}{}".format(apiserver, requestpath)
    requestcontenttype = 'text/xml'
    requestmethod = 'POST'
    requestbody = '<paths><path>{}</path></paths>\n\n'.format(flushpath)
    requestbodyhash = hashlib.md5(requestbody).hexdigest()

    # build the Authorization: header with our api key signing the request
    baresignature = "{}\n".format(requestdate)
    baresignature += "{}\n".format(requestpath)
    baresignature += "{}\n".format(requestcontenttype)
    baresignature += "{}\n".format(requestmethod)
    baresignature += "{}".format(requestbodyhash)
    baresignature = baresignature.encode('UTF-8', errors='strict')
    hashedsignature = hmac.new(apisecret, baresignature, hashlib.sha1).digest()
    authorizationvalue = "MPA {}:{}".format(apikeyid, hashedsignature.encode('base64', errors='strict'))

    requestheaders = {'Date': requestdate, 'Authorization': authorizationvalue, 'Content-Type': requestcontenttype, 'Content-MD5': requestbodyhash}

    return trytosendrequest(CDNname, flushpath, requesturl, requestheaders, requestbody, requestmethod, 'invalidation id="(.*?)"')


def flushedgecast(flushpath):
    CDNname = 'Edgecast'
    # our api key
    apitoken = config.CDNconfig[CDNname]['apitoken']
    customernumber = config.CDNconfig[CDNname]['customernumber']

    # details of our flushing
    mediapath = '{}{}'.format(config.CDNconfig[CDNname]['mediapathprefix'], flushpath)
    mediatype = config.CDNconfig[CDNname]['mediatype']
    apiserver = 'https://api.edgecast.com'
    apiurl = '{}/v2/mcc/customers/{}/edge/purge'.format(apiserver, customernumber)
    contenttype = 'application/xml'
    authorizationtoken = 'TOK:{}'.format(apitoken)
    requestbody = '''<MediaContentPurge xmlns="http://www.whitecdn.com/schemas/apiservices/">
<MediaPath>{}</MediaPath>
<MediaType>{}</MediaType>
</MediaContentPurge>'''.format(mediapath, mediatype)

    requestheaders = {'Authorization': authorizationtoken, 'Accept': contenttype, 'Content-Type': contenttype}

    return trytosendrequest(CDNname, flushpath, apiurl, requestheaders, requestbody, 'PUT', '<Id>(.*?)</Id>')


def flushcloudfront(flushpath):
    CDNname = 'Cloudfront'
    if not boto.config.has_section('Boto'):
        boto.config.add_section('Boto')
    boto.config.set('Boto', 'http_socket_timeout', '5')
    c = boto.connect_cloudfront(config.CDNconfig[CDNname]['accesskeyid'], config.CDNconfig[CDNname]['secretaccesskey'])
    distributionid = config.CDNconfig[CDNname]['distributionid']

    try:
        log_requestsent(CDNname, flushpath, "https://{}/{}/{}/invalidation".format(c.DefaultHost, c.Version, distributionid))
        inval_req = c.create_invalidation_request(distributionid, [flushpath])
    except boto.cloudfront.exception.CloudFrontServerError as error:
        log_requestfailed(CDNname, error)
    else:
        log_success(CDNname, flushpath, inval_req.id)
        status.flushids[CDNname] = inval_req.id
        status.flushSuccess[CDNname] = True
        return
    raise  # didn't return
