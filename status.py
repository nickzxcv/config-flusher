import socket
import json
import threading
import time
import logging
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

serviceconfigversion = None
lastsuccessfulflush = None
lastfailedflush = None
flushids = {'Edgecast': None, 'Cloudfront': None, 'Level3': None}
flushfailcount = 0
flushSuccess = {}
serviceconfigfailcount = 0
configfailcount = 0


class StatusHandler(BaseHTTPRequestHandler):
    def __init__(self, hostname, version, instanceid, *args):
        self.hostname = hostname
        self.version = version
        self.instanceid = instanceid
        BaseHTTPRequestHandler.__init__(self, *args)

    # Handler for the GET requests
    def do_GET(self):
        if serviceconfigfailcount > 0:
            status = 'Critical'
            message = 'Could not get the service config version!'
        elif configfailcount > 0:
            status = 'Warning'
            message = 'LPConfig request failed or version doesnt match c3ServiceConfig.xml.'
        elif flushfailcount > 0:
            status = 'Warning'
            message = 'Flush request failed.'
        elif not all(flushSuccess.values()):
            status = 'Warning'
            message = 'Flush request in progress.'
        else:
            status = 'Ok'
            message = 'Ok'

        basicjsonresponse = {
            "basic":
                {
                    "status": status,
                    "hostname": self.hostname,
                    "componentName": "config-flusher",
                    "instanceId": self.instanceid,
                    "version": self.version,
                    "message": message
                },
        }

        detailsjsonresponse = {
            "details":
                {
                    "lastSuccesfulFlush":
                        {
                            "flushIds":
                                {
                                    "Edgecast": flushids['Edgecast'],
                                    "Cloudfront": flushids['Cloudfront'],
                                    "Level3": flushids['Level3'],
                                },
                            "time": lastsuccessfulflush,
                        },
                    "lastFailedFlush":
                        {
                            "time": lastfailedflush,
                        },
                    "lastFlushSuccessStatus": flushSuccess,
                    "c3ConfigVersion": serviceconfigversion,
                }
        }

        statisticsjsonresponse = {
            "failCounts":
                {
                    "serviceConfig": serviceconfigfailcount,
                    "Config": configfailcount,
                    "Flush": flushfailcount,
                }
        }

        if self.path == "/1/status":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": status}))
            self.wfile.write("\n")
        elif self.path == "/1/status/basic":
            jsonresponse = basicjsonresponse
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(jsonresponse, indent=4, separators=(',', ': ')))
            self.wfile.write("\n")
        elif self.path == "/1/status/details":
            jsonresponse = basicjsonresponse
            jsonresponse.update(detailsjsonresponse)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(jsonresponse, indent=4, separators=(',', ': ')))
            self.wfile.write("\n")
        elif self.path == "/1/status/statistics":
            jsonresponse = statisticsjsonresponse
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(jsonresponse, indent=4, separators=(',', ': ')))
            self.wfile.write("\n")


def start_status_server(port, version, instanceid):
    # status server
    hostname = socket.gethostname()

    # a wrapper, so that we can pass some parameters to BaseHTTPRequestHandler
    def status_handler_wrapper(*arguments):
        StatusHandler(hostname, version, instanceid, *arguments)
    server = HTTPServer(('', port), status_handler_wrapper)
    thread = threading.Thread(target=server.serve_forever, name='status_server')
    thread.daemon = True
    thread.start()
    logging.info("Started httpserver on port %d" % port)
