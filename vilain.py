#!/usr/bin/env python3
# -*- coding:Utf-8 -*- 


"""
Author :      thuban <thuban@yeuxdelibad.net>  
Licence :     MIT
Require : python >= 3.5

Description : Mimic fail2ban with pf for OpenBSD.
              Inspired from http://www.vincentdelft.be/post/post_20161106

              In pf.conf, add : 
                    table <vilain_bruteforce> persist
                    block quick from <vilain_bruteforce> 

              You might want to add a cron task to remove old banned IP. As example, to ban for one day max : 
                    pfctl -t vilain_bruteforce -T expire 86400

              To see banned IP : 
                    pfctl -t vilain_bruteforce -T show
"""

import sys
import os
import configparser
import re
import logging
import subprocess
import asyncio
import time
from multiprocessing import Process

configfile = "/etc/vilain.conf"
version = "0.3"
vilain_table = "vilain_bruteforce"
logfile = "/var/log/daemon"
sleeptime = 0.5

if os.geteuid() != 0:
    print("Only root can use this tool")
    sys.exit()

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(filename=logfile,
                    format='%(asctime)s %(module)s:%(funcName)s:%(message)s',
                    datefmt='%H:%M:%S')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
logger.addHandler(ch)

# functions
def readconfig():
    if not os.path.isfile(configfile):
        logging.error("Can't read config file, exiting...")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(configfile)
    return(config)

def load_config():
    c = readconfig()
    d = c.defaults()
    watch_while = int(d['watch_while'])
    maxtries = int(d['maxtries'])
    vilain_table = d['vilain_table']

    if c.has_section('ignoreip'):
        ignoreip = [ i[1] for i in c.items('ignoreip') if i[0] not in c.defaults()]
    else:
        ignoreip = []
    return(watch_while, maxtries, vilain_table, ignoreip)

def load_sections():
    c = readconfig()
    for s in c.sections():
        if c.has_option(s,'logfile'):
            logfile = c.get(s,'logfile')
            regex = c.get(s,'regex')
            d = {'name' : s, 'logfile':logfile, 'regex':regex}
            yield d

class Vilain():
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.watch_while, self.maxtries, self.vilain_table, self.ignore_ip = load_config()
        #self.bad_ip_queue = []
        self.bad_ip_queue = asyncio.Queue(loop=self.loop)

        for entry in load_sections():
            logger.info("Start vilain for {}".format(entry['name']))
            asyncio.ensure_future(self.check_logs(entry['logfile'], entry['regex'], entry['name']))

        asyncio.ensure_future(self.ban_ips())

    def start(self):
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            self.loop.close()
        finally:
            self.loop.close()

    async def check_logs(self, logfile, regex, reason):
        """
        worker who put in bad_ip_queue bruteforce IP
        """
        if not os.path.isfile(logfile) :
            logger.warning("{} doesn't exist".format(logfile))
        else :
            # Watch the file for changes
            stat = os.stat(logfile)
            size = stat.st_size
            mtime = stat.st_mtime
            RE = re.compile(regex)
            while True:
                await asyncio.sleep(sleeptime)
                stat = os.stat(logfile)
                if mtime < stat.st_mtime:
                    mtime = stat.st_mtime
                    with open(logfile, "rb") as f:
                        f.seek(size)
                        lines = f.readlines()
                        ul = [ u.decode() for u in lines ]
                        line = "".join(ul).strip()

                        ret = RE.match(line)
                        if ret:
                            bad_ip = ret.groups()[0]
                            if bad_ip not in self.ignore_ip :
                                #self.bad_ip_queue.append({'ip' : bad_ip, 'reason' : reason})
                                await self.bad_ip_queue.put({'ip' : bad_ip, 'reason' : reason})
                    size = stat.st_size

    async def ban_ips(self):
        """
        worker who ban IP on bad_ip_queue
        add IP in bad_ips_list 
        record time when this IP has been seen in ip_seen_at = { ip:time }

        check number of occurence of the same ip in bad_ips_list
        if more than 3 : ban and clean of list

        check old ip in ip_seen_at : remove older than watch_while
        """

        bad_ips_list = []
        ip_seen_at = {}
        while True:
            await asyncio.sleep(sleeptime)
            #if not len(s#elf.bad_ip_queue) > 0:
            #    continue
            ip_item = await self.bad_ip_queue.get()
            #ip_item = self.bad_ip_queue.pop()
            ip = ip_item['ip']
            reason = ip_item['reason']
            logger.info("{} detected, reason {}".format(ip, reason))
            bad_ips_list.append(ip)
            ip_seen_at[ip] = time.time()
            n_ip = bad_ips_list.count(ip)
            if n_ip >= self.maxtries:
                logger.info("Blacklisting {}".format(ip))
                subprocess.call(["pfctl", "-t", self.vilain_table, "-T", "add", ip])
                ip_seen_at.pop(ip)
                while ip in bad_ips_list:
                    bad_ips_list.remove(ip)

            to_remove = []
            for recorded_ip, last_seen in ip_seen_at.items():
                if time.time() - last_seen >= self.watch_while:
                    logger.info("{} not seen since a long time, forgetting...".format(recorded_ip))
                    to_remove.append(recorded_ip)
            for i in to_remove:
                ip_seen_at.pop(i)





def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    v = Vilain()
    p = Process(target=v.start())
    p.start()
    return 0

if __name__ == '__main__':
	main()


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

