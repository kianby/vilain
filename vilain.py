#!/usr/bin/env python3
# -*- coding:Utf-8 -*- 


"""
Author :      thuban <thuban@yeuxdelibad.net>  
Licence :     MIT
Require : python >= 3.5

Description : Mimic fail2ban with pf for OpenBSD.
              Inspired from http://www.vincentdelft.be/post/post_20161106
              with improvements of vincendelft

              In pf.conf, add : 
                    table <vilain_bruteforce> persist
                    block quick from <vilain_bruteforce> 

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

configfile = "/etc/vilain.conf"
version = "0.4"
vilain_table = "vilain_bruteforce"
logfile = "/var/log/daemon"

if os.geteuid() != 0:
    print("Only root can use this tool")
    sys.exit()

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(filename=logfile,
                    format='%(asctime)s %(module)s:%(funcName)s:%(message)s',
                    datefmt='%H:%M:%S')
logger.setLevel(logging.INFO)
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
    default_maxtries = int(d['maxtries'])
    vilain_table = d['vilain_table']
    sleeptime = float(d['sleeptime'])
    ignore_ips = []

    if c.has_section('ignoreip'):
        ignoreips = [ i[1] for i in c.items('ignoreip') if i[0] not in c.defaults()]
    return(watch_while, default_maxtries, vilain_table, ignoreips, sleeptime)

def load_sections():
    c = readconfig()
    for s in c.sections():
        if c.has_option(s,'logfile'):
            logfile = c.get(s,'logfile')
            regex = c.get(s,'regex')
            #we take the default value of maxtries
            maxtries = c.defaults()['maxtries']
            if c.has_option(s,'maxtries'):
                #if we have a maxtries defined in the section, we overwrite the default
                maxtries = int(c.get(s,'maxtries'))
            d = {'name' : s, 'logfile':logfile, 'regex':regex, 'maxtries': maxtries}
            yield d


class Vilain():
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.watch_while, self.default_maxtries, self.vilain_table, self.ignore_ips, self.sleeptime = load_config()
        self.ip_seen_at = {}
        self.load_bad_ips()
        self.bad_ip_queue = asyncio.Queue(loop=self.loop)

        for entry in load_sections():
            logger.info("Start vilain for {}".format(entry['name']))
            asyncio.ensure_future(self.check_logs(entry['logfile'], entry['maxtries'], entry['regex'], entry['name']))

        asyncio.ensure_future(self.ban_ips())
        asyncio.ensure_future(self.clean_ips())

    def load_bad_ips(self):
        try:
            ret = subprocess.check_output(["pfctl", "-t", self.vilain_table, "-T", "show"])
        except:
            ret = ""
        for res in ret.split():
            ip = res.strip().decode('utf-8')
            logger.debug('Add existing banned IPs in your pf table: {}'.format(ip))
            #we assign the counter to 1, but for sure we don't know the real value 
            self.ip_seen_at[ip]={'time':time.time(),'count':1}


    def start(self):
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            self.loop.close()
        finally:
            self.loop.close()


    async def check_logs(self, logfile, maxtries, regex, reason):
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
                await asyncio.sleep(self.sleeptime)
                stat = os.stat(logfile)
                if mtime < stat.st_mtime:
                    logger.debug("{} has been modified".format(logfile))
                    mtime = stat.st_mtime
                    with open(logfile, "rb") as f:
                        f.seek(size)
                        lines = f.readlines()
                        ul = [ u.decode() for u in lines ]
                        line = "".join(ul).strip()

                        ret = RE.match(line)
                        logger.debug('line:{}'.format(line))
                        if ret:
                            bad_ip = ret.groups()[0]
                            if bad_ip not in self.ignore_ips :
                                logger.info('line match {} because of rule : {}'.format(bad_ip, reason))
                                await self.bad_ip_queue.put({'ip' : bad_ip, 'reason' : reason})
                                logger.debug('queue size: {}'.format(self.bad_ip_queue.qsize()))
                            else:
                                logger.info('line match {}. But IP in ignore list'.format(bad_ip))
                    size = stat.st_size

    async def ban_ips(self):
        """
        record time when this IP has been seen in ip_seen_at = { ip:{'time':<time>,'count':<counter} }
        """
        logger.info('ban_ips sarted with sleeptime={}'.format(self.sleeptime))
        while True:
            await asyncio.sleep(self.sleeptime)
            ip_item = await self.bad_ip_queue.get()
            logger.debug('ban_ips awake')
            ip = ip_item['ip']
            reason = ip_item['reason']
            maxtries = ip_item['maxtries']
            self.ip_seen_at.setdefault(ip,{'time':time.time(),'count':0})
            self.ip_seen_at[ip]['count'] += 1
            n_ip = self.ip_seen_at[ip]['count']
            logger.info("{} detected, reason {}, count: {}, maxtries: {}".format(ip, reason, n_ip, maxtries))
            if n_ip >= maxtries:
                ret = subprocess.call(["pfctl", "-t", self.vilain_table, "-T", "add", ip])
                logger.info("Blacklisting {}, return code:{}".format(ip, ret))
                self.ip_seen_at.pop(ip)
            #for debugging, this line allow us to see if the script run until here
            logger.debug('ban_ips end:{}'.format(self.ip_seen_at))

    async def clean_ips(self):
        """
        check old ip in ip_seen_at : remove older than watch_while
        """
        logger.info('clean_ips sarted with sleeptime={}'.format(self.sleeptime))
        while True:
            await asyncio.sleep(self.sleeptime)
            to_remove = []
            for recorded_ip, data in self.ip_seen_at.items():
                if time.time() - data['time'] >= self.watch_while:
                    ret = subprocess.call(["pfctl", "-t", self.vilain_table, "-T", "delete", recorded_ip])
                    logger.info("{} not blocked any more, return code:{}".format(recorded_ip, ret))
                    to_remove.append(recorded_ip)
            for ip in to_remove:
                self.ip_seen_at.pop(ip)
            #for debugging, this line allow us to see if the script run until here
            logger.debug('clean_ips end:{}'.format(self.ip_seen_at))




def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    v = Vilain()
    v.start()
    return 0

if __name__ == '__main__':
	main()


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

