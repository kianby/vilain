#!/usr/bin/env python3
# -*- coding:Utf-8 -*-


"""
Author :      thuban <thuban@yeuxdelibad.net>
              Vincent <vincent.delft@gmail.com>
Licence :     MIT
Require : python >= 3.5

Description : Mimic fail2ban with pf for OpenBSD.
              Inspired from http://www.vincentdelft.be/post/post_20161106

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
import logging.handlers
import subprocess
import asyncio
import time

CONFIGFILE = "/etc/vilain.conf"
VERSION = "0.7"
vilain_table = "vilain_bruteforce"
LOGFILE = "/var/log/daemon"

if os.geteuid() != 0:
    print("Only root can use this tool")
    sys.exit(1)

# declare logger
logger = logging.getLogger(__name__)

def configure_logging():
    print('Log file : {}'.format(LOGFILE))
    log_handler = logging.handlers.WatchedFileHandler(LOGFILE)
    formatter = logging.Formatter(
            '%(asctime)s %(module)s:%(funcName)s:%(message)s',
            '%Y-%m-%d %H:%M:%S')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)


# functions
def readconfig():
    logger.info('Read config file: {}'.format(CONFIGFILE))
    if not os.path.isfile(CONFIGFILE):
        logging.error("Can't read config file, exiting...")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(CONFIGFILE)
    return (config, config.defaults())

def load_config(c, d):
    watch_while = int(d['watch_while'])
    VILAIN_TABLE = d['vilain_table']
    default_maxtries = int(d['maxtries'])
    sleeptime = float(d['sleeptime'])
    ignore_ips = []

    if c.has_section('ignoreip'):
        ignoreips = [ i[1] for i in c.items('ignoreip') if i[0] not in c.defaults()]
    return(watch_while, default_maxtries, vilain_table, ignoreips, sleeptime)

def load_sections(c):
    for s in c.sections():
        if c.has_option(s,'logfile'):
            LOGFILE = c.get(s,'logfile')
            regex = c.get(s,'regex')
            #we take the default value of maxtries
            maxtries = c.defaults()['maxtries']
            if c.has_option(s,'maxtries'):
                #if we have a maxtries defined in the section, we overwrite the default
                maxtries = int(c.get(s,'maxtries'))
            d = {'name' : s, 'logfile':LOGFILE, 'regex':regex, 'maxtries': maxtries}
            yield d

class Vilain():
    def __init__(self, config, config_dict):
        logger.info('Start vilain version {}'.format(VERSION))
        self.loop = asyncio.get_event_loop()
        self.watch_while, self.default_maxtries, self.vilain_table, self.ignore_ips, self.sleeptime = load_config(config, config_dict)
        self.ip_seen_at = {}
        self.load_bad_ips()
        self.bad_ip_queue = asyncio.Queue(loop=self.loop)

        for entry in load_sections(config):
            logger.info("Start vilain for {}".format(entry))
            asyncio.ensure_future(self.check_logs(entry['logfile'], entry['maxtries'], entry['regex'], entry['name']))

        asyncio.ensure_future(self.ban_ips())
        asyncio.ensure_future(self.clean_ips())

    def load_bad_ips(self):
        try:
            ret = subprocess.check_output(["pfctl", "-t", self.vilain_table, "-T", "show"])
        except:
            logger.warning("Failed to run pfctl -t {} -T show".format(self.vilain_table))
            ret = ""
        for res in ret.split():
            ip = res.strip().decode('utf-8')
            logger.info('Add existing banned IPs in your pf table: {}'.format(ip))
            #we assign the counter to 1, but for sure we don't know the real value
            self.ip_seen_at[ip]={'time':time.time(),'count':1}


    def start(self):
        try:
            logger.info('Run forever loop')
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
            inode = stat.st_ino
            mtime = stat.st_mtime
            RE = re.compile(regex)
            while True:
                await asyncio.sleep(self.sleeptime)
                stat = os.stat(logfile)
                if size > stat.st_size and inode != stat.st_ino:
                    logger.info("The file {} has rotated. We start from position 0".format(logfile))
                    size = 0
                    inode = stat.st_ino
                if mtime < stat.st_mtime and inode == stat.st_ino:
                    logger.debug("{} has been modified".format(logfile))
                    mtime = stat.st_mtime
                    with open(logfile, "rb") as f:
                        f.seek(size,0)
                        for bline in f.readlines():
                            line = bline.decode().strip()
                            ret = RE.match(line)
                            logger.debug('line:{}'.format(line))
                            if ret:
                                bad_ip = ret.groups()[0]
                                if bad_ip not in self.ignore_ips :
                                    logger.info('line match {} the {} rule'.format(bad_ip, reason))
                                    await self.bad_ip_queue.put({'ip' : bad_ip, 'maxtries': maxtries, 'reason' : reason})
                                    logger.debug('queue size: {}'.format(self.bad_ip_queue.qsize()))
                                else:
                                    logger.info('line match {}. But IP in ignore list'.format(bad_ip))
                    size = stat.st_size

    async def ban_ips(self):
        """
        record time when this IP has been seen in ip_seen_at = { ip:{'time':<time>,'count':<counter} }
        and ban with pf
        """
        logger.info('ban_ips started')
        while True:
            ip_item = await self.bad_ip_queue.get()
            logger.debug('ban_ips awake')
            ip = ip_item['ip']
            reason = ip_item['reason']
            maxtries = ip_item['maxtries']
            self.ip_seen_at.setdefault(ip, {'time':time.time(),'count':0})
            self.ip_seen_at[ip]['count'] += 1
            n_ip = self.ip_seen_at[ip]['count']
            logger.info("{} detected, reason {}, count: {}, maxtries: {}".format(ip, reason, n_ip, maxtries))
            if n_ip >= maxtries:
                ret = subprocess.call(["pfctl", "-t", self.vilain_table, "-T", "add", ip])
                logger.info("Blacklisting {}, reason {}, return code:{}".format(ip, reason, ret))
            #for debugging, this line allow us to see if the script run until here
            logger.debug('ban_ips end:{}'.format(self.ip_seen_at))

    async def clean_ips(self):
        """
        check old ip in ip_seen_at : remove older than watch_while
        """
        logger.info('clean_ips started with sleeptime={}'.format(self.sleeptime))
        while True:
            await asyncio.sleep(self.watch_while)
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




def main(config, config_dict):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    v = Vilain(config, config_dict)
    v.start()
    return 0

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Vilain mimic fail2ban with pf for OpenBSD")
    parser.add_argument('--debug','-d', action="store_true", help="run in debug mode")
    parser.add_argument('--conf','-c', nargs="?", help="location of the config file")
    parser.add_argument('--version','-v', action="store_true", help="Show the version and exit")
    args = parser.parse_args()
    if args.debug:
        print("run in debug")
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler(sys.stdout)
        logger.addHandler(ch)
    if args.conf:
        CONFIGFILE = args.conf
    if args.version:
        print("Version: ", VERSION)
        sys.exit(0)
    # read config
    config, config_dict = readconfig()
    logfile = config_dict.get('vilain_log', None)
    if logfile:
        LOGFILE = logfile
    configure_logging()
    main(config, config_dict)


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4


# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
