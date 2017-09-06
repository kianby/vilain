#!/usr/bin/env python3
# -*- coding:Utf-8 -*-

import re
import sys

pattern = '(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+).*Blacklisting (\d+\.\d+\.\d+\.\d+), reason (.*), return'
regex = re.compile(pattern)


class CounterDict:

    def __init__(self):
        self._counters = dict()

    def inc(self, k):
        v = self._counters.get(k, 0) + 1
        self._counters[k] = v

    def get(self, k):
        return self._counters.get(k, 0)

    def keys(self):
        return self._counters.keys()

    def reset(self):
        self._counters = dict()

    def topitems(self):
        return sorted(self._counters.items(), key=lambda x: x[1], reverse=True)


class Value:

    def __init__(self):
        self._value = ""

    def __str__(self):
        return self._value

    def __eq__(self, other):
        return str(self._value) == str(other)

    def set(self, value):
        self._value = value


last_day = Value()

# daily counters: key is reason
dcounters = CounterDict()

# global counters: key is reason
gcounters = CounterDict()

# hourly counters: key is hour
hcounters = CounterDict()

# top counters: key is IP
tcounters = CounterDict()


def plural(noun, count):
    if count > 1:
        return noun + "s"
    else:
        return noun


def process(m):
    current_day = m.group(1) + "-" + m.group(2) + "-" + m.group(3)
    current_hour = m.group(4)
    full_time = m.group(4) + ":" + m.group(5) + ":" + m.group(6)
    ip = m.group(7)
    reason = m.group(8)

    # new day
    #print("({})-({}) => {}".format(last_day, current_day, last_day == current_day))
    if last_day != current_day:
        # display day counters
        sys.stdout.write("\n")
        for reason in dcounters.keys():
            count = dcounters.get(reason)
            sys.stdout.write("Probe '{}': {} {}\n".format(reason, count, plural("attack", count)))
        last_day.set(current_day)
        dcounters.reset()
        sys.stdout.write("\n### Date {}\n".format(current_day))

    # output current line
    sys.stdout.write("{} blacklist IP {} ({})\n".format(full_time, ip, reason))

    # increment counters
    dcounters.inc(reason)
    gcounters.inc(reason)
    hcounters.inc(current_hour)
    tcounters.inc(ip)


# parse stdin
for line in sys.stdin:
    match = regex.match(line)
    if match:
        process(match)

# output counters
sys.stdout.write("\n")
for reason in dcounters.keys():
    sys.stdout.write("Probe '{}' : {} attacks\n".format(reason, dcounters.get(reason)))

sys.stdout.write("\n### Attacks per probe\n")
for k in gcounters.keys():
    count = gcounters.get(k)
    sys.stdout.write("Probe '{}': {} {} \n".format(k, count, plural("attack", count)))

sys.stdout.write("\n### Hourly repartition\n")
for k in sorted(hcounters.keys()):
    sys.stdout.write("Hour {} - {:02d}: {}\n".format(k, int(k) + 1, hcounters.get(k)))

sys.stdout.write("\n### Top attackers\n")
for k, v in tcounters.topitems():
    if v < 2:
        break
    sys.stdout.write("IP {:16}: {}\n".format(k, v))
