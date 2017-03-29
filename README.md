# vilain
Mimic fail2ban with pf for OpenBSD.

Inspired from http://www.vincentdelft.be/post/post_20161106

In pf.conf, add according to your configuration : 

    table <vilain_bruteforce> persist
    block quick from <vilain_bruteforce> 

You might want to add a cron task to remove old banned IP. As example, to ban for one day max : 

    pfctl -t vilain_bruteforce -T expire 86400

To see banned IP : 

    pfctl -t vilain_bruteforce -T show


To start vilain at boot, add this in ``/etc/rc.local``

```
/usr/bin/tmux new -s vilain -d /usr/local/bin/vilain
```

Then, to attach to the tmux session, run : 

```
tmux a -t vilain
```
