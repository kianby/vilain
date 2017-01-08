# vilain
Mimic fail2ban with pf for OpenBSD.

Inspired from http://www.vincentdelft.be/post/post_20161106

This repository is just for work.
See here for last vilain "stable" version : http://git.yeuxdelibad.net/vilain/  


In pf.conf, add : 

    table <vilain_bruteforce> persist
    block quick from <vilain_bruteforce> 

You might want to add a cron task to remove old banned IP. As example, to ban for one day max : 

    pfctl -t vilain_bruteforce -T expire 86400

To see banned IP : 

    pfctl -t vilain_bruteforce -T show



