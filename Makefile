# vilain - anti-bruteforce for OpenBSD
# See LICENSE file for copyright and license details.
#
# vilain version
VERSION = 0.7

# Customize below to fit your system
# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/man/man1/

install:
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f vilain ${DESTDIR}${PREFIX}/bin
	@cp -f vilainreport ${DESTDIR}${PREFIX}/bin
	@echo installing script file to ${DESTDIR}${PREFIX}/sbin
	@cp -f vilain.py ${DESTDIR}${PREFIX}/sbin
	@cp -f vilainreport.py ${DESTDIR}${PREFIX}/sbin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/vilain
	@chmod 755 ${DESTDIR}${PREFIX}/bin/vilainreport
	@chmod 644 ${DESTDIR}${PREFIX}/sbin/vilain.py
	@chmod 644 ${DESTDIR}${PREFIX}/sbin/vilainreport.py
	@echo installing init script in /etc/rc.d
	@cp -f vilain.rc /etc/rc.d/vilain
	@chmod 755 /etc/rc.d/vilain
	@echo installing manual page to ${DESTDIR}${MANPREFIX}/man1
	@mkdir -p ${DESTDIR}${MANPREFIX}/
	@cp -f vilain.1 ${DESTDIR}${MANPREFIX}/vilain.1
	@chmod 644 ${DESTDIR}${MANPREFIX}/vilain.1


uninstall:
	@echo removing executable file from ${DESTDIR}${PREFIX}/bin
	@rm -f ${DESTDIR}${PREFIX}/bin/vilain
	@rm -f ${DESTDIR}${PREFIX}/bin/vilainreport
	@rm -f ${DESTDIR}${PREFIX}/sbin/vilain.py
	@rm -f ${DESTDIR}${PREFIX}/sbin/vilainreport.py
	@echo removing manual page to ${DESTDIR}${MANPREFIX}/
	@rm -f ${DESTDIR}${MANPREFIX}/vilain.1

.PHONY: install uninstall
