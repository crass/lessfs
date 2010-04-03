#!/bin/sh
umount /fuse
rm /core.*
rm -rf /data/mta
rm -rf /data/dta
./mklessfs -f -c /etc/lessfs.cfg
# Use the new lessfs.cfg syntax and let lessfs worry about the rest.
./lessfs /etc/lessfs.cfg /fuse 
