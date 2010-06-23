Summary:	Lessfs is an inline data deduplicating filesystem
Name:		lessfs
Version:	1.1.0
Release:	beta6%{?dist}
License:	GPLv3+
Group:		Applications/System
URL:            http://www.lessfs.com
Source:         http://downloads.sourceforge.net/%{name}/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}
BuildRequires:  tokyocabinet-devel 
BuildRequires:  openssl-devel 
BuildRequires:  mhash-devel
BuildRequires:  fuse-devel
BuildRequires:  autoconf

Requires: fuse
Requires: mhash
Requires: tokyocabinet

%description
Lessfs is an inline data deduplicating filesystem.

%prep
%setup -q

%build
autoconf
export CFLAGS="-ggdb2 -O2"
%configure --with-crypto
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
install -D -m 755 etc/lessfs %{buildroot}/etc/init.d/lessfs
install -D -m 755 etc/lessfs.cfg %{buildroot}/etc/lessfs.cfg

rm -rf %{buildroot}%{_datadir}/%{name}
rm -rf %{buildroot}%{_libdir}/lib%{name}.a

%clean
rm -rf %{buildroot}

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root, -)
%doc FAQ ChangeLog COPYING README
%{_bindir}/lessfs
%{_sbindir}/mklessfs
%{_sbindir}/defrag_lessfs
%{_sbindir}/lessfsck
%{_sbindir}/listdb
%{_mandir}/man1/lessfs.1.gz
/etc/init.d/lessfs
/etc/lessfs.cfg

%changelog
* Mon Jun 21 2010 Mark Ruijter <mruijter@gmail.com> - 1.1.0-beta6
- Improved cache eviction routines.
* Sun Jun 20 2010 Mark Ruijter <mruijter@gmail.com> - 1.1.0-beta5
- Fixes a bug where reads would mostly mis the cache.
- Read performance has now dramatically (300%) increased
- for chunks of data that are found in the cache.
* Tue Jun 19 2010 Mark Ruijter <mruijter@gmail.com> - 1.1.0-beta4
- Fixes a (rare) race condition with the file_io backend.
- Improved write performance when writing smaller then BLKSIZE
- data chunks. General code cleaning.
* Tue Jun 15 2010 Mark Ruijter <mruijter@gmail.com> - 1.1.0-beta3
- Under some circumstances a newly written block of data
- with hash (A) could be overwritten before the previous
- write had finished. A new 'per hash' locking mechanisme    
- now makes sure that this never happens.
- See create_hash_note for details.
* Thu Jun 10 2010 Mark Ruijter <mruijter@gmail.com> - 1.1.0-beta2
- Fixed a deadlock. Lessfs now supports deadlock reporting
- Telnet localhost 100 -> lockstatus will show details about locking
* Thu Jun 10 2010 Mark Ruijter <mruijter@gmail.com> - 1.1.0-beta1
- A number of race conditions has been fixed.
* Wed Jun 2 2010 Mark Ruijter <mruijter@gmail.com> - 1.1.0-alpha1
- This release changes lessfs internals in a major way.
- Lessfs-1.1.0 is _not_ compatible with previous lessfs versions.
- This new version provides a much improved cache layer and 
- way better performance. Threading has been improved and lessfs
- is now capable of using many threads /CPU's.
* Tue Mar 30 2010 Mark Ruijter <mruijter@gmail.com> - 1.0.8
- This release enables lessfs to be mounted without the
- need to specify other options then the configuration file
- and the mountpoint. Please consult the manual for more
- details. Eric D. Garver contributed a patch that
- makes the build process less picky about missing
- GNU files like INSTALL and NEWS. A bug in lessfs_read
- has been found by extensive testing with fsx-linux. In
- cases where a sparse block of data would be followed by
- a normal block lessfs_read would return wrong data in 
- some cases. Added automatic migration support for older
- lessfs versions.
* Sat Mar 27 2010 Mark Ruijter <mruijter@gmail.com> - 1.0.7
- This release fixes a problem where data copied
- from windows to lessfs (samba) would show the wrong
- nr of blocks. This would result in du reporting wrong
- numbers.
* Thu Mar 11 2010 Mark Ruijter <mruijter@gmail.com> - 1.0.6
- Fixes a segfault that may occur when lessfs is used 
- without transactions enabled. The segfault occurs when
- lessfs is unmounted after closing the databases. The 
- impact of the bug is therefore low.
* Sun Mar 07 2010 Mark Ruijter <mruijter@gmail.com> - 1.0.5
- Fixes a small problem with logging.
* Thu Mar 03 2010 Mark Ruijter <mruijter@gmail.com> - 1.0.4
- This release enables support for transactions/checkpointing.
- Lessfs now no longer needs fsck after a crash. Also new is the ability to
- run a program when disk space drops below a certain amount of space. 
- This program can be used to free up space when the tokyocabinet 
- datastore is used.
* Sun Jan 24 2010 Mark Ruijter <mruijter@gmail.com> - 1.0.1
- Fixes a rare race condition that can cause lessfs to crash.
* Mon Dec 30 2009 Mark Ruijter <mruijter@gmail.com> - 1.0.0
- Removed all the bugs. ;-)
* Mon Dec 21 2009 Mark Ruijter <mruijter@gmail.com> - 0.9.6
- Fix an erroneous free() that can crash lessfs upon startup
- when the tiger hash is selected. Changes mklessfs so that
- it supports automatic directory creation and database overwrites.
- mklessfs now has improved error reporting.
* Wed Dec 16 2009 Mark Ruijter <mruijter@gmail.com> - 0.9.4
- Fixes two memory leaks that are related to hardlink operations.
- Solves a problem caused by not initializing st_[a/c/m]time.tv_nsec.
- Thanks to Wolfgang Zuleger for doing a great job on analyzing these bugs.
- Fixed a memory leak in file_io.
* Sun Dec 13 2009 Mark Ruijter <mruijter@gmail.com> - 0.9.3
- Partial file truncation encryption caused data corruption.
* Sat Dec 12 2009 Mark Ruijter <mruijter@gmail.com> - 0.9.2
- This release fixes some problems where permissions where not properly
- set on open files. It also fixes a problem with the link count
- of directories. Performance for some meta data operations has improved.
* Fri Dec 11 2009 Mark Ruijter <mruijter@gmail.com> - 0.9.1
- Fix permission problems with open files.
* Wed Dec 09 2009 Mark Ruijter <mruijter@gmail.com> - 0.9.0
- Lessfs now passes fsx-linux. The problems reported with rsync
- have now been solved. Major changes of the truncation code.
* Sun Nov 15 2009 Mark Ruijter <mruijter@gmail.com> - 0.8.3
- Fixes a major bug in the truncation code.
- This bug will crash lessfs when used with ccrypt or rsync –inplace.
* Sat Nov 09 2009 Mark Ruijter <mruijter@gmail.com> - 0.8.2
- Fixes a bug that causes lessfsck and mklessfs to segfault when compiled
- with encryption support and encryption disabled in the config.
- Fixes a bug that causes lessfs to segfault on umount when compiled
- with encryption support and encryption disabled in the config.
- lessfsck,listdb and mklessfs are now installed in /usr/sbin
- instead of /usr/bin.
* Sat Nov 07 2009 Mark Ruijter <mruijter@gmail.com> - 0.8.1
- Fixes a bug that causes mklessfs to segfault when DEBUG is not set.
- Adds lessfsck. lessfsck can be used  to check, optimize and repair 
- a lessfs filesystem.
* Mon Oct 26 2009 Mark Ruijter <mruijter@gmail.com> - 0.8.0
- Fixes a possible segfault when lessfs is used with lzo compression.
- Fixes a problem when compiling lessfs without encryption on
- a system without openssl-devel.
- Enhances the logging facility.
- Performance has improved for higher latency storage like iscsi, drbd.
- Reduces the number of fsync operations when sync_relax>0.
- 
- Thanks to : Roland Kletzing for finding and assisting
- with solving some of the problems mentioned.
 
* Fri Oct 22 2009 Adam Miller <maxamillion@fedoraproject.org> - 0.7.5-4
- Fixed missing URL field as well as missing Require for fuse
- Removed period from summary 

* Thu Oct 22 2009 Adam Miller <maxamillion@fedoraproject.org> - 0.7.5-3
  -Added fuse-devel and autoconf as build dependencies

* Wed Oct 21 2009 Adam Miller <maxamillion@fedoraproject.org> - 0.7.5-2
  -First attempt to build for Fedora review request
  -Based on upstream .spec, full credit of initial work goes to Mark Ruijter

* Fri Oct 16 2009 Mark Ruijter <mruijter@lessfs.com> - 0.7.5-1
  Fix a segfault on free after unmounting lessfs without
  encryption support. Fix a problem that could lead to a
  deadlock when using file_io with NFS.
  A performance improvement, changed a mutex lock for a
  spinlock.
* Sun Oct 11 2009 Mark Ruijter <mruijter@lessfs.com> - 0.7.4
  This version of lessfs introduces a new hash named
  Blue Midnight Whish : http://www.q2s.ntnu.no/sha3_nist_competition/start
  This is a very fast hash that increases lessfs performance
  significantly. The implementation makes it easy to use any
  of the hashes from the NIST hash competition. MBW was 
  choosen for lessfs because of the speed.
  To use BMW : configure --with-sha3
* Tue Oct 06 2009 Mark Ruijter <mruijter@lessfs.com> - 0.7.2
  Fix a typo in lib_tc.c that can lead to data corruption.
* Mon Oct 05 2009 Mark Ruijter <mruijter@lessfs.com> - 0.7.1
  Introduced a new data storage backend, file-io.
  Higher overall performance.
* Sun Sep 06 2009 Mark Ruijter <mruijter@lessfs.com> - 0.6.1
  Never improve your code minutes before releasing it.
  Fix a silly bug with mklessfs.
* Sun Sep 06 2009 Mark Ruijter <mruijter@lessfs.com> - 0.6.0
  Added encryption support to lessfs.
  Fixed one small bug that would leave orphaned meta data in the
  metadatabase when hardlinks where removed.
* Wed Aug 26 2009 Mark Ruijter <mruijter@lessfs.com> - 0.5.0
  Improved thread locking that leads to much better performance.
  Many NFS related problems have been solved and debugging
  is now easier.
* Mon Aug 17 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.8
  Many bugfixes, including incorrect filesize on writing
  in a file with various offsets using lseek. This also
  caused problems with NFS.
* Fri Aug 14 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.7
  Fixed a problem where dbstat failed to return the proper
  filesize. One other bug could leak to a deadlock of lessfs.
* Fri Jul 17 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.6
  Fixed two bugs, one which could lead to data corruption.
  One other that would leave deleted data in the database.
* Wed Jul 08 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.5
  This release fixes to one minor and one major bug.
  One bug in the code would actually crash lessfs
  upon renaming a file or directory. lessfs-0.2.4
  is no longer available for download.
* Sun Jul 05 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.4
  Added support for automatic defragmentation.
* Tue Jun 23 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.3
  This release fixes a small memory leak and improves
  write performance in general approx 12%.
  Known issues : 
  Using direct_io with kernel 2.6.30 causes reads to
  continue for ever. I am not sure if this is a kernel
  issue or a lessfs bug. With earlier kernels direct_io
  works fine.
* Sun Jun 21 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.2
  NFS support and improved caching code.
  WARNING : nfs will only work with kernel >= 2.6.30
* Wed Jun 10 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.1
  Improved the performance of writes smaller then 
  max_write in size. These writes will now remain long
  enough in the cache so that subsequent writes to the 
  same block will update the cache instead of the database.
  Mounting lessfs without formatting the filesystem now
  logs a warning instead of creating a segfault.
  Creating of sparse files now works again after being 
  broken in release 0.1.19.
* Mon May 25 2009 Mark Ruijter <mruijter@lessfs.com> - 0.2.0
  Added a cache that improves performance with approx 30%.
* Thu May 14 2009 Mark Ruijter <mruijter@lessfs.com> - 0.1.22
  Fixed a data corruption bug (workaround) when the 
  underlying filesystems run out of space. Fixed a problem
  with hardlinking symlinks.
* Wed Apr 22 2009 Mark Ruijter <mruijter@lessfs.com> - 0.1.20
  Fixed two bugs:
  1. Truncate operations would sometimes fail.
  2. unlink of hardlinked files would sometimes fail.
* Wed Apr 04 2009 Mark Ruijter <mruijter@lessfs.com> - 0.1.19 
  Fixed a bug in the truncation routine where a delete chunk 
  would remain in the database. Cleaned up the init script.
* Mon Mar 30 2009 Mark Ruijter <mruijter@lessfs.com> - 0.1.18 
* Mon Mar 27 2009 Mark Ruijter <mruijter@lessfs.com> - 0.1.17 
  Bug fix, reenable syslog.
* Mon Mar 27 2009 Mark Ruijter <mruijter@lessfs.com> - 0.1.16
* Mon Mar 23 2009 Mark Ruijter <mruijter@gmail.com>  - 0.1.15
* Sat Mar 21 2009 Mark Ruijter <mruijter@gmail.com>  - 0.1.14
* Tue Feb 24 2009 Mark Ruijter <mruijter@gmail.com>  - 0.1.13
- Initial package
