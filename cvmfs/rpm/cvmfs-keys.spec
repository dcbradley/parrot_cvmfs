Summary: CernVM File System Public Keys
Name: cvmfs-keys
Version: 1.2
Release: 1
Source0: %{name}-%{version}.tar.gz
BuildArch: noarch
# from cvmfs source package
Group: System/Filesystems
License: Copyright (c) 2009, CERN.  Distributed unter the BSD License.
%description
HTTP File System for Distributing Software to CernVM.
See http://cernvm.cern.ch
%install
install -D -m 444 cern.ch.pub /etc/cvmfs/keys/cern.ch.pub
install -D -m 444 cern-it1.cern.ch.pub /etc/cvmfs/keys/cern-it1.cern.ch.pub
install -D -m 444 cern-it2.cern.ch.pub /etc/cvmfs/keys/cern-it2.cern.ch.pub
%files
%attr(444,root,root) /etc/cvmfs/keys/cern.ch.pub
%attr(444,root,root) /etc/cvmfs/keys/cern-it1.cern.ch.pub
%attr(444,root,root) /etc/cvmfs/keys/cern-it2.cern.ch.pub
%dir /etc/cvmfs
%dir /etc/cvmfs/keys
