
PREFIX=`pwd`
while [ "`basename $PREFIX`" != "parrot_cvmfs" ] && [ "$PREFIX" != "/" ]; do
  PREFIX="`dirname $PREFIX`"
done

PREFIX=$PREFIX/test
if ! [ -f $PREFIX/cms.hep.wisc.edu.pub ]; then
  echo "Cannot find cms.hep.wisc.edu.pub"
else

  if [ "$HTTP_PROXY" = "" ]; then
    cvmfs_proxies="proxies=frontier01.hep.wisc.edu:3128;fronteir02.hep.wisc.edu:3128,"
  fi

  export PARROT_CVMFS_REPO="
    cms.hep.wisc.edu:force_signing,pubkey=$PREFIX/cms.hep.wisc.edu.pub,${cvmfs_proxies}url=http://cvmfs01.hep.wisc.edu/cvmfs/cms.hep.wisc.edu
    cms.cern.ch:force_signing,pubkey=$PREFIX/cern.ch.pub,${cvmfs_proxies}url=http://cvmfs-stratum-one.cern.ch/opt/cms;http://cernvmfs.gridpp.rl.ac.uk/opt/cms;http://cvmfs.racf.bnl.gov/opt/cms
  "

fi
