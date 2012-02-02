
PREFIX=`pwd`
while [ "`basename $PREFIX`" != "parrot_cvmfs" ] && [ "$PREFIX" != "/" ]; do
  PREFIX="`dirname $PREFIX`"
done

PREFIX=$PREFIX/test
if ! [ -f $PREFIX/cms.hep.wisc.edu.pub ]; then
  echo "Cannot find cms.hep.wisc.edu.pub"
else

  if [ "$HTTP_PROXY" = "" ]; then
    if hostname | grep -q '\.wisc\.edu'; then
      export HTTP_PROXY="frontier01.hep.wisc.edu:3128|frontier02.hep.wisc.edu:3128"
    else
      echo "Reminder: you must define HTTP_PROXY or pass the -P option to parrot_run."
    fi
  fi

  export PARROT_CVMFS_REPO="
    cms.hep.wisc.edu:pubkey=$PREFIX/cms.hep.wisc.edu.pub,url=http://cvmfs01.hep.wisc.edu/cvmfs/cms.hep.wisc.edu
    <default-repositories>
  "

fi
