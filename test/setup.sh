
PREFIX=`pwd`
while [ "`basename $PREFIX`" != "parrot_cvmfs" ] && [ "$PREFIX" != "/" ]; do
  PREFIX="`dirname $PREFIX`"
done

PREFIX=$PREFIX/test
if ! [ -f $PREFIX/cms.hep.wisc.edu.pub ]; then
  echo "Cannot find cms.hep.wisc.edu.pub"
else

  if [ "$HTTP_PROXY" = "" ]; then
    export HTTP_PROXY="frontier01.hep.wisc.edu:3128|frontier02.hep.wisc.edu:3128"
  fi

  export PARROT_CVMFS_REPO="
    cms.hep.wisc.edu:pubkey=$PREFIX/cms.hep.wisc.edu.pub,url=http://cvmfs01.hep.wisc.edu/cvmfs/cms.hep.wisc.edu
    <default-repositories>
  "

fi
