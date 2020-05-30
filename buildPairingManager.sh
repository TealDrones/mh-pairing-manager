#!/bin/sh
source /usr/local/rb3-oecore-x86_64/environment-setup-aarch64-oe-linux

rm -Rf build
mkdir build
pushd build

cmake ..
tag=$(git describe --tags `git rev-list --tags --max-count=1`)
branch=$(git rev-parse --abbrev-ref HEAD)
echo pm-$branch-$tag
if make -j16; then
	popd
	scp build/src/pairing-manager pi@dmz.tealdrones.com:/home/pi/code/distro/pm-$branch-$tag
#	scp build/src/pairing-manager root@drone:~/code/distro/pm-$branch-$tag
	echo "Build Success +++++++++++++++++++++++++++"
else 
	echo "BUILD FAILED ----------------------------"
	popd
fi
