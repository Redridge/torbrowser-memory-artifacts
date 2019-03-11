#!/bin/bash

rm -rf tor 2> /dev/null
mkdir -p tor

cd tor

wget https://www.torproject.org/dist/torbrowser/8.0.6/tor-browser-linux64-8.0.6_en-US.tar.xz
wget https://dist.torproject.org/torbrowser/8.0.6/tor-browser-linux64-debug.tar.xz

tar xJf tor-browser-linux64-8.0.6_en-US.tar.xz
tar xJf tor-browser-linux64-debug.tar.xz

mv Debug/Browser tor-browser_en-US/Browser/.debug
mv tor-browser_en-US/* .
rmdir tor-browser_en-US
rm -rf Debug
rm *.tar.xz
