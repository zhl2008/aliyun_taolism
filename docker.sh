#!/bin/sh

docker run -p 80:80 -v `pwd`:/var/www/html -ti ubuntu:16.10
