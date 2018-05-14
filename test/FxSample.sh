#!/bin/sh

# change dir
FXROOT=$(cd $(dirname $0); cd ..; pwd)
export FXROOT

# Java Setting
JCP_OPT=-classpath .:../lib/freexades-0.2.jar
export JCP_OPT

echo Sample Compile.
javac $JCP_OPT FxSample.java

echo Sample Execute.
java $JCP_OPT FxSample

echo Sample Finished.
