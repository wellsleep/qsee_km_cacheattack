#!/bin/sh

adb shell am start -n com.example.svqsee/.MainActivity

sleep 2

adb shell am force-stop  com.example.svqsee
