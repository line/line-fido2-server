#!/bin/sh

SPRING_PROFILES_ACTIVE=local ./gradlew :demo:bootrun |tee server.log

