#!/bin/sh

SPRING_PROFILES_ACTIVE=local ./gradlew  :rpserver:bootrun|tee rpserver.log

