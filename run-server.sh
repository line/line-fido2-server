#!/bin/sh

SPRING_PROFILES_ACTIVE=conformance ./gradlew  :server:bootrun|tee server.log

