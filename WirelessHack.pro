#-------------------------------------------------
#
# Project created by QtCreator 2016-01-20T04:03:18
#
#-------------------------------------------------

QT       += core

QT       -= gui

TARGET = WirelessHack
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

SOURCES += main.cpp

LIBS += -lpcap

HEADERS += \
    ieee80211_radiotap.h

CONFIG += c++11

FORMS += \
    dialog.ui
