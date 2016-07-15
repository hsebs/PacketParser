TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp

win32: LIBS += -L'C://Program Files (x86)/Microsoft Visual Studio 14.0/VC/lib/x64/' -lwpcap
win32: LIBS += -lws2_32

INCLUDEPATH +='C://Program Files (x86)/Microsoft Visual Studio 14.0/VC/include'
DEPENDPATH += 'C://Program Files (x86)/Microsoft Visual Studio 14.0/VC/lib/x64'

HEADERS += \
    packetparser.h \
    libnet\libnet-headers.h \
    libnet\libnet-macros.h \
    libnet\libnet-asn1.h \
    libnet\libnet-functions.h \
    libnet\libnet-structures.h \
    libnet\libnet-types.h

