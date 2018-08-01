#-------------------------------------------------
#
# Project created by QtCreator 2018-06-28T13:04:44
#
#-------------------------------------------------

QT       -= gui

TARGET = vf-crypto-bridge
TEMPLATE = lib

DEFINES += VFCRYPTOBRIDGE_LIBRARY

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

HEADERS += vf-crypto-bridge_global.h

CONFIG += link_pkgconfig

isEmpty(VF_NO_OPENSSL) {
# Link to libcrypto using pkg-config:
  PKGCONFIG += libcrypto

  HEADERS += opensslsignaturehandler.h
  SOURCES += opensslsignaturehandler.cpp
}

public_headers.files = $$HEADERS

exists( ../../vein-framework.pri ) {
  include(../../vein-framework.pri)
}
