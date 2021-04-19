# $Id: Makefile,v 1.7 2005/09/23 15:41:55 kani Exp $
# $Date: 2005/09/23 15:41:55 $
# $Revision: 1.7 $

CXX= clang++

LIB= sha
SHLIB_MAJOR= 1
SHLIB_NINOR= 2

SRCS=	sha_base.cc sha1.cc sha224.cc sha256.cc sha384.cc sha512.cc md5.cc uintX_t.cc
INCS=	sha_base.hh sha1.hh sha224.hh sha256.hh sha384.hh sha512.hh md5.hh uintX_t.hh

CLEANFILES+=

CXXFLAGS+= -I${.CURDIR} -Wall -O2

test: a.out

a.out: ${SRCS} ${INCS}
	${CXX} -pipe -I. -O2 -Wall main.cc -L/home/kani/lib -lsha

.include <bsd.lib.mk>
