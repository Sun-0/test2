# CMake 最低版本号要求
cmake_minimum_required (VERSION 2.8)
# 项目信息
project (tawflexer C)

set(VERSION "0.1.0")
# 把默认目录配置为/usr
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	    set (CMAKE_INSTALL_PREFIX "/usr" CACHE PATH "default install path" FORCE )
endif()

#变量
if( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" ) 
	set(TAW_FLEXER_DEBUG "1" CACHE STRING "enable debug" FORCE)
  ADD_DEFINITIONS( -g -O0 -fsanitize=address -fno-omit-frame-pointer)
	link_libraries(asan)
endif()

#create config.h
#configure_file(config.h.cmake config.h @ONLY)

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(etc)

#ADD_SUBDIRECTORY(test)

include (InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_VERSION ${VERSION})
set(CPACK_PACKAGE_NAME "tawflexer")
set(CPACK_GENERATOR "DEB")
SET(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ZHANG Fengyu <zhang_fengyu@topsec.com.cn")
set(CPACK_PACKAGE_CONTACT "ZHANG Fengyu <zhang_fengyu@topsec.com.cn")

set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

#set(CPACK_DEBIAN_LIBS_PACKAGE_DEPENDS "flexer-libuv,nanomsg-libs,ngtawstd-libs")
#set(CPACK_DEBIAN_DEV_PACKAGE_DEPENDS "nanomsg-dev,ngtawstd-dev")
set(CPACK_DEBIAN_LIBS_PACKAGE_DEPENDS "flexer-libuv, ngtawstd-libs")
set(CPACK_DEBIAN_DEV_PACKAGE_DEPENDS "ngtawstd-dev")

include (CPack)

