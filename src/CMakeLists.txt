include_directories(AFTER SYSTEM ${CMAKE_BINARY_DIR})
link_directories(${PROJECT_SOURCE_DIR}/src)

set(DIR_LIB_SRCS tawflexer.c functions.c flexer_reader.c reciver.c reciver_reader.c logger.c logger_reader.c )

#ADD_DEFINITIONS( -g -D_GNU_SOURCE  -Wall -I../usr/include/ngtawstd/libconfig.h )
ADD_DEFINITIONS( -g -D_GNU_SOURCE  -Wall )

add_library (tawflexer SHARED ${DIR_LIB_SRCS})
SET_TARGET_PROPERTIES(tawflexer PROPERTIES SOVERSION 0 VERSION ${VERSION}
	COMPILE_DEFINITIONS  LOG_PREFIX=\"com.topsec.tawflexer.\")
TARGET_LINK_LIBRARIES(tawflexer uv nanomsg ngtawutils config)

add_library (tawflexer_test MODULE ${DIR_LIB_SRCS})
set(tawflexer_test_cflags  LOG_PREFIX=\"com.topsec.tawflexer_test.\" UNIT_TEST)
SET_TARGET_PROPERTIES(tawflexer_test PROPERTIES SOVERSION 0 VERSION ${VERSION}
	COMPILE_DEFINITIONS UNIT_TEST)
TARGET_LINK_LIBRARIES( tawflexer_test ngtawutils config uv nanomsg ngtawstd cunit ngtest rt pthread )


add_executable(tawlogserver main.c udp.c)
TARGET_LINK_LIBRARIES(tawlogserver ngtawstd tawflexer pcre pthread)
SET_TARGET_PROPERTIES(tawlogserver PROPERTIES COMPILE_DEFINITIONS  LOG_PREFIX=\"com.topsec.tawlogserver.\")


file(GLOB_RECURSE TAWFLEXER_HEADERS *.h)
install(FILES ${TAWFLEXER_HEADERS} DESTINATION include/tawflexer/ COMPONENT dev)

install(TARGETS tawflexer tawlogserver
   RUNTIME DESTINATION bin
   COMPONENT libs
	 LIBRARY DESTINATION lib
   COMPONENT libs
	 )
			


