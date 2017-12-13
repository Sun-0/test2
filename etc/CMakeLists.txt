file(GLOB_RECURSE TAWFLEXERS tawflexer/*.conf)
install(FILES ${TAWFLEXERS} DESTINATION /etc/tawflexer/flexer COMPONENT main)
install(FILES "tawflexer.conf" DESTINATION /etc/ COMPONENT main)
