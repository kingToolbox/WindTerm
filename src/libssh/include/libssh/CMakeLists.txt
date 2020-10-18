project(libssh-headers C)

set(libssh_HDRS
  callbacks.h
  libssh.h
  ssh2.h
  legacy.h
  libsshpp.hpp
)

if (WITH_SFTP)
  set(libssh_HDRS
    ${libssh_HDRS}
    sftp.h
  )
endif (WITH_SFTP)

if (WITH_SERVER)
  set(libssh_HDRS
    ${libssh_HDRS}
    server.h
  )
endif (WITH_SERVER)

install(
  FILES
    ${libssh_HDRS}
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/${APPLICATION_NAME}
  COMPONENT
    headers
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libssh_version.h.cmake
               ${libssh_BINARY_DIR}/include/libssh/libssh_version.h
               @ONLY)
install(FILES ${libssh_BINARY_DIR}/include/libssh/libssh_version.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${APPLICATION_NAME}
        COMPONENT headers)
