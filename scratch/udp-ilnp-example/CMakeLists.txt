build_exec(
  EXECNAME udp-ilnp-example
  SOURCE_FILES udp-ilnp-example.cc
  LIBRARIES_TO_LINK ${libinternet}
                    ${libcore}
                    ${libnetwork}
  EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/udp-ilnp-example
)
