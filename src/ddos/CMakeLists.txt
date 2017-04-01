set(CMAKE_AUTOMOC OFF)

set(SOURCES
    Params.cc
    Users.cc
)

add_library(runos_ddos STATIC ${SOURCES})

target_link_libraries(runos_ddos ${Boost_UNIT_TEST_FRAMEWORK})
