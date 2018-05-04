CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
PROJECT(sr_uci)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 -Wall")

set(SOURCES
	src/sr_uci.c)

set(HEADERS
	src/sr_uci.h)

add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})

# dependencies - sysrepo
find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

# dependencies - libubox
find_package(LIBUBOX REQUIRED)
include_directories(${LIBUBOX_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBUBOX_LIBRARIES})

# dependencies - libubus
find_package(LIBUBUS REQUIRED)
include_directories(${LIBUBUS_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBUBUS_LIBRARIES})

# dependencies - uci
find_package(UCI REQUIRED)
include_directories(${UCI_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${UCI_LIBRARIES} ${CMAKE_DL_LIBS})

# dependencies - json-c
find_package(JSON-C REQUIRED)
include_directories(${JSON-C_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} json-c)

install(FILES ${HEADERS} DESTINATION include)
install(TARGETS ${CMAKE_PROJECT_NAME} LIBRARY DESTINATION lib)
