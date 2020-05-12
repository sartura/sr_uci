cmake_minimum_required(VERSION 2.8)
project(sr_uci C)

include(CompileOptions.cmake)

include_directories(${CMAKE_SOURCE_DIR}/src/)
add_library(${PROJECT_NAME} MODULE src/sr_uci.c)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")
find_package(SYSREPO REQUIRED)
find_package(JSON-C REQUIRED)
find_package(UCI REQUIRED)
find_package(LIBUBUS REQUIRED)
find_package(LIBUBOX REQUIRED)

target_link_libraries(
	${PROJECT_NAME}
	${SYSREPO_LIBRARIES}
	${JSON-C_LIBRARIES}
	${UCI_LIBRARIES}
	${LIBUBUS_LIBRARIES}
	${LIBUBOX_LIBRARIES}
)

include_directories(
	${SYSREPO_INCLUDE_DIR}
	${LIBUBOX_INCLUDE_DIR}
	${LIBUBUS_INCLUDE_DIR}
	${UCI_INCLUDE_DIR}
	${JSON-C_INCLUDE_DIR}
)

install(FILES ${HEADERS} DESTINATION include)
install(TARGETS ${CMAKE_PROJECT_NAME} LIBRARY DESTINATION lib)