cmake_minimum_required(VERSION 3.8)
project(CarParts)

set(CMAKE_CXX_STANDARD 17)

set(SOURCE_FILES main.cpp BitConverter.h BitConverter.cc JDLZ.cc JDLZ.h)

set(Boost_INCLUDE_DIR /usr/local/Cellar/boost/1.64.0_1/include)
set(Boost_LIBRARY_DIR /usr/local/Cellar/boost/1.64.0_1/lib)
find_package(Boost COMPONENTS system filesystem REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

add_executable(CarParts ${SOURCE_FILES})
target_link_libraries(CarParts ${Boost_LIBRARIES})