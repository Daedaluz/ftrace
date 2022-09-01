cmake_minimum_required(VERSION 3.17)
project(ftrace)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(ftrace
        ftrace.c
        util.c)
