cmake_minimum_required(VERSION 3.5.0)

project(sha VERSION 0.1.0 LANGUAGES C)

find_package(OpenSSL REQUIRED)

add_executable(sha main.c)

target_link_libraries(sha PRIVATE OpenSSL::SSL)
target_link_libraries(sha PRIVATE OpenSSL::Crypto)
target_link_libraries(sha PRIVATE OpenSSL::applink)