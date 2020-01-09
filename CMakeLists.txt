cmake_minimum_required(VERSION 3.1)

#set project name and language
project(vf-crypto-bridge LANGUAGES CXX)

#Automoc and RCC ON. Needed in QT projects
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
#C++ 11 Flag
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

#Set project Version
set(VfCryptoBridge_VERSION_MAJOR "0")
set(VfCryptoBridge_VERSION_MINOR "0")
set(VfCryptoBridge_VERSION_PATCH "1")


set(PROJECT_VERSION "${VfCryptoBridge_VERSION_MAJOR}.${VfCryptoBridge_VERSION_MINOR}.${VfCryptoBridge_VERSION_PATCH}")


option(useOpenSsl "Using libsystemd" ON)


#Adding cmake functions like feature_summary()
include(FeatureSummary)
include(GNUInstallDirs)

#Find dependecies
find_package(Qt5 COMPONENTS Core CONFIG REQUIRED)
if(${useOpenSsl})
	find_package(OpenSSL COMPONENTS SSL Crypto REQUIRED)
endif()
#sum up project Files
file(GLOB SOURCES 
    ${PROJECT_SOURCE_DIR}/*.cpp
    )

file(GLOB HEADER
    ${PROJECT_SOURCE_DIR}/*.h
    )

file(GLOB RESOURCES 
    ${PROJECT_SOURCE_DIR}/*.qrc
    )

#create library 
add_library(VfCryptoBridge SHARED
    ${SOURCES}
    ${HEADER}
    ${RESOURCES}
    )

#link dependencies
target_link_libraries(VfCryptoBridge 
    PRIVATE
    Qt5::Core
    )

if(${openSSL_FOUND})
    target_link_libraries(VfCryptoBridge 
        PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()

#set target Version
set_target_properties(VfCryptoBridge PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(VfCryptoBridge PROPERTIES SOVERSION ${VfCryptoBridge_VERSION_MAJOR})
message(STATUS "Project Version: " ${PROJECT_VERSION})

#generate export header
include(GenerateExportHeader)
generate_export_header(VfCryptoBridge)


install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/vfcryptobridge_export.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/VfCryptoBridge
    )


# announce headers - target perspective
target_include_directories(VfCryptoBridge
    PUBLIC
    $<INSTALL_INTERFACE:include/VfCryptoBridge>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

# install library
install(TARGETS VfCryptoBridge
    EXPORT VfCryptoBridgeExport
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )

# configure *Version.cmake
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    VfCryptoBridgeConfigVersion.cmake
    VERSION ${PACKAGE_VERSION}
    COMPATIBILITY SameMinorVersion
    )

# configure *Config.cmake
configure_file(VfCryptoBridgeConfig.cmake.in VfCryptoBridgeConfig.cmake @ONLY)

message(STATUS "BINDIR: " ${CMAKE_CURRENT_BINARY_DIR})

# install *Config(Version).cmake
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/VfCryptoBridgeConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/VfCryptoBridgeConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/VfCryptoBridge
    )

# install targets cmake-files
install(EXPORT VfCryptoBridgeExport
    FILE VfCryptoBridgeTargets.cmake
    NAMESPACE VeinMeta::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/VfCryptoBridge
    )

# install public headers
install(
    FILES ${HEADER}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/VfCryptoBridge
    )

# spawn out some info on configuration
feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)



