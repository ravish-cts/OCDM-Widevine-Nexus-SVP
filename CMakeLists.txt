cmake_minimum_required(VERSION 3.3)

project(WideVine)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(DRM_PLUGIN_NAME "WideVine")

set(CENC_VERSION 3 CACHE STRING "Defines version of CENC is used.")

find_package(WPEFramework)
find_package(${NAMESPACE}Core)
find_package(NEXUS)
find_package(NXCLIENT)
find_package(NexusWidevine)

add_library(${DRM_PLUGIN_NAME} SHARED
    HostImplementation.cpp 
    DeviceCertificate.cpp 
    MediaSession.cpp 
    MediaSystem.cpp
)

set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES 
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED YES
    SUFFIX ".drm"
    PREFIX ""
)

target_compile_definitions(${DRM_PLUGIN_NAME} 
    PRIVATE
        USE_CENC${CENC_VERSION}
)

target_link_libraries(${DRM_PLUGIN_NAME} 
    PRIVATE
        ${NAMESPACE}Core::${NAMESPACE}Core
        NEXUS::NEXUS
        NXCLIENT::NXCLIENT
        NexusWidevine::NexusWidevine
)

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)

