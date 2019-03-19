# - Try to find Broadcom Nexus Widevine.
# Once done this will define
#  NexusWidevine_FOUND     - System has a Nexus Widevine
#  NexusWidevine::NexusWidevine - The Nexus Widevine library
#
# Copyright (C) 2019 Metrological B.V
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND ITS CONTRIBUTORS ``AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR ITS
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

find_path(LIBNexusWidevine_INCLUDE_DIR cdm.h
        PATH_SUFFIXES widevine refsw)

find_path(LIBNexusSVP_INCLUDE_DIR b_secbuf.h
        PATH_SUFFIXES refsw)

list(APPEND LIBNexusWidevine_INCLUDE_DIRS ${LIBNexusWidevine_INCLUDE_DIR} ${LIBNexusSVP_INCLUDE_DIR})

# main lib
find_library(LIBNexusWidevine_LIBRARY wvcdm)

# needed libs
list(APPEND NeededLibs cmndrm cmndrm_tl oemcrypto_tl protobuf-lite)

# needed svp libs
list(APPEND NeededLibs drmrootfs srai b_secbuf)

foreach (_library ${NeededLibs})
    find_library(LIBRARY_${_library} ${_library})
    if(NOT EXISTS "${LIBRARY_${_library}}")
        message(SEND_ERROR "Could not find mandatory library: ${_library}")
    endif()
    list(APPEND LIBNexusWidevine_LIBRARIES ${LIBRARY_${_library}})
endforeach ()

if(EXISTS "${LIBNexusWidevine_LIBRARY}")
    include(FindPackageHandleStandardArgs)

    set(NexusWidevine_FOUND TRUE)

    find_package_handle_standard_args(LIBNexusWidevine DEFAULT_MSG LIBNEXUS_INCLUDE LIBNexusWidevine_LIBRARY)
    mark_as_advanced(LIBNexusWidevine_LIBRARY)

    if(NOT TARGET NexusWidevine::NexusWidevine)
        add_library(NexusWidevine::NexusWidevine UNKNOWN IMPORTED)
        
        set_target_properties(NexusWidevine::NexusWidevine PROPERTIES
                IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                IMPORTED_LOCATION "${LIBNexusWidevine_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBNexusWidevine_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${LIBNexusWidevine_LIBRARIES}"
        )
    endif()
endif()