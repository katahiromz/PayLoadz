# Pause??.dll
add_library(Pause SHARED Pause.cpp Pause_res.rc)
set_target_properties(Pause PROPERTIES PREFIX "")
target_link_libraries(Pause PRIVATE hackKit_static shlwapi psapi winmm)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(Pause PROPERTIES OUTPUT_NAME "Pause64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(Pause PROPERTIES OUTPUT_NAME "Pause32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
