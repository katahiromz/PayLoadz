# SlowDown??.dll
add_library(SlowDown SHARED SlowDown.cpp SlowDown_res.rc)
set_target_properties(SlowDown PROPERTIES PREFIX "")
target_link_libraries(SlowDown PRIVATE hackKit_static shlwapi psapi winmm)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(SlowDown PROPERTIES OUTPUT_NAME "SlowDown64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(SlowDown PROPERTIES OUTPUT_NAME "SlowDown32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
