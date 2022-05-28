# SpeedUp??.dll
add_library(SpeedUp SHARED SpeedUp.cpp SpeedUp_res.rc)
set_target_properties(SpeedUp PROPERTIES PREFIX "")
target_link_libraries(SpeedUp PRIVATE hackKit_static shlwapi psapi winmm)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(SpeedUp PROPERTIES OUTPUT_NAME "SpeedUp64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(SpeedUp PROPERTIES OUTPUT_NAME "SpeedUp32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
