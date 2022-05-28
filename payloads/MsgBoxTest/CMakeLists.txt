# MsgBoxTest??.dll
add_library(MsgBoxTest SHARED MsgBoxTest.cpp MsgBoxTest_res.rc)
set_target_properties(MsgBoxTest PROPERTIES PREFIX "")
target_link_libraries(MsgBoxTest PRIVATE hackKit_static shlwapi psapi winmm)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(MsgBoxTest PROPERTIES OUTPUT_NAME "MsgBoxTest64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(MsgBoxTest PROPERTIES OUTPUT_NAME "MsgBoxTest32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
