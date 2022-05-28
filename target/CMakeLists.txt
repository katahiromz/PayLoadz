# target??.exe
add_executable(target WIN32 target.cpp target_res.rc)
target_link_libraries(target PRIVATE comctl32 winmm shlwapi)

# Choose filenames
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(target PROPERTIES OUTPUT_NAME "target64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(target PROPERTIES OUTPUT_NAME "target32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
