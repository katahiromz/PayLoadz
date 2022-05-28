# target2_??.exe
add_executable(target2_ target2_.cpp)
target_link_libraries(target2_ PRIVATE shlwapi)

# Choose filenames
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(target2_ PROPERTIES OUTPUT_NAME "target2_64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(target2_ PROPERTIES OUTPUT_NAME "target2_32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
