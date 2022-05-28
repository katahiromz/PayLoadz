# injector??.exe
add_executable(injector injector.cpp)
target_link_libraries(injector PRIVATE hackKit_static shlwapi psapi)

# Choose filenames
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(injector PROPERTIES OUTPUT_NAME "injector64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(injector PROPERTIES OUTPUT_NAME "injector32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
