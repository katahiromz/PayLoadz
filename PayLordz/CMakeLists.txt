# PayLordz??exe
add_executable(PayLordz WIN32 PayLordz.cpp PayLordz_res.rc)
target_link_libraries(PayLordz PRIVATE hackKit_static comctl32 comdlg32 imagehlp shlwapi)

# Choose filenames
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(PayLordz PROPERTIES OUTPUT_NAME "PayLordz64")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set_target_properties(PayLordz PROPERTIES OUTPUT_NAME "PayLordz32")
else()
    message(FATAL_ERROR "Your compiler is not supported yet")
endif()
