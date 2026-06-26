# examples/CMakeLists.txt
# ---------------------------------------------------------------------------
# Three SOME/IP demo applications — require vsomeip3.
# Each app is a standalone executable; run in separate terminals.
#
# Run sequence (from build directory):
#   VSOMEIP_CONFIGURATION=../examples/config/vsomeip-safety.json  ./safety_uc ../policies/tcu_rd_rc_policy.json
#   VSOMEIP_CONFIGURATION=../examples/config/vsomeip-appup.json   ./app_up    ../policies/tcu_rd_rc_policy.json
#   VSOMEIP_CONFIGURATION=../examples/config/vsomeip-nad.json     ./nad_app
# ---------------------------------------------------------------------------

# safety_uc — pure server (Diag + Ctrl services)
add_executable(safety_uc safety_uc.cpp)
target_link_libraries(safety_uc PRIVATE omac vsomeip3)
target_include_directories(safety_uc PRIVATE ${CMAKE_SOURCE_DIR}/include)

# app_up — broker (server for NAD + client to SafetyUC)
add_executable(app_up app_up.cpp)
target_link_libraries(app_up PRIVATE omac vsomeip3)
target_include_directories(app_up PRIVATE ${CMAKE_SOURCE_DIR}/include)

# nad_app — demo client driver
add_executable(nad_app nad_app.cpp)
target_link_libraries(nad_app PRIVATE omac vsomeip3)
target_include_directories(nad_app PRIVATE ${CMAKE_SOURCE_DIR}/include)
