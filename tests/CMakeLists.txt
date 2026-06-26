# tests/CMakeLists.txt
# ---------------------------------------------------------------------------
# Unit tests - no vsomeip required.
# Run from build directory: ctest --output-on-failure
# ---------------------------------------------------------------------------

# test_footer - header-only, no link deps
add_executable(test_footer test_footer.cpp)
target_include_directories(test_footer PRIVATE ${CMAKE_SOURCE_DIR}/include)

# test_crypto - needs omac (which links OpenSSL transitively)
add_executable(test_crypto test_crypto.cpp)
target_link_libraries(test_crypto PRIVATE omac)

# test_automaton - needs omac (automaton + nlohmann/json)
add_executable(test_automaton test_automaton.cpp)
target_link_libraries(test_automaton PRIVATE omac)

# test_flows - integration test (full stack: crypto + automaton + monitor)
add_executable(test_flows test_flows.cpp)
target_link_libraries(test_flows PRIVATE omac)

# test_inheritance - mock proof of the paper's SecuredMessageImpl flow
add_executable(test_inheritance test_inheritance.cpp)
target_link_libraries(test_inheritance PRIVATE omac)

# Register with CTest
enable_testing()
add_test(NAME footer    COMMAND test_footer)
add_test(NAME crypto    COMMAND test_crypto    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME automaton COMMAND test_automaton WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME flows     COMMAND test_flows     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME inheritance COMMAND test_inheritance WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
