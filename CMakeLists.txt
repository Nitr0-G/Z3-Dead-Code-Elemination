cmake_minimum_required(VERSION "3.15")
project("Z3MyTestDeadCodeElemination")

# Register Zydis dependency.
# Disable build of tools and examples.
option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

# Add our project executable
add_executable("Z3MyTestDeadCodeElemination" "Source.cpp")

# Have CMake link our project executable against Zydis.
target_link_libraries("Z3MyTestDeadCodeElemination" PRIVATE "Zydis")