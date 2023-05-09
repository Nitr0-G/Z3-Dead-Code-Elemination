cmake_minimum_required(VERSION "3.15")

include(FetchContent)

project("Z3DeadCodeAndOp")

# Zydis
FetchContent_Declare(
  Zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG        master
)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Zydis)

# Add our project executable
add_executable("Z3DeadCodeAndOp" "src/main.cpp")

# Have CMake link our project executable against Zydis.
target_link_libraries(${PROJECT_NAME} PRIVATE Zydis)
target_include_directories(${PROJECT_NAME} PRIVATE Zydis)
