

file(GLOB_RECURSE srcs src/*.cc)

add_library(ministd STATIC ${srcs})
target_include_directories(ministd PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
