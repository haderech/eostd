target_sources(eostd
   PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/xxHash/xxhash.c
      ${CMAKE_CURRENT_SOURCE_DIR}/sha256/sha256.c
      ${CMAKE_CURRENT_SOURCE_DIR}/sha256/zeroize.c
)

target_include_directories(eostd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
