target_sources(sio4
   PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/xxHash/xxhash.c
      ${CMAKE_CURRENT_SOURCE_DIR}/sha256/sha256.c
      ${CMAKE_CURRENT_SOURCE_DIR}/sha256/zeroize.c
)

target_include_directories(sio4 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
