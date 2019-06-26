target_sources(sio4
   PUBLIC
      ${CMAKE_CURRENT_SOURCE_DIR}/xxHash/xxhash.c
)

target_include_directories(sio4 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
