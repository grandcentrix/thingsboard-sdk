zephyr_include_directories(include)

if(CONFIG_THINGSBOARD)
    zephyr_library_named(thingsboard)

    set_property(
        TARGET thingsboard
        PROPERTY JSON_SCHEMAS
        ${CMAKE_CURRENT_SOURCE_DIR}/thingsboard_attr.jsonschema
    )

    add_custom_command(
        OUTPUT 
            ${CMAKE_CURRENT_BINARY_DIR}/generated/thingsboard_attr_parser.c
            ${CMAKE_CURRENT_BINARY_DIR}/generated/thingsboard_attr_parser.h
        COMMAND
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_json_parser.py ${CMAKE_CURRENT_BINARY_DIR}/generated/ $<TARGET_PROPERTY:thingsboard,JSON_SCHEMAS>
        DEPENDS ${JSON_SCHEMAS}
        COMMAND_EXPAND_LISTS
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    zephyr_library_sources(
        src/coap_client.c
        src/tb_fota.c
        src/thingsboard.c
        ${CMAKE_CURRENT_BINARY_DIR}/generated/thingsboard_attr_parser.c
    )

zephyr_include_directories(${CMAKE_CURRENT_BINARY_DIR}/generated)
endif()
