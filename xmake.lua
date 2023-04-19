add_rules("mode.debug", "mode.release")

-- Add prelude target
-- target("prelude")
--     set_kind("objects")
--     add_files("shellcode/prelude.S")
--     set_extension(".bin")

--     before_link(function (target)
--         print("test before_link")
--     end)
--     -- Add custom command to generate prelude.bin
--     -- after_build(function (target) 
--     print("objcopy -O binary --only-section=.text prelude.S.o prelude.bin")
--     os.exec("objcopy -O binary --only-section=.text prelude.o prelude.bin") 
--     -- end)
-- target_end()

-- -- Add shellcode target
-- target("shellcode")
--     set_kind("binary")
--     add_files("shellcode/shellcode.S")

--     -- Add custom command to generate shellcode.bin
--     add_custom_command("shellcode.bin", function (target)
--             os.runv("gcc", {"-nostdlib", "-o", "shellcode.o", "shellcode.S"})
--             os.runv("objcopy", {"-O", "binary", "--only-section=.text", "shellcode.o", "shellcode.bin"})
--         end,
--         {dependfile = "shellcode.S"})


target("ElfInject")

    add_includedirs("inc")
    set_kind("binary")
    
    if is_mode("debug") then 
        add_cxflags("-g") 
        add_cxflags("-O0") 
    end
    
    add_files("src/*.S")
    add_files("src/*.c")

--
-- If you want to known more usage about xmake, please see https://xmake.io
--
-- ## FAQ
--
-- You can enter the project directory firstly before building project.
--
--   $ cd projectdir
--
-- 1. How to build project?
--
--   $ xmake
--
-- 2. How to configure project?
--
--   $ xmake f -p [macosx|linux|iphoneos ..] -a [x86_64|i386|arm64 ..] -m [debug|release]
--
-- 3. Where is the build output directory?
--
--   The default output directory is `./build` and you can configure the output directory.
--
--   $ xmake f -o outputdir
--   $ xmake
--
-- 4. How to run and debug target after building project?
--
--   $ xmake run [targetname]
--   $ xmake run -d [targetname]
--
-- 5. How to install target to the system directory or other output directory?
--
--   $ xmake install
--   $ xmake install -o installdir
--
-- 6. Add some frequently-used compilation flags in xmake.lua
--
-- @code
--    -- add debug and release modes
--    add_rules("mode.debug", "mode.release")
--
--    -- add macro defination
--    add_defines("NDEBUG", "_GNU_SOURCE=1")
--
--    -- set warning all as error
--    set_warnings("all", "error")
--
--    -- set language: c99, c++11
--    set_languages("c99", "c++11")
--
--    -- set optimization: none, faster, fastest, smallest
--    set_optimize("fastest")
--
--    -- add include search directories
--    add_includedirs("/usr/include", "/usr/local/include")
--
--    -- add link libraries and search directories
--    add_links("tbox")
--    add_linkdirs("/usr/local/lib", "/usr/lib")
--
--    -- add system link libraries
--    add_syslinks("z", "pthread")
--
--    -- add compilation and link flags
--    add_cxflags("-stdnolib", "-fno-strict-aliasing")
--    add_ldflags("-L/usr/local/lib", "-lpthread", {force = true})
--
-- @endcode
--

