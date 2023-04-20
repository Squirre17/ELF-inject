add_rules("mode.debug", "mode.release")

-- Add prelude target
target("prelude")

    set_kind("object")
    add_files("shellcode/prelude.S")

    -- add_rules("extra_obj")
    -- before_build_files(function (target)
    --     os.exec("echo execute here")
    --     os.exec("objcopy -O binary --only-section=.text %s build/prelude.bin", target:objectfiles()[1])
    -- end)
target_end()
    
-- -- Add shellcode target
target("shellcode")
    
    set_kind("object")
    add_files("shellcode/shellcode.S")
    
    before_build(function (target)
    end)

target_end()
    
    
target("ElfInject")
    
    add_includedirs("inc")
    set_kind("binary")
    
    if is_mode("debug") then 
        add_cxflags("-g") 
        add_cxflags("-O0") 
    end
    
    add_files("src/*.S")
    add_files("src/*.c")

