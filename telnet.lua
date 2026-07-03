--[[
  *********************************************************************************
  * @file           : telnet.lua
  * @brief          : 用于 CC:Tweaked 的类Telnet服务端/客户端程序
  * 支持命令行参数解析、密码认证及安全连接管理。
  * 已测试可用的CC:T版本：1.120.0
  * @author         : HTP2048
  * @date           : 2026-07-03
  * @version        : 1.0.0
  *********************************************************************************
  * @attention
  *
  * MIT License
  * 
  * Copyright (c) 2026 HTP2048
  * 
  * Permission is hereby granted, free of charge, to any person obtaining a copy
  * of this software and associated documentation files (the "Software"), to deal
  * in the Software without restriction, including without limitation the rights
  * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  * copies of the Software, and to permit persons to whom the Software is
  * furnished to do so, subject to the following conditions:
  * 
  * The above copyright notice and this permission notice shall be included in all
  * copies or substantial portions of the Software.
  * 
  * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  * SOFTWARE.
  *
  *********************************************************************************
]]

-- ========================================================
-- 命令参数行解析
-- ========================================================
-- 参数定义表 (Schema)
local SCHEMA = {
    mode = {
        type = "string",
        pos = 1,
        desc = "Run mode (server/client)"
    },
    protocol = {
        type = "string",
        alias = {"p", "proto"},
        desc = "Rednet protocol name"
    },
    password = {
        type = "string",
        alias = {"pwd", "pw"},
        default = "",
        desc = "Connection password"
    },
    host = {
        type = "number",
        pos = 2,
        alias = {"server", "id", "h"},
        desc = "Remote host ID"
    },
    monitor = {
        type = "bool",
        alias = {"m", "monitor", "display"},
        desc = "Use monitor"
    },
    exclusive = {
        type = "bool",
        alias = {"e", "excl", "exc"},
        desc = "Exclusive connection"
    }
}

local function parseArgs(args)
    local result = {}
    local pos_map = {} 
    local alias_map = {}

    -- 初始化：构建映射表
    for k, cfg in pairs(SCHEMA) do
        -- Bool 类型默认设为 false，非 Bool 类型不预设
        if cfg.type == "bool" then result[k] = false end
        if cfg.pos then pos_map[cfg.pos] = k end
        alias_map[k] = k
        if cfg.alias then
            for _, a in ipairs(cfg.alias) do alias_map[a] = k end
        end
    end

    local i = 1
    local current_pos = 1

    while i <= #args do
        local arg = args[i]

        -- 处理 --long_flag
        if string.sub(arg, 1, 2) == "--" then
            local key = string.sub(arg, 3)
            local canonical = alias_map[key]
            if not canonical then error("Unknown flag: " .. arg, 0) end
            
            if SCHEMA[canonical].type == "bool" then
                result[canonical] = true
            else
                i = i + 1
                if i > #args then error("Flag " .. arg .. " requires a value", 0) end
                if SCHEMA[canonical].type == "number" then
                    result[canonical] = tonumber(args[i]) or error("Invalid number for " .. key, 0)
                else
                    result[canonical] = args[i]
                end
            end

        -- 处理 -s (短参数)
        elseif string.sub(arg, 1, 1) == "-" then
            if string.len(arg) ~= 2 then error("Invalid short flag: " .. arg, 0) end
            local key = string.sub(arg, 2, 2)
            local canonical = alias_map[key]
            if not canonical then error("Unknown flag: " .. arg, 0) end

            if SCHEMA[canonical].type == "bool" then
                result[canonical] = true
            else
                i = i + 1
                if i > #args then error("Flag " .. arg .. " requires a value", 0) end
                if SCHEMA[canonical].type == "number" then
                    result[canonical] = tonumber(args[i]) or error("Invalid number for " .. key, 0)
                else
                    result[canonical] = args[i]
                end
            end

        -- 处理位置参数
        else
            local target_key = pos_map[current_pos]
            if target_key then
                result[target_key] = arg
                current_pos = current_pos + 1
            end
        end
        i = i + 1
    end
    return result
end

local function printUsage()
    local programName = shell.getRunningProgram()
    
    -- 1. 动态生成 Usage 行，自动根据 pos 排序
    local pos_args = {}
    for k, v in pairs(SCHEMA) do
        if v.pos then pos_args[v.pos] = k end
    end
    
    local usageLine = "Usage: " .. programName
    for i = 1, #pos_args do
        usageLine = usageLine .. " [" .. pos_args[i] .. "]"
    end
    usageLine = usageLine .. " [options...]"
    
    print(usageLine)
    
    -- 2. 打印选项参数
    print("\nOptions:")
    for k, v in pairs(SCHEMA) do
        if not v.pos then
            local alias_str = v.alias and ("[" .. table.concat(v.alias, ", ") .. "]") or ""
            local default_str = (v.default ~= nil and v.default ~= "") and (" [Default: " .. tostring(v.default) .. "]") or ""
            print(string.format("  %-15s %-15s %s%s", k, alias_str, v.desc, default_str))
        end
    end
end

local opts = parseArgs({...})

if not opts.mode or opts.mode == "" then
    printUsage()
    error("Mode parameter is required.", 0)
end

if opts.mode ~= "server" and opts.mode ~= "client" then
    printUsage()
    error("Invalid mode: " .. tostring(opts.mode), 0)
end

if not opts.protocol or opts.protocol == "" then
    printUsage()
    error("Protocol parameter is required.", 0)
end

if opts.mode == "client" and not opts.host then
    printUsage()
    error("Host parameter is required.", 0)
end

-- ========================================================
-- TEA安全模块
-- ========================================================

local hex_utils = {}
hex_utils.toHex = function(s) return (s:gsub('.', function(c) return string.format('%02x', c:byte()) end)) end
hex_utils.fromHex = function(s) return (s:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end)) end

-- 辅助：二进制字符串异或
local function xor_strings(s1, s2)
    local res = ""
    for i = 1, #s1 do
        res = res .. string.char(bit32.bxor(string.byte(s1, i), string.byte(s2, i)))
    end
    return res
end

-- 密钥扩展
local function expandKey(key)
    local k = {0, 0, 0, 0}
    for i = 1, 16 do
        local char = string.byte(key, (i - 1) % #key + 1) or 0
        local idx = math.floor((i - 1) / 4) + 1
        k[idx] = bit32.bor(bit32.lshift(k[idx], 8), char)
    end
    return k
end

-- XXTEA 加密块 (2 个 32 位整数)
local function xxtea_block_encrypt(v0, v1, k)
    local delta = 0x9e3779b9
    local sum = 0
    -- XXTEA 轮数逻辑
    for i = 1, 32 do
        sum = (sum + delta) % 0x100000000
        local e = bit32.rshift(sum, 2)
        v0 = (v0 + bit32.bxor(bit32.lshift(v1, 4) + k[1], v1 + sum, bit32.rshift(v1, 5) + k[2])) % 0x100000000
        v1 = (v1 + bit32.bxor(bit32.lshift(v0, 4) + k[3], v0 + sum, bit32.rshift(v0, 5) + k[4])) % 0x100000000
    end
    return v0, v1
end

-- XXTEA 解密块
local function xxtea_block_decrypt(v0, v1, k)
    local delta = 0x9e3779b9
    local sum = (delta * 32) % 0x100000000
    for i = 1, 32 do
        v1 = (v1 - bit32.bxor(bit32.lshift(v0, 4) + k[3], v0 + sum, bit32.rshift(v0, 5) + k[4])) % 0x100000000
        v0 = (v0 - bit32.bxor(bit32.lshift(v1, 4) + k[1], v1 + sum, bit32.rshift(v1, 5) + k[2])) % 0x100000000
        sum = (sum - delta) % 0x100000000
    end
    return v0, v1
end

local xxtea_cbc = {}

function xxtea_cbc.encrypt(text, key)
    local k = expandKey(key)
    -- PKCS#7 填充
    local pad_len = 8 - (#text % 8)
    text = text .. string.rep(string.char(pad_len), pad_len)
    
    -- 生成随机 IV (8 bytes)
    local iv = ""
    for i = 1, 8 do iv = iv .. string.char(math.random(0, 255)) end
    
    local prev = iv
    local result = iv -- 密文开头包含 IV
    
    for i = 1, #text, 8 do
        local block = string.sub(text, i, i + 7)
        local xored = xor_strings(block, prev)
        local v0, v1 = string.unpack(">II", xored)
        v0, v1 = xxtea_block_encrypt(v0, v1, k)
        local encrypted = string.pack(">II", v0, v1)
        
        result = result .. encrypted
        prev = encrypted
    end
    return hex_utils.toHex(result)
end

function xxtea_cbc.decrypt(hex, key)
    local data = hex_utils.fromHex(hex)
    local k = expandKey(key)
    
    -- 提取 IV 和密文
    local iv = string.sub(data, 1, 8)
    local ciphertext = string.sub(data, 9)
    
    local prev = iv
    local result = ""
    
    for i = 1, #ciphertext, 8 do
        local block = string.sub(ciphertext, i, i + 7)
        local v0, v1 = string.unpack(">II", block)
        v0, v1 = xxtea_block_decrypt(v0, v1, k)
        local decrypted = string.pack(">II", v0, v1)
        
        result = result .. xor_strings(decrypted, prev)
        prev = block
    end
    
    -- 去填充
    local pad_len = string.byte(result, -1)
    if pad_len > 0 and pad_len <= 8 then
        return string.sub(result, 1, - (pad_len + 1))
    end
    return result
end


local modem = peripheral.find("modem", function(name, p) return p.isWireless() end) 
    or error("Fatal Error: No Wireless modem detected!", 0)
rednet.open(peripheral.getName(modem))



-- ========================================================
-- 服务器模式 (Server Mode)
-- ========================================================
if opts.mode == "server" then
    local connected_client_id = nil
    local tx_queue = { first = 1, last = 0 }

    local function queueMessage(targetId, msg, proto)
        -- 记录推入数据前的队列状态
        local wasEmpty = (tx_queue.first > tx_queue.last)

        local last = tx_queue.last + 1
        tx_queue.last = last
        tx_queue[last] = { targetId = targetId, msg = msg, proto = proto }

        -- 只有当 Worker 处于休眠状态（队列原先为空）时，才发出事件唤醒它
        if wasEmpty then
            os.queueEvent("telnet_new_packet")
        end
    end

    local function sender_worker()
        while true do
            os.pullEventRaw("telnet_new_packet")

            while tx_queue.first <= tx_queue.last do
                local packet_info = tx_queue[tx_queue.first]

                rednet.send(packet_info.targetId, packet_info.msg, packet_info.proto)
            
                tx_queue[tx_queue.first] = nil 
                tx_queue.first = tx_queue.first + 1

                if tx_queue.first > tx_queue.last then
                    tx_queue.first = 1
                    tx_queue.last = 0
                end

                for i = 1, 20000, 1 do   -- 这个空循环负责对发送进行微小延迟，以跟上接收端处理速度。
                end                     -- 如果客户端出现了画面内容截断，不同步或者丢包的现象，说明客户端处理速度无法跟上发送端发送速度，造成了事件队列溢出丢包，则可以尝试适当增加循环次数。
                                        -- 如果客户端画面内容更新出现不可接受的延迟，或者对服务端shell运行的程序造成了影响，说明这里消耗了过多CPU时间，则可以尝试适当减少循环次数。
            end
        end
    end

    local mon = opts.monitor and peripheral.find("monitor") or nil
    if opts.monitor and not mon then error("Fatal Error: No monitor detected!", 0) end

    local mon_w, mon_h = (mon or term.current()):getSize()
    local color_to_hex = {}
    for i = 0, 15 do color_to_hex[2 ^ i] = string.format("%x", i) end

    local curX, curY = 1, 1
    local curTextColor = colors.white or 1
    local curBgColor = colors.black or 32768
    local curCursorBlink = false
    local screen_buffer = {}

    local function reset_buffer()
        local bc = color_to_hex[curBgColor] or "f"
        for y = 1, mon_h do
            screen_buffer[y] = { text = string.rep(" ", mon_w), fg = string.rep("0", mon_w), bg = string.rep(bc, mon_w) }
        end
    end

    local function buffer_blit(text, fg, bg)
        local y = curY
        if y < 1 or y > mon_h then return end
        local row = screen_buffer[y]
        local x = curX
        local len = #text
        if x > mon_w or x + len - 1 < 1 then curX = x + len return end

        local start_idx = math.max(1, x)
        local end_idx = math.min(mon_w, x + len - 1)
        local t_offset = start_idx - x + 1
        local part_len = end_idx - start_idx + 1

        row.text = string.sub(row.text, 1, start_idx - 1) .. string.sub(text, t_offset, t_offset + part_len - 1) .. string.sub(row.text, end_idx + 1)
        row.fg = string.sub(row.fg, 1, start_idx - 1) .. string.sub(fg, t_offset, t_offset + part_len - 1) .. string.sub(row.fg, end_idx + 1)
        row.bg = string.sub(row.bg, 1, start_idx - 1) .. string.sub(bg, t_offset, t_offset + part_len - 1) .. string.sub(row.bg, end_idx + 1)
        curX = x + len
    end

    local function create_mirror(target_term)
        local proxy = {}
        for func_name, func in pairs(target_term) do
            if type(func) == "function" then
                proxy[func_name] = function(...)
                    local args = {...}
                    if func_name == "setCursorPos" then curX, curY = args[1], args[2]
                    elseif func_name == "setTextColor" or func_name == "setTextColour" then curTextColor = args[1]
                    elseif func_name == "setBackgroundColor" or func_name == "setBackgroundColour" then curBgColor = args[1]
                    elseif func_name == "setCursorBlink" then curCursorBlink = args[1]
                    elseif func_name == "write" then
                        local text = tostring(args[1])
                        buffer_blit(text, string.rep(color_to_hex[curTextColor] or "0", #text), string.rep(color_to_hex[curBgColor] or "f", #text))
                    elseif func_name == "blit" then buffer_blit(args[1], args[2], args[3])
                    elseif func_name == "clear" then reset_buffer()
                    elseif func_name == "clearLine" then
                        if curY >= 1 and curY <= mon_h then
                            screen_buffer[curY] = { text = string.rep(" ", mon_w), fg = string.rep("0", mon_w), bg = string.rep(color_to_hex[curBgColor] or "f", mon_w) }
                        end
                    elseif func_name == "scroll" then
                        local n = args[1] or 1
                        if n > 0 then
                            for i = 1, mon_h - n do screen_buffer[i] = screen_buffer[i + n] end
                            local bc = color_to_hex[curBgColor] or "f"
                            for i = mon_h - n + 1, mon_h do
                                screen_buffer[i] = { text = string.rep(" ", mon_w), fg = string.rep("0", mon_w), bg = string.rep(bc, mon_w) }
                            end
                        end
                    end
                    if connected_client_id then queueMessage(connected_client_id, {type= "FUNC",data = {func_name, ...}}, opts.protocol) end
                    return func(table.unpack(args))
                end
            end
        end
        return proxy
    end

    local function keyboard_listener()
        local timer_id = nil
        local waiting_id = nil
        while true do
            local event_data = { os.pullEventRaw() }
            if event_data[1] == "rednet_message" and event_data[3] ~= nil and type(event_data[3]) == "table" and event_data[4] == opts.protocol then
                if event_data[3].type == "REQ_INIT" and not waiting_id and not timer_id then
                    local decryptedId = tonumber(xxtea_cbc.decrypt(event_data[3].data, opts.password))
                    if decryptedId == event_data[2] then
                        -- 验证通过
                        if connected_client_id and connected_client_id ~= event_data[2] then
                            if opts.exclusive then
                                -- 独占模式：给老客户端发心跳探测
                                queueMessage(connected_client_id, {type = "PING", data = nil}, opts.protocol)
                                timer_id = os.startTimer(3)
                                waiting_id = event_data[2]
                                goto continue
                            else
                                -- 非独占模式：直接踢掉旧客户端
                                queueMessage(connected_client_id,{type = "DISCONNECT", data = "Another Telnet client has connected to the server."}, opts.protocol)
                            end
                        end
                        -- 赋予新客户端活跃身份
                        connected_client_id = event_data[2]
                        queueMessage(event_data[2], {
                            type ="INIT_TERM",
                            data = {
                                mon_w, mon_h, screen_buffer,curX, curY, curTextColor, curBgColor, curCursorBlink,
                            }
                        }, opts.protocol)
                    else
                        queueMessage(event_data[2], {type = "AUTH_FAIL", data = "Authentication failed"}, opts.protocol)
                    end
                elseif event_data[2] == connected_client_id and event_data[3].type == "ACK" then -- 老客户端应答了
                    queueMessage(waiting_id, {type = "AUTH_FAIL", data = "Server occupied (Exclusive mode)"}, opts.protocol)
                    waiting_id,timer_id = nil,nil
                elseif event_data[2] == connected_client_id and event_data[3].type == "INPUT" then
                    -- 接收到来自客户端透传传送过来的硬中断，注入本地系统事件环
                    if event_data[3].data[1] == "char" or string.sub(event_data[3].data[1], 1, 3) == "key" or event_data[3].data[1] == "paste" or event_data[3].data[1] == "terminate" then
                        os.queueEvent(table.unpack(event_data[3].data))
                    end
                end
            elseif event_data[1] == "timer" and waiting_id and timer_id and event_data[2] == timer_id then -- 老客户端超时没应答
                -- 虽然可能没有意义但还是踢一脚旧客户端
                queueMessage(connected_client_id,{type = "DISCONNECT", data = "Response timed out; forced offline."}, opts.protocol)
                -- 赋予新客户端活跃身份
                connected_client_id = waiting_id
                queueMessage(waiting_id, {
                    type ="INIT_TERM",
                    data = {
                        mon_w, mon_h, screen_buffer,curX, curY, curTextColor, curBgColor, curCursorBlink,
                    }
                }, opts.protocol)
                waiting_id,timer_id = nil,nil
            end
            ::continue::
        end
    end

    local function centerBanner(text, width)
        width = math.max(1, width)
        local total_padding = width - #text
        if total_padding <= 0 then return text end
        local left = math.floor(total_padding / 2)
        return string.rep("=", left) .. text .. string.rep("=", total_padding - left)
    end

    local function run_shell()
        local old_term = term.current()
        reset_buffer()
        local target_term = mon or old_term
        local mirrored_term = create_mirror(target_term)

        term.redirect(mirrored_term)
        term.clear()
        term.setCursorPos(1, 1)

        print(centerBanner(" Host Telnet Service Started ", target_term.getSize()))
        os.run({}, "rom/programs/shell.lua")
        print(centerBanner(" Host Telnet Service Stopped ", target_term.getSize()))
        term.redirect(old_term)
    end

    -- 将原来的 parallel.waitForAny 包装在 pcall 中, 防止terminate直接中断, 留出机会通知客户端下线
    local ok, err = pcall(function()
        parallel.waitForAny(run_shell, keyboard_listener, sender_worker)
    end)

    if not ok then printError("\nServer crashed: " .. tostring(err)) end
    
    -- 给客户端发送下线通知
    if connected_client_id then
        rednet.send(connected_client_id, {type = "DISCONNECT", data = "Server offline"}, opts.protocol)
    end

-- ========================================================
-- 客户端模式 (Client Mode)
-- ========================================================
else
    if not opts.host then error("host=<server_id> parameter is required", 0) end

    local function safe_call(func, ...)
        local ok, err = pcall(func, ...)
        if not ok then
            local file = fs.open("Telnet_debug.txt", "a")
            if file then file.writeLine("Error: " .. tostring(err)) file.close() end
        end
        return ok, err
    end

    local pw, ph = term.getSize()
    local virtual_screen
    local screen_w, screen_h = pw, ph
    local offsetX, offsetY = 0, 0

    local function update_camera()
        if not virtual_screen then return end
        local cx, cy = virtual_screen.getCursorPos()
        local changed = false
        local padX, padY = 3, 2

        if cx - offsetX <= padX then offsetX = math.max(0, cx - padX - 1) changed = true
        elseif cx - offsetX > pw - padX then offsetX = math.max(0, math.min(screen_w - pw, cx - pw + padX)) changed = true end

        if cy - offsetY <= padY then offsetY = math.max(0, cy - padY - 1) changed = true
        elseif cy - offsetY > ph - padY then offsetY = math.max(0, math.min(screen_h - ph, cy - ph + padY)) changed = true end

        if changed and virtual_screen.reposition then virtual_screen.reposition(1 - offsetX, 1 - offsetY) end
    end

    local function event_handler()
        local is_dragging = false
        local last_mx, last_my = 0, 0

        while true do
            local event_data = { os.pullEventRaw() }

            if event_data[1] == "paste" or event_data[1] == "char" or event_data[1] == "key" or event_data[1] == "key_up" or event_data[1] == "terminate" then
                rednet.send(opts.host, {type = "INPUT", data = event_data}, opts.protocol)
            elseif event_data[1] == "mouse_click" then
                is_dragging = true
                last_mx, last_my = event_data[3], event_data[4]
            elseif event_data[1] == "mouse_drag" and is_dragging then
                local mx, my = event_data[3], event_data[4]
                if virtual_screen and virtual_screen.reposition then
                    offsetX = math.max(0, math.min(screen_w - pw, offsetX - (mx - last_mx)))
                    offsetY = math.max(0, math.min(screen_h - ph, offsetY - (my - last_my)))
                    virtual_screen.reposition(1 - offsetX, 1 - offsetY)
                end
                last_mx, last_my = mx, my
            elseif event_data[1] == "mouse_up" then
                is_dragging = false
            elseif event_data[1] == "rednet_message" then
                -- 处理网络消息
                if event_data[2] == opts.host and event_data[3] ~= nil and type(event_data[3]) == "table" and event_data[4] == opts.protocol then
                    if event_data[3].type == "FUNC" then
                        local func_name = event_data[3].data[1]
                        if virtual_screen and virtual_screen[func_name] then
                            safe_call(function()
                                virtual_screen[func_name](table.unpack(event_data[3].data, 2))
                                update_camera()
                            end)
                        end
                    elseif event_data[3].type == "DISCONNECT" then
                        term.clear()
                        term.setCursorPos(1, 1)
                        print("Kicked: " ..event_data[3].data)
                        error("Disconnected By Server", 0)
                    elseif event_data[3].type == "PING" then
                        rednet.send(opts.host, {type = "ACK", data = nil}, opts.protocol)
                    end
                end
            end
        end
    end

    term.clear()
    term.setCursorPos(1, 1)
    print("Connecting to host (Encrypted handshake)...")
    
    local function do_handshake()
        while true do
            -- 客户端计算针对本地物理编号的密码密文
            local encryptedId = xxtea_cbc.encrypt(tostring(os.getComputerID()), opts.password)
            rednet.send(opts.host, {type = "REQ_INIT", data = encryptedId}, opts.protocol)
            
            local senderId, msg = rednet.receive(opts.protocol, 2)

            if senderId == opts.host and msg ~= nil and type(msg) == "table" then
                if msg.type == "INIT_TERM" then
                    print("Connected successfully!")
                    local mon_w_max, mon_h_max = msg.data[1], msg.data[2]
                    local buf = msg.data[3]

                    local ok, result = pcall(window.create, term.current(), 1, 1, mon_w_max, mon_h_max)
                    if not ok then error("Failed to create window: " .. tostring(result)) end

                    virtual_screen = result
                    screen_w, screen_h = mon_w_max, mon_h_max
                    offsetX, offsetY = 0, 0
                    safe_call(virtual_screen.clear)

                    for y = 1, mon_h_max do
                        if buf[y] then
                            safe_call(virtual_screen.setCursorPos, 1, y)
                            safe_call(virtual_screen.blit, buf[y].text, buf[y].fg, buf[y].bg)
                        end
                    end

                    safe_call(virtual_screen.setTextColor, msg.data[6])
                    safe_call(virtual_screen.setBackgroundColor, msg.data[7])
                    safe_call(virtual_screen.setCursorPos, msg.data[4], msg.data[5])
                    safe_call(virtual_screen.setCursorBlink, msg.data[8])
                    update_camera()
                    break
                elseif msg.type == "AUTH_FAIL" then
                    error("Connection Refused: " .. tostring(msg.data or "Unknow error."), 0)
                end
            else
                print("Waiting for server response...")
            end
        end
    end

    do_handshake()
    event_handler()

    term.clear()
    term.setCursorPos(1, 1)
    print("Disconnected from remote host.")
end
