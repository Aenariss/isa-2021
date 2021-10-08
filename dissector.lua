-- https://mika-s.github.io/wireshark/lua/dissector/2018/12/30/creating-port-independent-wireshark-dissectors-in-lua.html

isa_protocol = Proto("ISA", "ISA Project Protocol")

-- Header fields
status = ProtoField.string("isa_protocol.status", "Response status")
command = ProtoField.string("isa_protocol.command", "Operation code")
message = ProtoField.string("isa_protocol.error_message", "Message")
body = ProtoField.string("isa_protocol.body", "Body")
type = ProtoField.string("isa_protocol.type", "Type")
msg_length = ProtoField.string("isa_protocol.msg_length", "Length")
username = ProtoField.string("isa_protocol.username", "Username")
password = ProtoField.string("isa_protocol.password", "Obfuscated password")
user_id = ProtoField.string("isa_protocol.user_id", "User Token")
recipient = ProtoField.string("isa_protocol.recipient", "Message recipient")
subject = ProtoField.string("isa_protocol.subject", "Message subject")
body_message = ProtoField.string("isa_protocol.body", "Message body")
message_number = ProtoField.string("isa_protocol.body", "Message ID")

isa_protocol.fields = { status, command, error_message, body, type, msg_length, username, password, user_id, recipient, subject, body_message, message_number }

local function get_status(msg)
    -- wireshark ma integrovanou lua konzoli: Tools -> Lua
    -- V te hledat vypisy a errory a prijit na to, proc todle nejde
    local message_name = "unknown"
    local find = tostring(msg)
    local find = Struct.fromhex(find)

    if string.find(find, "ok") then message_name = "ok"
    elseif string.find(find, "err") then message_name = "error" 
    elseif string.find(find, "register") then message_name = "reg"
    elseif string.find(find, "login") then message_name = "login"
    elseif string.find(find, "fetch") then message_name = "fetch"
    elseif string.find(find, "logout") then message_name = "logout"
    elseif string.find(find, "send") then message_name = "send"
    elseif string.find(find, "list") then message_name = "list"
    end

    return message_name
end

local function get_quote_index(buffer, n)
    
    local buff_len = buffer:len()
    local first_quote = -1
    local second_quote = -1
    local counter = 0
    local my_string
    local limit
    if n > 1 then 
        limit = n + n-1 
    else 
        limit = n
    end
    local i = 1
    local k = 1
    local flag = 0
    local remains_to_read = buff_len

    while k <= buff_len do
        if remains_to_read >= 36 and flag == 0 then
            my_string = tostring(buffer(0, 36))
            my_string = Struct.fromhex(my_string)
            flag = 1
        elseif flag == 0 then
            my_string = tostring(buffer)
            my_string = Struct.fromhex(my_string)
            flag = 1
        end

        -- 
        mod = k % 36
        if mod == 0 then

            remains_to_read = remains_to_read - 36
            if remains_to_read >= 36 then
                local tmp_buf = buffer(k, 36)
                my_string = tostring(tmp_buf)
                my_string = Struct.fromhex(my_string)
            elseif remains_to_read > 0 then
                local tmp_buf = buffer(k, buff_len-k)
                my_string = tostring(tmp_buf)
                my_string = Struct.fromhex(my_string)
            end
        end

        local char = my_string:sub(i,i)
        if (i == 36) then i = 0 end
        if char == "\"" then 
            counter = counter + 1
            if first_quote ~= -1 then
                second_quote = k
                break
            end
            if counter == limit then
                first_quote = k
            end
        end
        i = i + 1
        k = k + 1
    end
    return first_quote, second_quote
end

local function get_number(buffer)
    local buff_len = buffer:len()
    local my_string = tostring(buffer(0, buff_len))
    --local my_string = Struct.fromhex(my_string)
    local flag = 0
    local n_begin = -1
    local n_end = -1
    for i=1,buff_len do
        local char = my_string:sub(i,i)
        local byte_compare = string.byte(char)
        if (byte_compare >= 48 and byte_compare <= 57) then
            if (n_begin ~= -1) then n_end = i end
            if (flag == 0) then n_begin = i flag = 1 end
        end
    end
    if n_end == -1 then n_end = 1 end
    return n_begin, n_end

end

local function heuristic_checker(buffer, pinfo, tree)
    -- guard for length
    length = buffer:len()
    if length < 5 then return false end -- takhle neberu random SYN/ACK pakety, ktere nemaji telo

    -- ~= znamena !=
    local potential_status = buffer(0,10)

    local status = get_status(potential_status)
    if status ~= "unknown"
    then
        isa_protocol.dissector(buffer, pinfo, tree)
        return true
    else return false end
end

function add_quote_to_tree(subtree, buffer, max_length, n, field)
    local first_quote, second_quote = get_quote_index(buffer(0,max_length-1), n)
    subtree:add(field, buffer(first_quote, second_quote-first_quote-1))
    return first_quote, second_quote
end

function add_number_to_tree(subtree, buffer, max_length, field, prev_quote)
    local begin_n, end_n = get_number(buffer(prev_quote, max_length-prev_quote-1))
    subtree:add(field, buffer(prev_quote+begin_n, end_n-begin_n))
    print(prev_quote+begin_n, end_n-begin_n)
end

function isa_protocol.dissector(buffer, pinfo, tree)
    local max_length = buffer:len()
    if max_length == 0 then return end

    pinfo.cols.protocol = isa_protocol.name

    local subtree = tree:add(isa_protocol, buffer(), "ISA Protocol Payload")

    msg_type = get_status(buffer(0,10))

    if (msg_type == "ok") then
        subtree:add(type):append_text("Response")
        subtree:add(status, buffer(1,3))
        subtree:add(body, buffer(4, max_length-5))

    elseif (msg_type == "error") then
        subtree:add(type):append_text("Response")
        subtree:add(status, buffer(1,4))
        subtree:add(body, buffer(5, max_length-6))
    else
        subtree:add(type):append_text("Request")
        if (msg_type == "reg") then
            subtree:add(command, buffer(1,8))
            add_quote_to_tree(subtree, buffer, max_length, 1, username)
            add_quote_to_tree(subtree, buffer, max_length, 2, password)

        elseif (msg_type == "login") then
            subtree:add(command, buffer(1,5))
            add_quote_to_tree(subtree, buffer, max_length, 1, username)
            add_quote_to_tree(subtree, buffer, max_length, 2, password)

        elseif (msg_type == "fetch")  then
            subtree:add(command, buffer(1,5))
            local first_quote, second_quote = add_quote_to_tree(subtree, buffer, max_length, 1, user_id)
            add_number_to_tree(subtree, buffer, max_length, message_number, second_quote)

        elseif (msg_type == "logout") then
            subtree:add(command, buffer(1,4))
            add_quote_to_tree(subtree, buffer, max_length, 1, user_id)

        elseif (msg_type == "send") then
            subtree:add(command, buffer(1,4))
            add_quote_to_tree(subtree, buffer, max_length, 1, user_id)
            add_quote_to_tree(subtree, buffer, max_length, 2, recipient)
            add_quote_to_tree(subtree, buffer, max_length, 3, subject)
            add_quote_to_tree(subtree, buffer, max_length, 4, body_message)

        elseif (msg_type == "list") then
            subtree:add(command, buffer(1,4))
            add_quote_to_tree(subtree, buffer, max_length, 1, body_message)
        end

    end
    subtree:add(msg_length):append_text(max_length)

end

isa_protocol:register_heuristic("tcp", heuristic_checker)
