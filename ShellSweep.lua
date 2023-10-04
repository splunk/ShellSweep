-- Entropy thresholds and operations for each file extension using a Lua table
-- Each file extension maps to a nested Lua table with 'operation' and 'value' fields.
-- Adjust the values based on your requirements.

-- ASCII art
local asciiArt = [[
    ██████  ██░ ██ ▓█████  ██▓     ██▓      ██████  █     █░▓█████ ▓█████  ██▓███  
    ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    ▒██    ▒ ▓█░ █ ░█░▓█   ▀ ▓█   ▀ ▓██░  ██▒
    ░ ▓██▄   ▒██▀▀██░▒███   ▒██░    ▒██░    ░ ▓██▄   ▒█░ █ ░█ ▒███   ▒███   ▓██░ ██▓▒
      ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░      ▒   ██▒░█░ █ ░█ ▒▓█  ▄ ▒▓█  ▄ ▒██▄█▓▒ ▒
    ▒██████▒▒░▓█▒░██▓░▒████▒░██████▒░██████▒▒██████▒▒░░██▒██▓ ░▒████▒░▒████▒▒██▒ ░  ░
    ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░ ▓░▒ ▒  ░░ ▒░ ░░░ ▒░ ░▒▓▒░ ░  ░
    ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░░ ░▒  ░ ░  ▒ ░ ░   ░ ░  ░ ░ ░  ░░▒ ░     
    ░  ░  ░   ░  ░░ ░   ░     ░ ░     ░ ░   ░  ░  ░    ░   ░     ░      ░   ░░       
          ░   ░  ░  ░   ░  ░    ░  ░    ░  ░      ░      ░       ░  ░   ░  ░         
                                                                                     
]]

print(asciiArt)

local fileExtensions = {
    ['.asp'] = {
        { operation = 'lt', value = 0.805376867704514 },
        { operation = 'gt', value = 5.51268104400858 }
    },
    ['.ashx'] = {
        { operation = 'gt', value = 3.75840459657413 }
    },
    ['.asax'] = {
        { operation = 'gt', value = 3.7288741494524 }
    },
    ['.jspx'] = {
        { operation = 'gt', value = 4.87651397975203 }
    },
    ['.html'] = {
        { operation = 'gt', value = 4.8738392644771 }
    },
    ['.aspx'] = {
        { operation = 'lt', value = 0.805376867704514 },
        { operation = 'gt', value = 4.15186444439319 }
    },
    ['.php'] = {
        { operation = 'gt', value = 4.23015141285636 }
    },
    ['.jsp'] = {
        { operation = 'gt', value = 4.40958415652662 }
    },
    ['.js'] = {
        { operation = 'gt', value = 4.25868439013462 }
    }
}

-- Calculate the entropy of a given string
local function getEntropy(str)
    local length = #str
    local symbolFrequency = {}
    for i = 1, length do
        local symbol = str:sub(i, i)
        if symbolFrequency[symbol] then
            symbolFrequency[symbol] = symbolFrequency[symbol] + 1
        else
            symbolFrequency[symbol] = 1
        end
    end

    local entropy = 0
    for _, frequency in pairs(symbolFrequency) do
        local freq = frequency / length
        entropy = entropy - (freq * math.log(freq, 2))
    end

    return entropy
end

-- Directories to scan
local directoryPaths = {
    '/opt/webshells'
}

-- Directories to exclude
local excludePaths = {
    '/path/to/exclude1',
    '/path/to/exclude2',
    '/path/to/exclude3'
}

-- File hashes to ignore
local ignoreHashes = {
    'FE3F0B4326FF9754CB8B61AA3CEFB465A5308658064EE51C41B0A8B50027728D',
    'B6675117A7B174C3AA2510DDDEFF4221BA6E31005333F47C7239ED5D055BBBDD',
    '54EFA324203B762A03033879057F8A9DB0F7B45C83C8E1A40529CAFF1EB18004',
    '71FE41C6CCB0023576483A1C89929255480A4F5F0F07CFF9A8D2030ECF70E7AE'
}

-- Read the hashes from the file into an array (if needed)
local ignoreHashesFilePath = 'path_to_your_file.txt'
local file = io.open(ignoreHashesFilePath, 'r')
if file then
    ignoreHashes = {}
    for line in file:lines() do
        table.insert(ignoreHashes, line)
    end
    file:close()
end

local webshellFound = false

-- Walk through each directory and flag files with high/low entropy
for _, directoryPath in ipairs(directoryPaths) do
    for file in io.popen('find "'..directoryPath..'" -type f'):lines() do
        local exclude = false
        for _, excludePath in ipairs(excludePaths) do
            if file:find('^'..excludePath) then
                exclude = true
                break
            end
        end

        local extension = file:match('^.+(%..+)$')
        if extension and fileExtensions[extension] and not exclude then
            local f = io.open(file, 'r')
            if f then
                local content = f:read('*all')
                f:close()

                local entropy = getEntropy(content)
                local hash = io.popen('sha256sum "'..file..'"'):read():match('^([%w%d]+)')

                for _, condition in ipairs(fileExtensions[extension]) do
                    local operation = condition.operation
                    local value = condition.value
                    local metCondition = false

                    if operation == 'gt' then
                        if entropy > value then
                            metCondition = true
                        end
                    elseif operation == 'lt' then
                        if entropy < value then
                            metCondition = true
                        end
                    elseif operation == 'eq' then
                        if entropy == value then
                            metCondition = true
                        end
                    end

                    if metCondition and not ignoreHashes[hash] then
                        print('Possible webshell found: '..file..', Entropy: '..entropy..', Hash: '..hash)
                        webshellFound = true
                    end
                end
            end
        end
    end
end

-- If no webshells were found
if not webshellFound then
    print('No evil identified today.')
end
