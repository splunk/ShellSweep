import os
import hashlib
import math
from collections import Counter
import datetime


print("""\
   _________         _________
  /         \       /         \   Normand
 /  /~~~~~\  \     /  /~~~~~\  \  Veilleux
 |  |     |  |     |  |     |  |
 |  |     |  |     |  |     |  |
 |  |     |  |     |  |     |  |         /
 |  |     |  |     |  |     |  |       //
(o  o)    \  \_____/  /     \  \_____/ /
 \__/      \         /       \        /
  |         ~~~~~~~~~         ~~~~~~~~
  ^

ShellSwee.py
""")


# file extensions and entropy thresholds
file_extensions = {
    '.asp': [('lt', 0.805376867704514), ('gt', 5.51268104400858)],
    '.ashx': [('gt', 3.75840459657413)],
    '.asax': [('gt', 3.7288741494524)],
    '.jspx': [('gt', 4.87651397975203)],
    '.html': [('gt', 4.8738392644771)],
    '.aspx': [('lt', 0.805376867704514), ('gt', 4.15186444439319)],
    '.php': [('gt', 4.23015141285636)],
    '.jsp': [('gt', 4.40958415652662)],
    '.js': [('gt', 4.25868439013462)]
}

# Calculate the entropy of a given string
def get_entropy(input_string):
    probability = [float(x) / len(input_string) for x in Counter(input_string).values()]
    return - sum(p * math.log(p, 2) for p in probability)

# Directories to scan
directory_paths =  ['/opt/webshells']

# Directories to exclude
exclude_paths = ['exclude_path1', 'exclude_path2', 'exclude_path3']

# File hashes to ignore.
ignore_hashes = ['hash1', 'hash2', 'hash3']

# Check if ignore_hashes file exists, if yes then read the hashes from the file into an array
if os.path.isfile('path_to_your_file.txt'):
    with open('path_to_your_file.txt', 'r') as f:
        file_hashes = f.read().splitlines()

    # If the file_hashes list is not empty, use it instead of ignore_hashes
    if file_hashes:
        ignore_hashes = file_hashes

webshell_found = False

# Walk through each directory and flag files with high/low entropy
for directory_path in directory_paths:
    for root, dirs, files in os.walk(directory_path):
        # Exclude specified paths
        if any(root.startswith(path) for path in exclude_paths):
            continue
        for file in files:
            full_path = os.path.join(root, file)
            if any(file.endswith(ext) for ext in file_extensions.keys()):
                # Skip if file is empty
                if os.stat(full_path).st_size == 0:
                    continue
                with open(full_path, 'r', errors='ignore') as f:
                    content = f.read()
                    entropy = get_entropy(content)
                    hasher = hashlib.sha256()
                    hasher.update(content.encode())
                    file_hash = hasher.hexdigest()

                    # get last modification time
                    last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(full_path))

                    for extension, conditions in file_extensions.items():
                        if file.endswith(extension):
                            for operation, value in conditions:
                                met_condition = False
                                if operation == 'gt' and entropy > value:
                                    met_condition = True
                                elif operation == 'lt' and entropy < value:
                                    met_condition = True
                                if met_condition and file_hash not in ignore_hashes:
                                    print(f"Possible webshell found: {full_path}, Last Modified: {last_modified}, Entropy: {entropy}, Hash: {file_hash}")
                                    webshell_found = True


# If no webshells were found -->
if not webshell_found:
    print("No evil identified today.")
