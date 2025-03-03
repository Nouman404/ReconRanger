import os
import sys

# Get the directory where ReconRanger is located
script_dir = os.path.dirname(os.path.abspath(__file__))
# Add this directory to sys.path so that import are found
sys.path.insert(0, script_dir)

from functions import get_current_user_and_group

reconranger = """

 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █  ██▀███   ▄▄▄       ███▄    █   ▄████ ▓█████  ██▀███  
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █ ▓██ ▒ ██▒▒████▄     ██ ▀█   █  ██▒ ▀█▒▓█   ▀ ▓██ ▒ ██▒
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒▓██ ░▄█ ▒▒██  ▀█▄  ▓██  ▀█ ██▒▒██░▄▄▄░▒███   ▓██ ░▄█ ▒
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒▒██▀▀█▄  ░██▄▄▄▄██ ▓██▒  ▐▌██▒░▓█  ██▓▒▓█  ▄ ▒██▀▀█▄  
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░░██▓ ▒██▒ ▓█   ▓██▒▒██░   ▓██░░▒▓███▀▒░▒████▒░██▓ ▒██▒
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▒░   ▒ ▒  ░▒   ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░  ░▒ ░ ▒░  ▒   ▒▒ ░░ ░░   ░ ▒░  ░   ░  ░ ░  ░  ░▒ ░ ▒░
  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░   ░░   ░   ░   ▒      ░   ░ ░ ░ ░   ░    ░     ░░   ░ 
   ░        ░  ░░ ░          ░ ░           ░    ░           ░  ░         ░       ░    ░  ░   ░     
                ░                                                                                  

                                        Made with <3 by BatBato
"""

print(reconranger)

user_name, group_name = get_current_user_and_group()
target_script_path = "create_template.py"
list_flags = ""
for flag in sys.argv[1:]:
    if "-sT" in flag or "-sU" in flag:
        list_flags += flag.split("=")[0] + "=\"" + flag.split("=")[1] + "\""
    else:
        if " " in flag:
            list_flags += "'" + flag + "' "
        else:
            list_flags += flag + " "
command = f'sudo python3 "{script_dir}/{target_script_path}" -U {user_name}:{group_name} {list_flags}'
exit_code = os.system(command)

if exit_code != 0:
    print(f"Script execution failed with exit code {exit_code}")
    exit()
