from functions import get_current_user_and_group
import os
import sys

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
        list_flags += flag + " "

command = f'sudo python3 {target_script_path} -U {user_name}:{group_name} {list_flags}'
exit_code = os.system(command)

if exit_code != 0:
    print(f"Script execution failed with exit code {exit_code}")
    exit()
