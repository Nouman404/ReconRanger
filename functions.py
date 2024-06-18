import re
import socket
import os
import subprocess
import pwd
import grp
import xml.etree.ElementTree as ET

# Set UID to original user so folders and files are accessible
def drop_privileges(uid_name='SUDO_UID', gid_name='SUDO_GID'):
    if uid_name in os.environ and gid_name in os.environ:
        new_uid = int(os.environ[uid_name])
        new_gid = int(os.environ[gid_name])

        os.setgroups([])
        os.setgid(new_gid)
        os.setuid(new_uid)
    else:
        print("Could not find UID and GID in environment")

def get_current_user_and_group():
    user_id = os.getuid()
    group_id = os.getgid()
    user_name = pwd.getpwuid(user_id).pw_name
    group_name = grp.getgrgid(group_id).gr_name
    return user_name, group_name

# Change ownership of a file/directory
def change_owner(path, user, group):
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, uid, gid)
        print(f"Changed ownership of {path} to {user}:{group}")
    except KeyError as e:
        print(f"Error: {e}")

# Check if the format looks like an IP or not (domain)
def isIP(value):
    return re.search("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", value)

# Run a classic TCP nmap scan
def launch_tcp_nmap(target, flags="", folder="Nmap_Scans"):
    # Ensure the output directory exists
    os.makedirs(folder, exist_ok=True)

    # Launch basic nmap scan
    if flags == "":
        arguments='-vv -Pn --min-rate 1000 -p- -sV -sC '
    else:
        arguments=flags
    if "-sC" not in arguments and "-sV" not in arguments:
        arguments += " -sC -sV"
    if "-oA" not in arguments or "-oX" not in arguments:
        # Add output
        arguments += " -oA " + folder + "/nmap_tcp_" + target

    if not os.path.exists(folder + "/nmap_tcp_" + target+".nmap"):
        command = ["nmap"]+ arguments.split() + [target]
        # Run the command and capture the text output
        result = subprocess.run(command, capture_output=True, text=True)

        # Check if the command was successful
        if result.returncode == 0:
            return result.stdout
        else:
            # Print the error
            print(f'Error: {result.stderr}')
            return "\n\n"
    else:
        return open(folder + "/nmap_tcp_" + target+".nmap").read()
        
# Run a classic UDP nmap scan
def launch_udp_nmap(target, flags="", folder="Nmap_Scans"):
    # Ensure the output directory exists
    os.makedirs(folder, exist_ok=True)
    # Launch basic nmap scan
    if flags == "":
        arguments='-vv -Pn --min-rate 1000 -sU --top-ports 1000 -sV -sC '
    else:
        arguments=flags

    if "-oA" not in arguments or "-oG" not in arguments:
        # Add output
        arguments += " -oA " + folder + "/nmap_udp_" + target
    
    command = ["sudo", "nmap"]+ arguments.split() + [target]
    
    if not os.path.exists(folder + "/nmap_udp_" + target+".nmap"):
        # Run the command and capture the text output
        result = subprocess.run(command, capture_output=True, text=True)

        # Check if the command was successful
        if result.returncode == 0:
            return result.stdout
        else:
            # Print the error
            print(f'Error: {result.stderr}')
    else:
        return open(folder + "/nmap_udp_" + target+".nmap").read()

# Run testssl.sh on the specified target using docker
def run_testssl_docker(target, output_dir="Test_SSL", port="443"):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    uid = os.getuid()
    gid = os.getgid()
    if port != "443":
        target += ":"+port

    command = [
        'sudo', 'docker', 'run', '--rm',
        '-v', f"{os.path.abspath(output_dir)}:/ssl",
        '--user', f"{uid}:{gid}",
        'drwetter/testssl.sh','--color', '0', '--warnings', 'off' ,'--overwrite', '--logfile', f"/ssl/testssl_{target}.log", target
    ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    test_vuln = 0
    rating = 0
    content_to_save_vuln = ""
    content_to_save_rating = ""

    if result.returncode == 0:
        file = open(f'{output_dir}/testssl_{target}.log').readlines()
        for line in file:
            if 'Could not determine the protocol, only simulating generic clients.' in line:
                continue
            if "Testing vulnerabilities" in line:
                content_to_save_vuln += line
                test_vuln = 1
            if "Running client simulations" in line:
                test_vuln = 0
            if test_vuln == 1 and "Testing vulnerabilities" not in line:
                if "(OK)" not in line and len(line) > 1 and line[1].isalpha():
                    content_to_save_vuln += "[-] " + line
                else:
                    if len(line) > 1 and line[1].isalpha():
                        content_to_save_vuln += "[+] " + line
                    else:
                        content_to_save_vuln += line
            if "Rating (experimental)" in line:
                content_to_save_rating += line
                rating = 1
            if rating == 1 and "Rating" not in line:
                content_to_save_rating += line
            if "<--" in line:
                rating = 0
    else:
        if "non-empty" in result.stderr and "exists" in result.stderr:
            print(f'Testssl.sh error. Please remove the file {os.path.abspath(output_dir)}/testssl_{target}.log')
        else:
            print(f'Testssl.sh native error: {result.stderr}')
    
    return content_to_save_vuln.encode().replace(b"\n\n\n", b"\n").decode(), content_to_save_rating.encode().replace(b"\n\n\n", b"\n").decode()

# Run testssl.sh on the specified target and download the code if not in the local folder
def run_testssl_native(target, output_dir="Test_SSL", port="443"):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    if not os.path.exists("./testssl.sh"):

        install_command = [
            "git", "clone", "--depth", "1",
            "https://github.com/drwetter/testssl.sh.git"
        ]
        subprocess.run(install_command)
    
    if port != "443":
        target += ":"+port

    command = ['./testssl.sh/testssl.sh','--color', '0', '--overwrite', '--warnings', 'off', '--logfile', f'{output_dir}/testssl_{target}.log', target]
    result = subprocess.run(command, capture_output=True, text=True)
    test_vuln = 0
    rating = 0
    content_to_save_vuln = ""
    content_to_save_rating = ""

    if result.returncode >= 0 and os.path.exists(f'{output_dir}/testssl_{target}.log'):
        file = open(f'{output_dir}/testssl_{target}.log').readlines()
        for line in file:
            if 'Could not determine the protocol, only simulating generic clients.' in line:
                continue
            if "Testing vulnerabilities" in line:
                content_to_save_vuln += line
                test_vuln = 1
            if "Running client simulations" in line:
                test_vuln = 0
            if test_vuln == 1 and "Testing vulnerabilities" not in line:
                if "(OK)" not in line and len(line) > 1 and line[1].isalpha():
                    content_to_save_vuln += "[-] " + line
                else:
                    if len(line) > 1 and line[1].isalpha():
                        content_to_save_vuln += "[+] " + line
                    else:
                        content_to_save_vuln += line
            if "Rating (experimental)" in line:
                content_to_save_rating += line
                rating = 1
            if rating == 1 and "Rating" not in line:
                content_to_save_rating += line
            if "<--" in line:
                rating = 0
    else:
        if "non-empty" in result.stderr and "exists" in result.stderr:
            print(f'Testssl.sh error. Please remove the file {os.path.abspath(output_dir)}/testssl_{target}.log')
        else:
            print(f'Testssl.sh native error: {result.stderr}')
    
    return content_to_save_vuln.encode().replace(b"\n\n\n", b"\n").decode(), content_to_save_rating.encode().replace(b"\n\n\n", b"\n").decode()

# Get possible vulnerabilties from HTTP or HTTPS headers
def run_shcheck(target, type="https", output_dir="Headers_Check", port=""):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    if port in ["", "80", "443"]:
        command = ["shcheck.py","--colours=none" , type+"://"+target, "-d"]
    else:
        command = ["shcheck.py","--colours=none" , type+"://"+target+":"+port, "-d"]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        #print(result.stdout)
        with open(output_dir+"/header_"+target, "w+") as file:
            file.write(result.stdout)
            if len(file.readlines()) == 0:
                return ""
        return result.stdout
    else:
        print(f'Error: {result.stderr}')
        return None

# Get list of web port and protocol
def extract_web_ports_from_gnmap(gnmap_file):
    web_ports = []

    with open(gnmap_file, 'r') as file:
        for line in file:
            # Search for lines that contain open ports
            if "Ports:" in line:
                # Find all ports labeled as http or ssl|http
                matches = re.findall(r'\d+/open/tcp//(?:ssl\|)', line)
                for match in matches:
                    # Extract port number
                    have_ssl = ""
                    if "ssl" in match:
                        have_ssl = "https"
                    else:
                        have_ssl = "http"
                    port = match.split('/')[0]
                    web_ports.append({have_ssl:port})
    
    return web_ports

# Get list of web port (HTTP/HTTPS)
def extract_open_http_ports(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    web_ports = []

    # Find all 'port' tags
    for port in root.findall('.//port'):
        protocol = port.get('protocol')
        portid = port.get('portid')
        
        # Check if the protocol is 'tcp'
        if protocol == 'tcp':
            # Check if the state is 'open'
            state = port.find('state').get('state')
            if state == 'open':
                # Check if the service is 'http'
                service = port.find('service')
                if service.get("tunnel") == "ssl":
                    web_ports.append({"https":portid})
                else:
                    web_ports.append({"http":portid})
    return web_ports


# Print the help menu
def help_menu():
    help_message = """
    Usage: python ReconRanger.py [OPTIONS]

    By default the script will run basic scans (-D). Full scan TCP, top 1000 UDP port, SSL check and header check

    Options:
      -h, --help                Show this help message and exit
      -D, --default             Use default settings
      -p, --path                Path where to create the report (default: "./")
      -n, --name                Name of the project (default: "./test_project")
      -H, --host_file           Name of the host file (default: "./hosts.txt")

    Nmap Options:
      -s, --scan-dir            Folder name for the nmap output folder (default: "[PROJECT_FOLDER]/Nmap_Scans")
      -sU, --udp-flags          Specify your own nmap flags for UDP scan (default: "-vv -Pn --min-rate 1000 -sU --top-ports 1000 -sV -sC")
      -sT, --tcp-flags          Specify your own nmap flags for TCP scan (default: "-vv -Pn --min-rate 1000 -p- -sV -sC")
      -xU, --exclude-udp        Exclude UDP scan from the report (default: False)

    TestSSL Options:  
      -S, --ssl                 Folder name for the SSL check output folder (default: "[PROJECT_FOLDER]/Test_SSL")
      -St, --scan-type          User either "docker" or "native" to either run a docker container for the testssl or run it from binary.
    
    Header Check Options:
      -He, --header-folder     Folder name for the HTTP header check (default: "[PROJECT_FOLDER]/Headers_Check")


    Examples:
      python ReconRanger.py -D
      => Will run with all default options

      python ReconRanger.py -H my_host_file.txt -p ./ -sT="-p 10-1000"
      => Will use the hosts from my_host_file.txt, create the project in the current directory and scan the TCP ports from 10 to 1000
    """
    print(help_message)
    exit(0)
