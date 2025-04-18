import requests as r
import re
import socket
import os
import subprocess
import pwd
import grp
import sys
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie
from colorama import Fore, Back, Style, init
from halo import Halo



def get_current_user_and_group(uid_name='SUDO_UID', gid_name='SUDO_GID'):
    old_uid = int(os.environ[uid_name])
    old_gid = int(os.environ[gid_name])
    old_user = pwd.getpwuid(old_uid).pw_name
    old_group = grp.getgrgid(old_gid).gr_name
    return old_user, old_group

# Change ownership of a file/directory
def change_owner(path, user_group):
    try:
        command = ['sudo', "chown",  "-R", user_group  , path]
        subprocess.run(command)
    except KeyError as e:
        print(f"Error: {e}")

def signal_handler(sig, frame):
    spinner = Halo(text=f'Program aborted', spinner='dots')
    spinner.fail()
    sys.exit(0)

# Check if the format looks like an IP or not (domain)
def isIP(value):
    return re.search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", value)

# Run a classic TCP nmap scan
def launch_tcp_nmap(target, flags="", folder="Nmap_Scans"):
    nmap_folder = os.path.normpath(folder)
    # Ensure the output directory exists
    os.makedirs(nmap_folder, exist_ok=True)

    # Launch basic nmap scan
    if flags == "":
        arguments='-vv -Pn --min-rate 1000 -p- -sV -sC'
    else:
        arguments=flags

    if not os.path.exists(nmap_folder + "/nmap_tcp_" + target +".nmap") or not os.path.exists(nmap_folder + "/nmap_tcp_" + target +".xml"):
        command = ["nmap"]+ arguments.split(" ") 
        add_options = None
        add_path = None
        if "-sC" not in arguments or "-sV" not in arguments:
            arguments = arguments.replace("-sC", "").replace("-sV", "")
            add_options = "-sC -sV".split()
        if "-oA" not in arguments or "-oX" not in arguments:
            # Add output
            add_path = ["-oA"]
            add_path.extend([nmap_folder + "/nmap_tcp_" + target])
            
        if add_options is not None:
            command.extend(add_options)
        if add_path is not None:
            command.extend(add_path)
        
        command.extend([target])
        
        try:
            # Run the command and capture the text output
            result = subprocess.run(command, capture_output=True, text=True)
            return result.stdout    
        except subprocess.CalledProcessError as e:
            print(f"Error! Return Code: {e.returncode}")
            print(f'Error: {result.stderr}')
    else:
        try:
            ET.parse(nmap_folder + "/nmap_tcp_" + target +".xml")
            return open(nmap_folder + "/nmap_tcp_" + target +".nmap").read()
        except:
            os.remove(nmap_folder + "/nmap_tcp_" + target +".nmap")
            if os.path.exists(nmap_folder + "/nmap_tcp_" + target +".gnmap"):
                os.remove(nmap_folder + "/nmap_tcp_" + target +".gnmap")
            if os.path.exists(nmap_folder + "/nmap_tcp_" + target +".xml"):
                os.remove(nmap_folder + "/nmap_tcp_" + target +".xml")
            launch_tcp_nmap(target, flags, nmap_folder)

# Run a classic UDP nmap scan
def launch_udp_nmap(target, flags="", folder="Nmap_Scans"):
    nmap_folder = os.path.normpath(folder)
    # Ensure the output directory exists
    os.makedirs(folder, exist_ok=True)

    # Launch basic nmap scan
    if flags == "":
        arguments='-vv -Pn --min-rate 1000 -sU --top-ports 1000 -sV -sC'
    else:
        arguments=flags

    if not os.path.exists(folder + "/nmap_udp_" + target +".nmap") or not os.path.exists(folder + "/nmap_udp_" + target +".xml"):
        command = ["sudo", "nmap"]+ arguments.split(" ")
        add_path = None
        if "-oA" not in arguments or "-oX" not in arguments:
            # Add output
            add_path = ["-oA"]
            add_path.extend([nmap_folder + "/nmap_udp_" + target])
        if add_path is not None:
            command.extend(add_path)

        command.extend([target])        
        
        try:
            # Run the command and capture the text output
            result = subprocess.run(command, capture_output=True, text=True)
            return result.stdout    
        except subprocess.CalledProcessError as e:
            print(f"Error! Return Code: {e.returncode}")
            print(f'Error: {result.stderr}')
    else:
        try:
            ET.parse(folder + "/nmap_udp_" + target +".xml")
            return open(folder + "/nmap_udp_" + target +".nmap").read()
        except:
            os.remove(folder + "/nmap_udp_" + target +".nmap")
            if os.path.exists(folder + "/nmap_udp_" + target +".gnmap"):
                os.remove(folder + "/nmap_udp_" + target +".gnmap")
            if os.path.exists(folder + "/nmap_udp_" + target +".xml"):
                os.remove(folder + "/nmap_udp_" + target +".xml")
            launch_udp_nmap(target, flags, folder)
        
# Run testssl.sh on the specified target 
def run_testssl(target, project_path, output_dir="Test_SSL", port="443"):
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    if port != "443":
        target += ":"+port
    
    command = [project_path + '/testssl/testssl.sh','--color', '0', '--ip', 'one' ,'--overwrite', '--warnings', 'off', '--logfile', f'{output_dir}/testssl_{target}.log', target]

    result = subprocess.run(command, capture_output=True, text=True)
    test_vuln = 0
    rating = 0
    content_to_save_vuln = ""
    content_to_save_rating = ""
    is_positive = False
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
                    is_positive = False
                else:
                    if len(line) > 1 and line[1].isalpha():
                        is_positive = True
                    else:
                        if is_positive == False:
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
            print(f'Testssl.sh error: {result.stderr}')
    
    return content_to_save_vuln.encode().replace(b"\n\n\n", b"\n").decode(), content_to_save_rating.encode().replace(b"\n\n\n", b"\n").decode()

sec_headers = {
    'X-XSS-Protection': 'deprecated',
    'X-Frame-Options': 'warning',
    'Content-Type': 'warning',
    'Strict-Transport-Security': 'error',
    'Content-Security-Policy': 'warning',
    'X-Permitted-Cross-Domain-Policies': 'deprecated',
    'Referrer-Policy': 'warning',
}

information_headers = {
    'X-Powered-By',
    'Server',
    'X-AspNet-Version',
    'X-AspNetMvc-Version'
}

cache_headers = {
    'Cache-Control',
    'Pragma',
    'Last-Modified'
    'Expires',
    'ETag'
}

# My own header check
def run_my_header_check(target, my_type="https", output_dir="Headers_Check", port=""):
    headers = {}
    missing_sec_headers = []
    deprecated_headers = []
    missing_info_headers = []
    missing_cache_headers = []

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)
    try:
        if port in ["", "80", "443"]:
            res = r.get(my_type+"://"+target)
        else:
            res = r.get(my_type+"://"+target +":"+port)
    except:
        return ""
    if port == "":
        port = "80" if my_type == "http" else 443
    headers = res.headers

    # Check if Headers from website are correctelly set up
    for sec_key in sec_headers.keys():
        if sec_key not in headers.keys():
            if sec_headers[sec_key] != "deprecated":
                missing_sec_headers.append(sec_key)
        else:
            if sec_headers[sec_key] == "deprecated":
                deprecated_headers.append(sec_key)

    for info_key in information_headers:
        if info_key in headers.keys():
            missing_info_headers.append(info_key+ f" ({headers[info_key]})")

    for cache_key in cache_headers:
        if cache_key not in headers.keys():
            missing_cache_headers.append(cache_key)
    
    init(autoreset=True)

    # Prepare the display of the result
    final_printed_result = f"-= Missing Headers =-\nTarget: {target}:{port}\n"
    final_saved_result =  Style.BRIGHT + f"-= Missing Headers =-\nTarget: {target}:{port}\n"
    
    check = 0
    if len(missing_sec_headers) != 0:
        final_printed_result += "\nSecurity Headers Missing:\n"
        final_saved_result += Style.RESET_ALL + Style.BRIGHT + "\nSecurity Headers Missing:\n"
        for value in missing_sec_headers:
            final_printed_result += "[-] " +value + "\n"
            final_saved_result += Fore.YELLOW + "[-] " +value + "\n"
        check += 1

    if len(deprecated_headers) != 0:
        final_printed_result += "\nSecurity Headers Deprecated (not to use):\n"
        final_saved_result += Style.RESET_ALL + Style.BRIGHT + "\nSecurity Headers Deprecated (not to use):\n"
        for value in deprecated_headers:
            final_printed_result += "[-] " +value + "\n"
            final_saved_result += Fore.YELLOW + "[-] " +value + "\n"
        check += 1

    if len(missing_info_headers) != 0:
        final_printed_result += "\nInformation Disclosure Headers:\n"
        final_saved_result += Style.RESET_ALL + Style.BRIGHT + "\nInformation Disclosure Headers:\n"
        for value in missing_info_headers:
            final_printed_result += "[-] " +value + "\n"
            final_saved_result += Fore.YELLOW + "[-] " +value + "\n"
        check += 1
    if len(missing_cache_headers) != 0:
        final_printed_result += "\nCache Headers Missing:\n"
        final_saved_result += Style.RESET_ALL + Style.BRIGHT + "\nCache Headers Missing:\n"
        for value in missing_cache_headers:
            final_printed_result += "[-] " +value + "\n"
            final_saved_result += Fore.YELLOW + "[-] " +value + "\n"
        check += 1

    final_printed_result += "\n-= End Headers Check =-\n\n"
    final_saved_result += Style.RESET_ALL + Style.BRIGHT + "\n-= End Headers Check =-\n\n"
    
    if check > 0:
        with open(output_dir+"/header_"+target.replace("/","_"), "w+") as file:
            file.write(final_saved_result)
            file.seek(0)
            if len(file.readlines()) == 0:
                return ""
        return final_printed_result
    else:
        return ""

# Check Security of the cookies
def get_cookies_sec(target, my_type="https", port=""):
    try:
        if port in ["", "80", "443"]:
            res = r.get(my_type+"://"+target)
        else:
            res = r.get(my_type+"://"+target +":"+port)
    except:
        return ""
    headers = res.headers

    # Retrieve all 'Set-Cookie' headers
    set_cookie_headers = res.headers.get('Set-Cookie')
    if set_cookie_headers is not None :
        set_cookie_headers = split_set_cookie_headers(set_cookie_headers)
    info_cookies = ""

    if not set_cookie_headers:
        set_cookie_headers = [headers.get('Set-Cookie')]

    for cookie_header in set_cookie_headers:
        if cookie_header:
            # Parse the 'Set-Cookie' header using SimpleCookie
            cookie = SimpleCookie()
            cookie.load(cookie_header)

            for key, morsel in cookie.items():
                info_cookies += f"\nCookie: {morsel.OutputString()}"
                # Check attributes
                attributes = morsel.OutputString().split('; ')
                has_http_only = 'HttpOnly' in attributes
                has_secure = 'Secure' in attributes
                samesite_value = [attr for attr in attributes if attr.lower().startswith('samesite')]

                info_cookies += f"\nHttpOnly: {'Yes' if has_http_only else 'No [!]'}"
                info_cookies += f"\nSecure: {'Yes' if has_secure else 'No [!]'}"
                if samesite_value:
                    samesite_final_value = samesite_value[0].split('=')[1].lower()
                    if samesite_final_value not in ["lax", "strict"]:
                        info_cookies += f"\nSameSite: {samesite_final_value} [!] Need to use 'strict' or 'lax'"
                    elif samesite_final_value == "lax":
                        info_cookies += f"\nSameSite: {samesite_final_value} (may be better to use 'strict' value)')"
                else:
                    info_cookies += f"\nSameSite: No"
                info_cookies += "\n" + "-" * 48 + "\n\n"
        else:
            return ""
    return info_cookies

# Split correctly the cookies 
def split_set_cookie_headers(header_value):
    cookies = []
    cookie = ""
    parts = header_value.split(",")
    for part in parts:
        if "expires=" in part.lower():
            cookie += part + ","
        else:
            cookie += part
            cookies.append(cookie.strip())
            cookie = ""
    if cookie:
        cookies.append(cookie.strip())
    return cookies

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
                if service.get("name") in ["ssl", "http", "https", "tcpwrapped"]:
                    if service.get("tunnel") == "ssl" or portid == "443":
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
      -H, --host_file           Name of the host file (default: "./hosts.txt")
      -p, --path                Path where to create the report (default: "./")
      -n, --name                Name of the project (default: "ReconRanger_Project")
      -U --user-group           User and group that will own the folder as user:group

    Nmap Options:
      -s, --scan-dir            Folder name for the nmap output folder (default: "Nmap_Scans")
      -sU, --udp-flags          Specify your own nmap flags for UDP scan -sU="options1 option2...." (default: "-vv -Pn --min-rate 1000 -sU --top-ports 1000 -sV -sC")
      -sT, --tcp-flags          Specify your own nmap flags for TCP scan as: -sT="options1 option2...." (default: "-vv -Pn --min-rate 1000 -p- -sV -sC")
      -xU, --exclude-udp        Exclude UDP scan from the report (default: False)

    TestSSL Options:  
      -S, --ssl                 Folder name for the SSL check output folder (default: "Test_SSL")
    
    Header Check Options:
      -He, --header-folder     Folder name for the HTTP header check (default: "Headers_Check")

    

    Examples:
      python ReconRanger.py -D
      => Will run with all default options

      python ReconRanger.py -H my_host_file.txt -p ./ -sT="-p 10-1000"
      => Will use the hosts from my_host_file.txt, create the project in the current directory and scan the TCP ports from 10 to 1000
    """
    print(help_message)
    exit(0)
