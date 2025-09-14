import os
from functions import *
import argparse
import sys
from progress_bar import ProgressBar

def create_markdown_files(path="./", folder_name="ReconRanger_Project", hosts_file="hosts.txt", host="", scan_folder="Nmap_Scans", udp_flags="" , tcp_flags="", exclude_udp=False, ssl_folder="Test_SSL", header_folder="Headers_Check", user_group=":", podman=False, docker=False):

    if podman or docker:
        container_path = "/ouptut"

        if podman:
            runner = ["podman"]
        else:
            runner = ["sudo", "docker"]

        runner_args = ["--cap-add", "NET_RAW", "--rm", "-it", "-v", f"{path}:{container_path}"]

        if host != "" and not hosts_file:
            hostvar = ["-H", host],
        elif hosts_file != "" and host == "":
            runner_args.extend(["-v", f"{hosts_file}:/hosts.txt"])
            hostvar = ["-Hf", "/hosts.txt"],
        else:
            print("\033[91m[-] You need to specify either a host file or a host\033[0m")
            exit(1)

        new_arg_list = [*runner, "run", *runner_args, "reconranger",
                        "-p", f"{container_path}",
                        "-n", f"{folder_name}",
                        *hostvar,
                        "-s", f"{scan_folder}",
                        "-S", f"{ssl_folder}",
                        "-He", f"{header_folder}"
                        ]
        if udp_flags != "":
            new_arg_list.extend(["-sU", f'"{udp_flags}"'])
        if tcp_flags != "":
            new_arg_list.extend(["-sT", f'"{tcp_flags}"'])
        if exclude_udp:
            new_arg_list.extend(["-xU"])
        run_command = new_arg_list
        try:
            subprocess.run(run_command, check=True)
        except Exception as e:
            print(f"\033[91m[-] Error running the container\n[-] Don't forget to build the container with the command:\n\033[0m\033[93m{runner} build -t reconranger .\033[0m")
            exit(1)
        saved_path = os.path.join(path, folder_name)
        print(f"\033[92m[+] Scan ended and result saved in\033[0m {saved_path}")
        exit(0)

    # Create the folder if it doesn't exist
    if not os.path.exists(path+"/"+folder_name):
        folder_name = path+"/"+folder_name
        os.makedirs(folder_name)
        os.makedirs(folder_name+"/"+"Photos")
    else:
        folder_name = path+"/"+folder_name

    folder_name = os.path.normpath(folder_name)
    ssl_folder = os.path.normpath(folder_name + "/"+ ssl_folder)
    header_folder = os.path.normpath(folder_name + "/"+ header_folder)
    scan_folder = os.path.normpath(folder_name + "/"+ scan_folder)

    if not os.path.exists(hosts_file) and host == "":
        print("\033[91m[-] Host file not present\033[0m")
        exit(1)

    hosts = []

    # Read the hosts.txt file
    if host == "":
        host_list = open(hosts_file, "r").read()
        lines = host_list.splitlines()
    else:
        host_list = host.split(",")
        lines = host_list

    # Read each line from the file
    for line in lines:
        # Remove leading and trailing whitespace
        domain = line.strip()

        # Skip empty lines or lines starting with #
        if domain == "" or domain.startswith("#"):
            continue

        # Deal with non domain in hosts file (https://domain or domain/)
        domain = domain.replace("https://","").replace("http://","")
        if domain[len(domain)- 1] == "/":
            domain = domain[:len(domain)- 1]

        full_URL = domain
        if "/" in domain:
            domain = full_URL.split("/")[0]

        hosts.append({
            "domain": domain,
            "full_URL": full_URL
        })

    steps = {
        "ports_tcp": "TCP ports scan",
        "services_tcp": "TCP services scan",
        "scripts_tcp": "Nmap TCP scripts scan",
        "tls": "TLS configuration scan",
        "headers": "HTTP headers scan",
        "cookies": "HTTP cookies scan",
    }

    if not exclude_udp:
        steps.update({
            "ports_udp": "UDP ports scan",
            "services_udp": "UDP services scan",
            "scripts_udp": "Nmap UDP scripts scan",
        })

    progress_bar = ProgressBar(len(hosts), steps)

    try:
        for host in hosts:
            domain = host["domain"]
            full_URL = host["full_URL"]
            progress_bar.newHost(full_URL)

            # Run Nmap scan
            tcp_nmap = launch_tcp_nmap(target=domain, flags=tcp_flags, folder=scan_folder, progress_bar=progress_bar)

            if not exclude_udp:
                udp_nmap = launch_udp_nmap(target=domain, flags=udp_flags ,folder=scan_folder, progress_bar=progress_bar)

            # Check if a web port is open http and/or https to display or not the "Test HTTP Header" section
            value_of_web_port = extract_open_http_ports(scan_folder+"/nmap_tcp_"+domain+".xml")

            full_test_ssl = ""
            full_rating = ""
            https_ports = [port for proto, port in value_of_web_port if proto == "https"]
            progress_bar.newStep("tls", segments = len(https_ports))
            for port in https_ports:
                test_ssl, rating = run_testssl(target=domain, project_path=os.path.dirname(os.path.abspath(__file__)), output_dir=ssl_folder, port=port, progress_bar=progress_bar)

                if test_ssl != "" or rating != "":
                    full_test_ssl += "\n---------------------\nHTTPS on port " + port + "\n---------------------\n" + test_ssl
                    full_rating += "\n---------------------\nHTTPS on port " + port + "\n---------------------\n" + rating
                    test_ssl = ""
                    rating = ""

                progress_bar.newSegment()

            headers = ""
            progress_bar.newStep("headers", segments = len(value_of_web_port))
            for proto, port in value_of_web_port:
                headers += run_my_header_check(target=full_URL, my_type=proto, output_dir=header_folder, port=port)
                progress_bar.newSegment()

            cookies_check_sec = ""
            progress_bar.newStep("cookies", segments = len(value_of_web_port))
            for proto, port in value_of_web_port:
                cookies_check_sec += get_cookies_sec(target=full_URL, my_type=proto, port=port)
                progress_bar.newSegment()

            # Create the markdown file
            file_name = os.path.join(folder_name, f"{domain}.md")
            with open(file_name, "w") as md_file:
                # Write Markdown content to the file
                md_file.write("- [ ] Finished\n\n\n")
                md_file.write(f"# {domain}\n\n")

                md_file.write("# TCP\n\n")
                md_file.write("```")
                md_file.write(nmap_verbose_output(tcp_nmap))
                md_file.write("```\n\n")

                if not exclude_udp:
                    md_file.write("# UDP\n\n")
                    md_file.write("```")
                    md_file.write(nmap_verbose_output(udp_nmap))
                    md_file.write("```\n\n")

                md_file.write("# FFuF / Gobuster\n\n")
                md_file.write("```\n\n```\n\n")

                if headers != "":
                    md_file.write("# Test HTTP Header\n\n")
                    md_file.write("```")
                    md_file.write(headers)
                    md_file.write("```\n\n")

                if full_rating != "":
                    md_file.write("# Test SSL\n\n")
                    md_file.write("```\n")
                    md_file.write(full_rating)
                    md_file.write("```\n\n")
                if full_test_ssl != "":
                    md_file.write("## SSL Linked CVE\n\n")
                    md_file.write("```\n")
                    md_file.write(full_test_ssl)
                    md_file.write("```\n\n")

                if cookies_check_sec != "":
                    md_file.write("# Cookie Misconfigurations\n\n")
                    md_file.write("```\n")
                    md_file.write(cookies_check_sec)
                    md_file.write("```\n\n")

                md_file.write("# Vulnerabilities\n\n\n")

        progress_bar.complete()

    finally:
        progress_bar.end()

    if user_group != ":" :
        # Change rights to original user
        change_owner(folder_name, user_group)
    exit(0)

def main():
    parser = argparse.ArgumentParser(description="Run different scans and write the repport", add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("-p", "--path", default="./", help='Path where to create the report (default: "./")')
    parser.add_argument("-n", "--name", default="ReconRanger_Project", help='Name of the project (default: "ReconRanger_Project")')
    parser.add_argument("-s", "--scan-dir", default="Nmap_Scans", help='Folder name for the nmap output folder (default: "Nmap_Scans")')
    parser.add_argument("-sU", "--udp-flags", nargs='+', help='Specify your own nmap flags for UDP scan')
    parser.add_argument("-sT", "--tcp-flags", nargs='+', help='Specify your own nmap flags for TCP scan')
    parser.add_argument("-xU", "--exclude-udp", action="store_true", default="", help='Exclude UDP scan')
    parser.add_argument("-Hf", "--host-file", default="", help='Name of the host file (default: "")')
    parser.add_argument("-H", "--host", default="", help='Name of the host to scan (default: "")')
    parser.add_argument("-S", "--ssl", default="Test_SSL", help='Folder name for the SSL check output folder (default: "Test_SSL")')
    parser.add_argument("-He", "--header-folder", default="Headers_Check", help='Folder name for the HTTP header check (default: "Headers_Check")')
    parser.add_argument("-U", "--user-group", default="", help='Specify the username and group as user:group')
    parser.add_argument("-P", "--podman", action="store_true", default="", help='Use ReconRanger in a Podman container')
    parser.add_argument("-D", "--docker", action="store_true", default="", help='Use ReconRanger in a Docker container')
    args = parser.parse_args()

    if args.help or len(sys.argv) == 3 or (len(args.host_file) <= 0 and len(args.host) <= 0) or (len(args.host_file) > 1 and len(args.host) > 1):
        help_menu()
    if args.path:
        output_dir = args.path
    else:
        output_dir = "./"

    if args.name:
        project_name = args.name
    else:
        project_name = "./test_project"

    if args.scan_dir:
        scan_dir = args.scan_dir
    else:
        scan_dir = "./Nmap_Scans"

    if args.tcp_flags:
        tcp_flags = ' '.join(args.tcp_flags)
    else:
        tcp_flags = ""

    if args.udp_flags:
        udp_flags = ' '.join(args.udp_flags)
    else:
        udp_flags = ""

    if args.exclude_udp:
        exclude_udp = True
    else:
        exclude_udp = False

    if args.host_file:
        host_file = args.host_file
    else:
        host_file = "./hosts.txt"

    if args.host:
        host = args.host
    else:
        host = ""

    if args.ssl:
        ssl_folder = args.ssl
    else:
        ssl_folder = "./Test_SSL"

    if args.header_folder:
        header_folder = args.header_folder
    else:
        header_folder = "./Headers_Check"

    if args.user_group:
        user_group = args.user_group
    else:
        user_group = ":"

    if args.podman:
        podman = True
    else:
        podman = False

    if args.docker:
        docker = True
    else:
        docker = False

    create_markdown_files(path=output_dir, folder_name=project_name, hosts_file=host_file, host=host, scan_folder=scan_dir, udp_flags=udp_flags, tcp_flags=tcp_flags, exclude_udp=exclude_udp, ssl_folder=ssl_folder, header_folder=header_folder, user_group=user_group, podman=podman, docker=docker)

if __name__ == "__main__":
    main()