import os
from functions import *
from libnmap.parser import NmapParser
import argparse
from alive_progress import alive_bar
import sys

def create_markdown_files(path="./", folder_name="project_name", hosts_file="hosts.txt", scan_folder="Nmap_Scan", existing_folder=False, udp_flags="" , tcp_flags="", ssl_folder="Test_SSL", scan_type="native", header_folder="Headers_Check", user_group=":"):
    with alive_bar(title='Processing...', spinner='arrows_in', length=40) as bar:
        # Create the folder if it doesn't exist
        if not os.path.exists(path+"/"+folder_name):
            folder_name = path+"/"+folder_name
            os.makedirs(folder_name)
            os.makedirs(folder_name+"/"+"Photos")
        else:
            folder_name = path+"/"+folder_name
        
        folder_name = os.path.normpath(folder_name)
        
        if existing_folder == False:
            scan_folder = os.path.normpath(folder_name +"/"+ scan_folder)

        ssl_folder = os.path.normpath(folder_name + "/"+ ssl_folder)
        header_folder = os.path.normpath(folder_name + "/"+ header_folder)

        if not os.path.exists(hosts_file):
            print("[-] Host file not present")
            exit(1)

        # Read the hosts.txt file
        with open(hosts_file, "r") as file:
            # Read each line from the file
            for line in file:
                # Remove leading and trailing whitespace
                domain = line.strip()
                # Skip empty lines or lines starting with #
                if not domain or domain.startswith("#"):
                    continue

                # Run Nmap scan
                udp_nmap = launch_udp_nmap(target=domain, flags=udp_flags ,folder=scan_folder)                
                tcp_nmap = launch_tcp_nmap(target=domain, flags=tcp_flags ,folder=scan_folder)
                # Check if a web port is open http and/or https to display or not the "Test HTTP Header" section
                value_of_web_port = extract_open_http_ports(scan_folder+"/nmap_tcp_"+domain+".xml")
                headers = ""
                port =""
                https_port =  ""
                full_test_ssl = ""
                full_rating = ""
                test_ssl, rating = "", ""
                for value in value_of_web_port:
                    if "https" in value:
                        # Run Header check on HTTPS
                        headers += run_shcheck(target=domain, type="https", output_dir=header_folder, port=value["https"])
                        https_port = value["https"]
                    else:
                        if "http" in value:
                            port = value["http"]
                            headers += run_shcheck(target=domain, type="http", output_dir=header_folder, port=port)
                        else:
                            print(value)
                    # Run Certificate check on HTTPS
                    if https_port != "":
                        if scan_type == "native":
                            test_ssl, rating = run_testssl_native(target=domain, output_dir=ssl_folder, port=https_port) 
                        elif scan_type == "docker":
                            test_ssl, rating = run_testssl_docker(target=domain, output_dir=ssl_folder, port=https_port)
                        else:
                            test_ssl, rating = "", ""
                        if test_ssl != "" or rating != "":
                            full_test_ssl += "\n---------------------\nHTTPS on port " + https_port + "\n---------------------\n" + test_ssl 
                            full_rating += "\n---------------------\nHTTPS on port " + https_port + "\n---------------------\n" + rating 
                            test_ssl = ""
                            rating = ""


                # Create the markdown file
                file_name = os.path.join(folder_name, f"{domain}.md")
                with open(file_name, "w") as md_file:
                    # Write Markdown content to the file
                    md_file.write("- [ ] Finished\n\n\n")
                    md_file.write(f"# {domain}\n\n")
                    
                    md_file.write("# TCP\n\n")
                    md_file.write("```")
                    md_file.write(tcp_nmap)
                    md_file.write("```\n\n")

                    md_file.write("# UDP\n\n")
                    md_file.write("```")
                    md_file.write(udp_nmap)
                    md_file.write("```\n\n")

                    md_file.write("# FFuF / Gobuster\n\n")
                    md_file.write("```\n\n```\n\n")
                    
                    if headers != "":
                        md_file.write("# Test HTTP Header\n\n")
                        md_file.write("```")
                        md_file.write(headers)
                        md_file.write("```\n\n")

                    if https_port != "":
                        md_file.write("# Test SSL\n\n")
                        md_file.write("```\n")
                        md_file.write(full_rating)
                        md_file.write("```\n\n")
                    
                        md_file.write("## SSL linked CVE\n\n")
                        md_file.write("```\n")
                        md_file.write(full_test_ssl)
                        md_file.write("```\n\n")
                    
                    md_file.write("# Vulnerabilities\n\n\n")
                print()
                print(f"[+] Rapport written for {domain}")
                print()
        if user_group != ":" :
            # Change rights to original user
            command = ['sudo', "chown",  "-R", user_group  , folder_name]
            subprocess.run(command)
        exit(0)

def main():
    parser = argparse.ArgumentParser(description="Run different scans and write the repport", add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("-D", "--default", action="store_true", help="Use all default settings")
    parser.add_argument("-p", "--path", default="./", help='Path where to create the report (default: "./")')
    parser.add_argument("-n", "--name", default="./test_project", help='Name of the project (default: "./test_project")')
    parser.add_argument("-s", "--scan-dir", default="./Nmap_Scans", help='Folder name for the nmap output folder (default: "./Nmap_Scans")')
    parser.add_argument("-sU", "--udp-flags", nargs='+', help='Specify your own nmap flags for UDP scan')
    parser.add_argument("-sT", "--tcp-flags", nargs='+', help='Specify your own nmap flags for TCP scan')
    parser.add_argument("-H", "--host-file", default="./hosts.txt", help='Name of the host file (default: "./hosts.txt")')
    parser.add_argument("-S", "--ssl", default="./Test_SSL", help='Folder name for the SSL check output folder (default: "./Test_SSL")')
    parser.add_argument("-St", "--scan-type", choices=["docker", "native"], help='Use either "docker" or "native" to either run a docker container for the testssl or run it from binary.')
    parser.add_argument("-He", "--header-folder", default="./Headers_Check", help='Folder name for the HTTP header check (default: "./Headers_Check")')
    parser.add_argument("-U", "--user-group", default="", help='Specify the username and group as user:group')

    args = parser.parse_args()
    if args.default:
        create_markdown_files()
    else:
        if args.help or len(sys.argv) == 1:
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

        if args.existing_folder:
            existing_folder = True
        else:
            existing_folder = False

        if args.tcp_flags:
            tcp_flags = ' '.join(args.tcp_flags)
        else:
            tcp_flags = ""

        if args.udp_flags:
            udp_flags = ' '.join(args.udp_flags)
        else:
            udp_flags = ""

        if args.host_file:
            host_file = args.host_file
        else:
            host_file = "./hosts.txt"

        if args.ssl:
            ssl_folder = args.ssl
        else:
            ssl_folder = "./Test_SSL"

        if args.header_folder:
            header_folder = args.header_folder
        else:
            header_folder = "./Headers_Check"

        if args.scan_type:
            scan_type = args.scan_type
        else:
            scan_type = "native"

        if args.user_group:
            user_group = args.user_group
        else:
            user_group = ":"

    create_markdown_files(path=output_dir, folder_name=project_name, hosts_file=host_file, scan_folder=scan_dir, existing_folder=existing_folder, udp_flags=udp_flags, tcp_flags=tcp_flags, ssl_folder=ssl_folder, scan_type=scan_type, header_folder=header_folder, user_group=user_group)

if __name__ == "__main__":
    main()