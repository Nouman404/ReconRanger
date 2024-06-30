
# ReconRanger

```
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
```

So this script could allow you to scan a lot of domains/IPs and give you Nmap (UDP+TCP) scan result with an SSL check and a header check. A section for your fuzzing is added so you can put the result you found and a vulnerability section for you to add any vulnerability on your report. 

## Installation

To be able to run this script use the following command:

```bash
sudo pip3 install -r requirement.txt
```

> Note that you have to run the pip install in sudo. This is due to the way the program runs. The nmap in UDP mode needs sudo rights so to be able to scan a lot of IPs/domains the whole process runs in sudo. If not, you would be asked to retype the password and may need to stay in front of your computer...


## Information

The final structure will look like this:

```
# DOMAIN_or_IP

# TCP

...
nmap_tcp_result
...

# UDP

...
nmap_udp_result
...

# FFUF / Gobuster

waiting_your_input

# Test HTTP Header

...
HTTP header check result
...

# Test SSL

...
SSL test result
...

# SSL linked CVE
...
SSL CVEs
...

# Cookie Misconfigurations
...
Cookie Misconfigurations
...

# Vulnerabilities

waiting_your_input

```

You can find an example [here](https://raw.githubusercontent.com/Nouman404/ReconRanger/main/test_project/127.0.0.1.md) if you want.

Note that if you don't specify an output directory for the Nmap scans, one will be created for the correct use of this tool.


## Help menu

If you run the scipt without any parameter or using the `-h` or `--help` flag, you will get the following help menu:

```
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
```

## Usage

### Default 

You can use the `--default` or `-D` flag to run the script with default options. The default options are the following:
- Path of the project (`-p` or `--path`): `./`
- Project name (`-n` or `--name`): `test_project` 
- Nmap output folder (`-s` or `--scan-dir`): `[PROJECT_FOLDER]/Nmap_Scans` 
- Nmap UDP flags (`-sU` or `--udp-flags`): `-vv -Pn --min-rate 1000 -sU --top-ports 1000 -sV -sC -oA [PROJECT_FOLDER]/[NMAP_FOLDER]/nmap_tcp_DOMAIN_OR_IP`
- Nmap TCP flags (`-sT` or `--tcp-flags`): `-vv -Pn --min-rate 1000 -p- -sV -sC -oA [PROJECT_FOLDER]/[NMAP_FOLDER]/nmap_tcp_DOMAIN_OR_IP`
- Exlude UDP scans (`-xU`, `--exclude-udp`): `False` (No need to specify True after using this flag)
- Host file (`-H`, `--host-file`): `./hosts.txt`
- Test SSL folder (`-S`, `--ssl`): `[PROJECT_FOLDER]/Test_SSL`
- Header scan type (`-sT`, `--scan-type`): `native`
- Header folder (`-He`, `--user-group`): `./Headers_Check`

### Custom

You can modify any of the input used by the program by using the simple flags `-X` or long flags `--XYZ`. Be aware that the flags that can take a string as argument (flags for Nmap TCP/UDP) need the `=` sign to work. So, `-sT -p 10-1000` won't work if you want to scan the port from 10 to 1000. Instead you will have to run `-sT="-p 10-1000"` 

## LICENCE

This project is using a GPL3 licence available [here](https://raw.githubusercontent.com/Nouman404/ReconRanger/main/LICENSE)
