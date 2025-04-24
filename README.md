
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

## Default Install

To be able to run this script use the following command:

```bash
sudo apt install git \
    bash \
    python3 \
    py3-pip \
    sudo \
    nmap \
    nmap-scripts \
    coreutils \
    procps
git clone --recursive https://github.com/Nouman404/ReconRanger.git
cd ReconRanger
sudo pip3 install -r src/requirements.txt
```

> Note that you have to run the pip install in sudo. This is due to the way the program runs. The nmap in UDP mode needs sudo rights so to be able to scan a lot of IPs/domains the whole process runs in sudo. If not, you would be asked to retype the password and may need to stay in front of your computer...

## Podman Install

Best install since it doesn't require root privileges is by using podman:

```bash
git clone --recursive https://github.com/Nouman404/ReconRanger.git
cd ReconRanger
podman build -t reconranger .
```

## Docker Install

To run this script using docker and without worrying about dependencies, execute the following command:
```bash
git clone --recursive https://github.com/Nouman404/ReconRanger.git
cd ReconRanger
sudo docker build -t reconranger .
```

> If you get any issues when trying the docker build command try restarting your docker service using `sudo systemctl restart docker`


## Usage

### Default 

You can use the `--default` or `-D` flag to run the script with default options. The default options are the following:
- Path of the project (`-p` or `--path`): `./`
- Project name (`-n` or `--name`): `ReconRanger_Project` 
- Nmap output folder (`-s` or `--scan-dir`): `Nmap_Scans` 
- Nmap UDP flags (`-sU` or `--udp-flags`): `-vv -Pn --min-rate 1000 -sU --top-ports 1000 -sV -sC -oA nmap_tcp_DOMAIN_OR_IP`
- Nmap TCP flags (`-sT` or `--tcp-flags`): `-vv -Pn --min-rate 1000 -p- -sV -sC -oA nmap_tcp_DOMAIN_OR_IP`
- Exlude UDP scans (`-xU`, `--exclude-udp`): `False` (No need to specify True after using this flag)
- Host file (`-H`, `--host-file`): `./hosts.txt`
- Test SSL folder (`-S`, `--ssl`): `test_SSL`
- Header folder (`-He`, `--header-folder`): `Headers_Check`

### Custom

You can modify any of the input used by the program by using the simple flags `-X` or long flags `--XYZ`. Be aware that the flags that can take a string as argument (flags for Nmap TCP/UDP) need the `=` sign to work. So, `-sT -p 10-1000` won't work if you want to scan the port from 10 to 1000. Instead you will have to run `-sT="-p 10-1000"` 

### Exemples

Via your host:
```bash
sudo python3 ReconRanger.py -H ../hosts.txt -p ../ -n my_project -xU"
```

Via podman:
```bash
podman run --cap-add NET_RAW --rm -it -v "/home/user/Documents/:/ReconRangerDir/" reconranger -H /ReconRangerDir/hosts.txt -p /ReconRangerDir/ -n my_project -xU
```

> If you try scans that need sudo rights (ex: nmap -sS) you may need to run podman with sudo. 

Via docker:
```bash
sudo docker run --cap-add NET_RAW --rm -it -v "/home/user/Documents/:/ReconRangerDir/" reconranger -H /ReconRangerDir/hosts.txt -p /ReconRangerDir/ -n my_project -xU
```

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
      -n, --name                Name of the project (default: "ReconRanger_Project")
      -H, --host_file           Name of the host file (default: "./hosts.txt")

    Nmap Options:
      -s, --scan-dir            Folder name for the nmap output folder (default: "Nmap_Scans")
      -sU, --udp-flags          Specify your own nmap flags for UDP scan (default: "-vv -Pn --min-rate 1000 -sU --top-ports 1000 -sV -sC")
      -sT, --tcp-flags          Specify your own nmap flags for TCP scan (default: "-vv -Pn --min-rate 1000 -p- -sV -sC")
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
```
## LICENCE

This project is using a GPL3 licence available [here](https://raw.githubusercontent.com/Nouman404/ReconRanger/main/LICENSE)
