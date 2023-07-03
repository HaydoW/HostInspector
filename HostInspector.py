from libnmap.parser import NmapParser, NmapParserException
import argparse
import os


dc_ports = { 88, 389, 464, 636, 3268, 3269}
web_ports = { 80, 443, 4080, 4443, 5080, 5443, 5555, 6080, 6443, 6666, 7000, 7080, 7443, 7777, 8000, 8080, 8443, 8888, 9000, 9080, 9443, 9999, 10000, 10080, 10443 }
dbms_ports = { 443, 1025, 1433, 1521, 1526, 1527, 1883, 1972, 3000, 3306, 4000, 4200, 4334, 5000, 5432, 5439, 6379, 7070, 7474, 8000, 8080, 8082, 8086, 8091, 8123, 8529, 8765, 9042, 9088, 9092, 9200, 10255, 10800, 11211, 16000, 21212, 26257, 27017, 28015, 30015, 50000 }
remote_mgmt_ports = { 22, 23, 80, 135, 137, 138, 139, 161, 443, 1494, 2222, 3283, 3389, 4899, 5631, 5650, 5900, 5938, 6129, 6783, 6784, 6785, 7070, 8041, 8192, 8200 }
cleartext_ports = { 21, 23, 25, 80, 110, 143, 512, 513, 514, 5222, 5900 }
fileshare_ports = { 21, 22, 445, 873, 990, 2049 }


def arg_handler():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--xmlfile", help="Nmap XML file to parse", required=True)
    parser.add_argument("-m","--mode", help="Host sorting mode", choices=['simple','smart'], required=True)
    parser.add_argument("-c","--count", help="Number of hosts to return", required=True)
    parser.add_argument("-o","--outfile", help="Outputfile name", required=True)
    return parser.parse_args()


def simple_sort(report):

    host_services = {}
    
    for host in report.hosts:
        count = 0
        if host.is_up():
            for s in host.services:
                if s.open():
                    count += 1

        host_services.update({host.address : count})
    
    return host_services
    

def smart_sort(report):

    host_services = {}
    
    for host in report.hosts:
        score = 0
        if host.is_up():
            for s in host.services:
                if s.open():
                    if s.port in dc_ports:
                        # Heavily favour DC's
                        score += 50 
                    if s.port in cleartext_ports:
                        # Favour hosts with cleartext protocols
                        score += 5
                    if s.port in web_ports or s.port in dbms_ports or s.port in remote_mgmt_ports or s.port in fileshare_ports:
                        score +=1

        host_services.update({host.address : score})

    return host_services


def print_and_save(host_services, numhosts, outfile, mode):

    host_services = dict(sorted(host_services.items(), key=lambda item: item[1], reverse=True))

    try:
        f = open(outfile, 'w')
    except:
        raise SystemExit('\n[!] Could not create specified output file!')
    
    print('\n[+] Printing top {0} hosts:\n'.format(numhosts))

    for key, value in list(host_services.items()) [0: numhosts]:
        if mode == 'simple':
            print('Host: {0} \t Open ports: {1}'.format(key, value))
        elif mode == 'smart':
            print('Host: {0} \t Interest score: {1}'.format(key, value))
        f.write(key + '\n')
    
    print('\n[+] {0} IP\'s saved to file: {1}'.format(numhosts, outfile))
    
    f.close()


def main():

    args = arg_handler()
    if not os.path.exists(args.xmlfile):
        raise SystemExit('\n[!] Provided XML file does not exist!')
    elif not os.access(args.xmlfile, os.R_OK):
        raise SystemExit('\n[!] Could not open provided XML file!')
    else:
        report = NmapParser.parse_fromfile(args.xmlfile)

    if args.mode == 'simple':
        host_services = simple_sort(report)
    elif args.mode == 'smart':
        host_services = smart_sort(report)

    print_and_save(host_services, int(args.count), args.outfile, args.mode)

if __name__ == main():
    main()