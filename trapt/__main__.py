#! /usr/bin/python3

import argparse
import configparser
from scapy.all import sniff as sniff

import core.capture
import config.main
import config.router
import config.host

def arguments():

    ap = argparse.ArgumentParser( description='Run the trAPT virtual deception network environment')
    ap.add_argument('-c', '--config',  default='etc/config.ini' , help='path to configuration file')
    ap.add_argument('-r', '--routers', default='etc/routers.ini', help='path to router definitions file')
    ap.add_argument('-o', '--hosts',   default='etc/hosts.ini'  , help='path to host definitions file')

    return(ap.parse_args())

def main():
    args = arguments()
    configuration = config.main.Main(args.config)
    routers = config.router.Router(args.routers)
    hosts = config.host.Host(args.hosts, routers)

    packet_capture = core.capture.Capture(configuration)
    packet_capture.start()

if __name__ == '__main__':    
    main()
