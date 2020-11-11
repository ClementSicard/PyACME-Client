from time import sleep
from copy import copy
from dnslib import RR
from dnslib.server import DNSServer, BaseResolver, DNSLogger
import argparse


class SingleAddressResolver(BaseResolver):
    def __init__(self, zone):
        # Parse RRs
        self.rrs = RR.fromZone(zone)

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        # Replace labels with request label
        for rr in self.rrs:
            a = copy(rr)
            a.rname = qname
            reply.add_answer(a)
        return reply


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", type=str)
    args = parser.parse_args()

    response = open("dns_records.txt", "r")
    resolver = SingleAddressResolver(response)
    logger = DNSLogger("request,reply,truncated,error", False)

    print("Starting DNS server (%s:%d) [%s]" % ("Port", 10053, "UDP"))

    for rr in resolver.rrs:
        print("    | ", rr.toZone().strip(), sep="")
    print()

    udp_server = DNSServer(resolver,
                           port=10053,
                           address=args.record,
                           logger=logger)
    udp_server.start_thread()

    while udp_server.isAlive():
        previous = resolver.rrs
        response = open("dns_records.txt", "r")
        resolver.rrs = RR.fromZone(response)
        if previous != resolver.rrs:
            print("Record file updated.")
            for rr in resolver.rrs:
                print("    | ", rr.toZone().strip(), sep="")
        sleep(1)
