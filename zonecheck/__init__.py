#!rusr/bin/env python
import os
import os.path
import time
import socket
import logging
import argparse
import dns
import dns.zone
import dns.query
import dns.message
import dns.rdatatype
from datetime import datetime, timedelta
class AxfrCheck:
    '''check a zone via AXFR'''
    
    zone_content = False
    errors       = []

    def __init__(self, zone, server = 'localhost',
            rrsig_ttl = 2, rrsig_perc = 20, rrsig_time = 172800):

        self.logger     = logging.getLogger('zonecheck.AxfrCheck')
        self.server     = server
        self.zone       = zone
        self.rrsig_ttl  = rrsig_ttl
        self.rrsig_perc = rrsig_perc
        self.rrsig_time = rrsig_time
        self.get_axfr()

    def get_axfr(self):
        try:
            self.zone_content = dns.zone.from_xfr(
                    dns.query.xfr(self.server, self.zone, timeout=5))
        except dns.exception.FormError as e:
            msg = '{} {}: unable to xfr {} '. format(self.zone, self.server, e)
            self.logger.warn(msg)
            self.errors.append(msg)
        except dns.exception.Timeout:
            msg = '{} {} timed out'. format(self.zone, self.server)
            self.logger.warn(msg)
            self.errors.append(msg)
        except socket.error as e:
            msg = '{} {}: {} '. format(self.zone, self.server, e)
            self.logger.warn(msg)
            self.errors.append(msg)

    def _check_rrsig(self, name, rrsig):
        '''check individual record'''
        now           = time.time()
        rrsig_expires = rrsig.expiration - now
        rrsig_period  = rrsig.expiration - rrsig.inception
        if rrsig.expiration <= now + (self.rrsig_ttl * rrsig.original_ttl):
            self.logger.warn('TTL_WARN:{}: expires in {} secs'.format(name, rrsig_expires)) 
        if rrsig.expiration <= now + (self.rrsig_perc / 100 * rrsig_period):
            self.logger.warn('PERC_WARN:{}: expires in {} secs'.format(name, rrsig_expires)) 
        if rrsig.expiration <= now + self.rrsig_time:
            self.logger.warn('TIME_WARN:{}: expires in {} secs'.format(name, rrsig_expires)) 

    def check(self):
        '''check the axfr of the zone'''
        if self.zone_content:
            for name, node in self.zone_content.items():
                self.logger.debug('{}: started'.format(name))
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.RRSIG:
                        for rdata in rdataset:
                            if rdataset.rdtype == dns.rdatatype.RRSIG:
                                self._check_rrsig(name, rdata)

class ZoneCheck:
    '''Object to store zone check data'''
    master_soa    = None
    zone_soa      = None

    def __init__(self, server, soa_server, zone, 
            serial_lag = 2, retry = 3, timeout = 5):
        self.logger     = logging.getLogger('zonecheck.ZoneCheck')
        self.retry      = retry
        self.timeout    = timeout
        self.serial_lag = serial_lag
        self.zone       = zone
        self.soa_server = soa_server
        self.server     = server
        self.errors     = {
                'master_soa': False,
                'general' : [],
                'soa'     : []}
        self.set_master_soa()
    def get_dns(self, addr, proto='udp'):
        question = dns.message.make_query(self.zone, dns.rdatatype.SOA)
        addr_tokens = addr.split()
        port = 53
        if len(addr_tokens) == 3 and addr_tokens[1] == 'port':
            port = int(addr_tokens[2])
        for i in xrange(self.retry):
            try:
                if proto == 'tcp':
                    response = dns.query.tcp(question, addr_tokens[0], port=port, 
                            timeout=self.timeout)
                else:
                    response = dns.query.udp(question, addr_tokens[0], port=port,
                            timeout=self.timeout)
            except dns.exception.Timeout:
                msg = '{} {} timed out'. format(addr, proto)
                if i == self.retry - 1:
                    self.errors['general'].append(msg)
                    self.logger.error(msg)
                else:
                    self.logger.warn(msg)
                    time.sleep(1)
            except socket.error as e:
                msg = '{} {} socket error'. format(addr, proto)
                if i == self.retry - 1:
                    self.errors['general'].append(msg)
                    self.logger.error(msg)
                else:
                    self.logger.warn(msg)
                    time.sleep(1)
            else:
                if response.rcode() == dns.rcode.NOERROR:
                    if len(response.answer) < 1:
                        msg = '{} returned no answers for {}'.format(addr, self.zone)
                        if i == self.retry - 1:
                            self.errors['general'].append(msg)
                            self.logger.error(msg)
                        else:
                            self.logger.warn(msg)
                            time.sleep(1)
                    else:
                        return response.answer
                else:
                    msg = '{} returned {} for {} over {}'.format(
                        addr, dns.rcode.to_text(response.rcode()), self.zone, proto)
                    if i == self.retry - 1:
                        self.errors['general'].append(msg)
                        self.logger.error(msg)
                    else:
                        self.logger.warn(msg)
                        time.sleep(1)
        return None

    def set_master_soa(self):
        '''perform checks'''
        question = dns.message.make_query(self.zone, dns.rdatatype.SOA)
        answers = self.get_dns(self.soa_server)
        if answers:
            for answer in answers:
                if answer.rdtype == dns.rdatatype.SOA:
                    self.master_soa = answer.to_rdataset()[0]
        else:
            self.errors['master_soa'] = True

    def check_soa(self, soa):
        '''check the soa'''
        if self.master_soa:
            if soa.serial < (self.master_soa.serial - self.serial_lag):
                msg = 'serial is lagging. Expected {} recived {}'.format(
                        self.master_soa.serial, soa.serial)
                self.logger.warn(msg)
                master_date = datetime.strptime(str(self.master_soa.serial)[:8],
                        '%Y%m%d').date()
                soa_date = datetime.strptime(str(soa.serial)[:8],
                        '%Y%m%d').date()
                if soa_date < (master_date - timedelta(days=self.serial_lag)):
                    self.errors['soa'].append(msg)
            elif soa.serial > (self.master_soa.serial + self.serial_lag):
                msg = 'serial is ahead. Expected {} recived {}'.format(
                        self.master_soa.serial, soa.serial)
                self.logger.warn(msg)
                self.errors['master_soa'] = True
                self.errors['soa'].append(msg)

    def check_zone(self, addr, proto='udp'):
        '''check a zone on the specifid version and protocol'''
        question = dns.message.make_query(self.zone, dns.rdatatype.SOA)
        answers = self.get_dns(addr, proto)
        if answers:
            for answer in answers:
                if answer.rdtype == dns.rdatatype.SOA:
                    self.check_soa(answer.to_rdataset()[0])

    @staticmethod
    def have_ipv6_scop_local():
        '''check if the hst has a Global Scope ipv6 address'''
        with open('/proc/net/if_inet6') as f:
            for line in f.readlines():
                if line.split()[3] == '00':
                    return True
        return False
            
    def check(self):
        '''preform all checks'''
        if not self.errors['master_soa']:
            for proto in ['udp', 'tcp']:
                for i in xrange(self.retry):
                    try:
                        for addr_info in socket.getaddrinfo(
                                self.server, 0, 0, 0, socket.SOL_TCP):
                            if addr_info[0] == 10 and not self.have_ipv6_scop_local():
                                #only check v6 if we have a global v6 address
                                continue
                            self.check_zone(addr_info[4][0], proto)
                    except socket.gaierror as e:
                        msg = 'could not get address for {}: {}'.format(
                                self.server, e)
                        if i == self.retry - 1:
                            self.errors['general'].append(msg)
                            self.logger.error(msg)
                        else:
                            self.logger.warn(msg)
                            time.sleep(1)


