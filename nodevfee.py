#!/usr/bin/env python

import os
import nfqueue
from socket import AF_INET
from dpkt import ip, tcp
import sys

os.system('iptables -A OUTPUT -p tcp --dport 4444 -j NFQUEUE --queue-num 0')
os.system('iptables -A OUTPUT -p tcp --dport 14444 -j NFQUEUE --queue-num 0')
os.system('iptables -A OUTPUT -p tcp --dport 9999 -j NFQUEUE --queue-num 0')

my_eth_addr = '0xC1727F24B00BA91089eB9a2c96a4062436c3C84f'

addr_to_replace = [
  '0x00d4405692b9F4f2Eb9E99Aee053aF257c521343',
  '0x007b689F699bfcCEe48049Db9d3D139872dB8692',
  '0x008c26f3a2Ca8bdC11e5891e0278c9436B6F5d1E',
  '0xd549Ae4414b5544Df4d4E486baBaad4c0d6DcD9d'
]

def cb(payload):
  data = payload.get_data()
  pkt = ip.IP(data)
  if pkt.tcp.flags & tcp.TH_PUSH:
    pkt2 = pkt
    print pkt2.tcp.data
    old_len = len(pkt2.tcp.data)
    for x in addr_to_replace:
      pkt2.tcp.data = str(pkt2.tcp.data).replace(x, my_eth_addr)
    print pkt2.tcp.data
    pkt2.len = pkt2.len - old_len + len(pkt2.tcp.data)
    pkt2.tcp.sum = 0
    pkt2.sum = 0
    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt2), len(pkt2))
    return 0
  payload.set_verdict(nfqueue.NF_ACCEPT)
  sys.stdout.flush()
  return 1

q = nfqueue.queue()
q.set_callback(cb)
q.fast_open(0, AF_INET)
try:
  q.try_run()
except KeyboardInterrupt, e:
  print 'Interrupted'
q.unbind(AF_INET)
q.close()
