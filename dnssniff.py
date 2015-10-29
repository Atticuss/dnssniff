from scapy.all import *
import Queue, threading

class Listener(threading.Thread):
	def __init__(self,queue):
		threading.Thread.__init__(self)
		self.queue = queue
		self.die = False

	def run(self):
		while not self.die:
			sniff(prn=self.queue.put,filter="port 53",store=0,timeout=5)

domains = {}
pktQueue = Queue.Queue()

listener = Listener(pktQueue)
listener.start()

try:
	while True:
		if not pktQueue.empty():
			pkt = pktQueue.get()
			try:
				domains[pkt.getlayer('DNS').qd.qname] += 1
			except:
				domains[pkt.getlayer('DNS').qd.qname] = 1
				print('[*] New domain recorded: %s'%pkt.getlayer('DNS').qd.qname)
except KeyboardInterrupt:
	listener.die = True
	for k,v in domains.iteritems():
		print('%s: %s'%(k,v))