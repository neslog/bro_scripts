event sysmonProcNetConn(loghost: string, proto: string, srcip: string, srcprt: string, dstip: string, dstprt: string, procId: string, procImage: string)
#event sysmon(data: string, dstip: string, srcip: addr, srcprt: string, dstip: string, dstprt: string, procId: int, procImage: string)
{
#print loghost,proto,srcip,srcprt,dstip,dstprt,procId,procImage;
  local srcAddr = to_addr(srcip);
  local srcport =  to_port(string_cat(srcprt,"/",proto));
  local dstAddr = to_addr(dstip);
  local dstport =  to_port(string_cat(dstprt,"/",proto));

print "srcAddr:srcport==>dstAddr:dstport";
}

event bro_init()
{
Broker::subscribe("/sysmon");
}
