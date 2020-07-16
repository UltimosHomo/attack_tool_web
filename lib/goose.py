from scapy.all import *
from scapy.layers.ntp import TimeStampField
import datetime
from binascii import unhexlify


def num2str(num):
    bytestring = bytearray()
    if num // 256 // 256 // 256 // 256 % 256 > 0:
        bytestring.append(num // 256 // 256 // 256 // 256 % 256)
    if num // 256 // 256 // 256 % 256 > 0:
        bytestring.append(num // 256 // 256 // 256 % 256)
    if num // 256 // 256 % 256 > 0:
        bytestring.append(num // 256 // 256 % 256)
    if num // 256 % 256 > 0:
        bytestring.append(num // 256 % 256)
    bytestring.append(num % 256)
    return bytestring


class GooseHeader(Packet):
    name = "Goose Header"
    fields_desc = [ShortField("appid", 1),
                   ShortField("length", 0),
                   ShortField("reserved1", None),
                   ShortField("reserved2", None)]


class GoosePDU(Packet):
    name = "Goose PDU"
    fields_desc = [ByteField("sequence_t", 0x61),
                   ConditionalField(ByteField("sequence_el", 0x81), lambda pkt: pkt.sequence_l > 127),
                   ByteField("sequence_l", 0),
                   ByteField("gocbRef_t", 0x80),
                   FieldLenField("gocbRef_l", None, length_of="gocbRef", fmt="B"),
                   StrLenField("gocbRef", None, length_from=lambda pkt:pkt.gocbRef_l),
                   ByteField("timeAllowedtoLive_t", 0x81),
                   FieldLenField("timeAllowedtoLive_l", None, length_of="timeAllowedtoLive", fmt="B"),
                   StrLenField("timeAllowedtoLive", None, length_from=lambda pkt:pkt.timeAllowedtoLive_l),
                   ByteField("datSet_t", 0x82),
                   FieldLenField("datSet_l", None, length_of="datSet", fmt="B"),
                   StrLenField("datSet", None, length_from=lambda pkt: pkt.datSet_l),
                   ByteField("goID_t", 0x83),
                   FieldLenField("goID_l", None, length_of="goID", fmt="B"),
                   StrLenField("goID", None, length_from=lambda pkt: pkt.goID_l),
                   ByteField("T_t", 0x84),
                   ByteField("T_l", 8),
                   TimeStampField("T", None),
                   ByteField("stNum_t", 0x85),
                   FieldLenField("stNum_l", None, length_of="stNum", fmt="B"),
                   StrLenField("stNum", None, length_from=lambda pkt: pkt.stNum_l),
                   ByteField("sqNum_t", 0x86),
                   FieldLenField("sqNum_l", None, length_of="sqNum", fmt="B"),
                   StrLenField("sqNum", None, length_from=lambda pkt: pkt.sqNum_l),
                   ByteField("simulation_t", 0x87),
                   ByteField("simulation_l", 1),
                   ByteField("simulation", None),
                   ByteField("confRev_t", 0x88),
                   FieldLenField("confRev_l", None, length_of="confRev", fmt="B"),
                   StrLenField("confRev", None, length_from=lambda pkt: pkt.confRev_l),
                   ByteField("ndsCom_t", 0x89),
                   ByteField("ndsCom_l", 1),
                   ByteField("ndsCom", None),
                   ByteField("numDatSetEntries_t", 0x8a),
                   FieldLenField("numDatSetEntries_l", None, length_of="numDatSetEntries", fmt="B"),
                   StrLenField("numDatSetEntries", None, length_from=lambda pkt: pkt.numDatSetEntries_l)
                   ]


def ref620_trip():
    ethernet_mac = Ether(src='00:21:c1:50:52:95', dst='01:0c:cd:01:00:00',type=0x88b8)
    vlan = Dot1Q(type=0x88b8, prio=4, id=0, vlan=99)
    goose_pdu = GoosePDU(gocbRef="ABBREF620LD0/LLN0$GO$gcbTRIP",
                         timeAllowedtoLive=num2str(11000),
                         datSet="ABBREF620LD0/LLN0$TRIP",
                         goID="ABBREF620LD0/LLN0.gcbTRIP",
                         T=datetime.datetime.now(datetime.timezone.utc).timestamp(),
                         stNum=num2str(1),
                         sqNum=num2str(1),
                         simulation=0,
                         confRev=num2str(1),
                         ndsCom=0,
                         numDatSetEntries=num2str(1)
                         )
    goose_data = unhexlify("ab088301018403030000")
    goose_pdu.sequence_l = (len(goose_pdu)+len(goose_data)-2)
    goose_header = GooseHeader(length=len(goose_pdu)+len(goose_data))
    goose_packet = ethernet_mac/goose_header/goose_pdu/goose_data
    sendp(goose_packet, iface="Intel(R) Ethernet Connection (4) I219-V")
    return "DONE"


if __name__ == '__main__':
    print("GOOSE packet for Scapy by Sever Sudakov")
    ref620_trip()

