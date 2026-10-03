import io
import ipaddress
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import camsweep as c

class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.network=c.Network('192.168.4.20','192.168.4.0/23','en0','192.168.4.1','001122334455')
        self.net=ipaddress.IPv4Network(self.network.subnet)

    def test_real_netmask_not_assumed_24(self):
        n=c.parse_mac_interface('ether 0:11:22:33:44:55\n inet 192.168.4.20 netmask 0xfffffe00 broadcast 192.168.5.255','en0','192.168.4.1')
        self.assertEqual(n.subnet,'192.168.4.0/23')
        self.assertEqual(n.mac,'001122334455')

    def test_neighbors_exclude_other_network_interface_and_broadcast(self):
        text='''? (192.168.4.5) at 3c:a0:70:1:2:3 on en0 ifscope
? (10.0.0.2) at 3c:a0:70:1:2:4 on en0
? (192.168.4.6) at 3c:a0:70:1:2:5 on en1
? (192.168.4.8) at (incomplete) on en0
? (192.168.5.255) at ff:ff:ff:ff:ff:ff on en0'''
        self.assertEqual(c.parse_neighbors(text,self.net,'en0'),{'192.168.4.5':'3CA070010203'})

    def test_windows_and_linux_neighbors(self):
        self.assertEqual(c.parse_neighbors('192.168.4.5 3c-a0-70-01-02-03 dynamic',self.net),{'192.168.4.5':'3CA070010203'})
        self.assertEqual(c.parse_neighbors('192.168.4.5 dev eth0 lladdr 3c:a0:70:01:02:03 STALE',self.net,'eth0'),{'192.168.4.5':'3CA070010203'})

    def test_ping_only_device_shown_and_cache_not_claimed_live(self):
        macs={'192.168.4.5':'3CA070010203'}
        rows=c.assemble_rows(self.network,self.net,macs,macs,{'192.168.4.9':True},{},c.CAM_OUI)
        by_ip={r['ip']:r for r in rows}
        self.assertEqual(by_ip['192.168.4.9']['state'],'responding')
        self.assertEqual(by_ip['192.168.4.5']['state'],'cached/unconfirmed')
        self.assertIn('may be a hub',by_ip['192.168.4.5']['verdict'])
        self.assertEqual(by_ip[self.network.ip]['verdict'],'THIS COMPUTER')

    def test_refused_tcp_and_new_neighbor_are_discovery_evidence(self):
        rows=c.assemble_rows(self.network,self.net,{}, {'192.168.4.5':'3CA070010203'}, {}, {'192.168.4.9':({},True)},c.CAM_OUI)
        by_ip={r['ip']:r for r in rows}
        self.assertEqual(by_ip['192.168.4.9']['state'],'responding')
        self.assertIn('new neighbor entry',by_ip['192.168.4.5']['evidence'])

    def test_actual_timeout_reaches_every_port_probe(self):
        with patch.object(c,'probe',return_value=(False,True)) as probe:
            ports,alive=c.scan_host('192.168.4.9',.15)
        self.assertTrue(alive)
        self.assertEqual(ports,{})
        self.assertTrue(all(call.args[2]==.15 for call in probe.call_args_list))

    def test_refused_connection_is_not_open_port(self):
        with patch.object(c.socket,'socket') as sock:
            sock.return_value.__enter__.return_value.connect_ex.return_value=c.errno.ECONNREFUSED
            self.assertEqual(c.probe('192.168.4.9',554,.2),(False,True))

    def test_local_mac_not_misidentified_as_vendor(self):
        self.assertEqual(c.vendor_for('021122334455',{'021122':'Made up camera'}),'private/local MAC')
        self.assertEqual(c.normalized_mac('ff:ff:ff:ff:ff:ff'),'')

    def test_no_arguments_uses_detected_subnet(self):
        with patch.object(c,'detect_network',return_value=self.network), patch.object(c,'sweep',return_value=([],[])) as sweep, patch('sys.stdout',new_callable=io.StringIO):
            result=c.main([])
        self.assertEqual(result['subnet'],'192.168.4.0/23')
        self.assertEqual(sweep.call_args.args[1],self.net)

    def test_invalid_timeouts_and_outside_subnet_rejected_before_scan(self):
        for value in ['nan','inf','0','-1','11']:
            with self.assertRaises(c.argparse.ArgumentTypeError): c.positive_timeout(value)
        with patch.object(c,'detect_network',return_value=self.network),patch.object(c,'sweep') as sweep:
            with self.assertRaises(RuntimeError):c.main(['--subnet','10.0.0.0/24'])
            sweep.assert_not_called()


class LabelTests(unittest.TestCase):
    def test_saved_camera_label_does_not_change_liveness_or_scanner_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'labels.json'
            p.write_text('{"version":1,"devices":{"B4107AD7E17E":{"name":"My camera","source":"prior test"}}}')
            rows=[{'mac':'B4107AD7E17E','state':'cached/unconfirmed','verdict':'CHECK'}]
            c.apply_saved_labels(rows,p)
            self.assertEqual(rows[0]['label'],'My camera')
            self.assertEqual(rows[0]['state'],'cached/unconfirmed')
            self.assertEqual(rows[0]['verdict'],'CHECK')

if __name__=='__main__':unittest.main()
