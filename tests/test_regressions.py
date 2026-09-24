import copy
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import knx_config as config
import knx_events as events
from knx_manager import Selection, Endpoint
from knx_discovery import parse_search
from knx_const import make_frame, make_hpai, SEARCH_RESP, DESCRIPTION_RESP
from knx_const import (CONNECT_REQ, CONNECT_RESP, TUNNELLING_REQ, DISCONNECT_REQ,
                       CONNSTATE_REQ, CONNSTATE_RESP, parse_frame, read_tcp_frame)
from knx_health import probe_description_tcp, probe_description_udp
from knx_proxy import KNXProxy
from knx_session import Session
from knx_session import SessionManager
from knx_transport import BackendConnector
from knx_usb import KNXUSBBridge
import knx_webui as web


def interface(ident='one', role='fallback', kind='ip'):
    item = dict(id=ident, name=ident, role=role, type=kind)
    item.update(dict(host='192.168.1.2', port=3671, protocol='udp') if kind == 'ip'
                else dict(device='/dev/bus/usb/001/002', mode='native'))
    return item


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for key, filename in [('CONFIG_FILE', 'flappy.json'), ('OPTIONS_FILE', 'options.json')]:
            patcher = patch.object(config, key, str(Path(self.tmp.name) / filename))
            patcher.start(); self.addCleanup(patcher.stop)
        Path(config.OPTIONS_FILE).write_text(json.dumps({'primary_host':'192.168.1.2'}))

    def test_migration_preserves_passwords_and_usb_priority(self):
        cfg = config.migrate(dict(primary_host='a', backup_host='b', primary_secure=True,
                                  primary_user_password='secret', usb_device='auto', usb_priority='prefer'))
        self.assertEqual([i['id'] for i in cfg['interfaces']], ['usb','primary','backup'])
        self.assertEqual(cfg['interfaces'][1]['user_password'], 'secret')
        self.assertTrue(cfg['interfaces'][1]['secure'])

    def test_ui_save_survives_supervisor_options_replacement(self):
        cfg = config.load_config(); cfg['interfaces'][0]['host']='192.168.1.3'
        saved = config.save_config(cfg)
        Path(config.OPTIONS_FILE).write_text('{}')
        self.assertEqual(config.load_config()['interfaces'][0]['host'], '192.168.1.3')
        self.assertEqual(saved['revision'], 1)
        backup=Path(config.CONFIG_FILE+'.legacy-options.json')
        self.assertEqual(json.loads(backup.read_text())['primary_host'],'192.168.1.2')

    def test_stale_revision_rejected_without_changing_file(self):
        cfg = config.load_config(); config.save_config(cfg)
        before = Path(config.CONFIG_FILE).read_bytes()
        with self.assertRaises(RuntimeError): config.save_config(cfg)
        self.assertEqual(before, Path(config.CONFIG_FILE).read_bytes())

    def test_atomic_failure_preserves_last_good_file(self):
        saved = config.save_config(config.load_config())
        before = Path(config.CONFIG_FILE).read_bytes()
        with patch.object(config.os, 'replace', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError): config.save_config(saved)
        self.assertEqual(before, Path(config.CONFIG_FILE).read_bytes())

    def test_duplicate_endpoint_and_boolean_integer_rejected(self):
        cfg=config.migrate({'interfaces':[interface(),interface('two')]})
        with self.assertRaises(ValueError): config.validate(cfg)
        cfg=config.migrate({'interfaces':[],'listen_port':True})
        with self.assertRaises(ValueError): config.validate(cfg)

    def test_multiple_explicit_usb_and_ip_are_accepted(self):
        one,two=interface('a',kind='usb'),interface('b',kind='usb')
        two['device']='/dev/bus/usb/001/003'
        config.validate(config.migrate({'interfaces':[one,two,interface('ip')]}))

    def test_ambiguous_auto_usb_rejected(self):
        one=interface('a',kind='usb');one['device']='auto'
        with self.assertRaises(ValueError):
            config.validate(config.migrate({'interfaces':[one,interface('b',kind='usb')]}))

    def test_monitor_limit(self):
        items=[]
        for n in range(5):
            i=interface(str(n),'monitor');i.update(host=f'192.168.1.{n+10}',telegrams=True);items.append(i)
        with self.assertRaises(ValueError): config.validate(config.migrate({'interfaces':items}))

    def test_unsupported_schema_is_not_silently_downgraded(self):
        with self.assertRaises(ValueError): config.migrate({'schema_version':99})

    def test_duplicate_usb_identity_and_knxd_address_ranges_rejected(self):
        first,second=interface('a',kind='usb'),interface('b',kind='usb')
        second['device']='/dev/bus/usb/001/003'
        first['serial']=second['serial']='same-device'
        with self.assertRaises(ValueError):config.validate(config.migrate({'interfaces':[first,second]}))
        first.pop('serial');second.pop('serial')
        for item in (first,second):
            item.update(mode='knxd',knx_address='1.1.1',client_address='1.1.20')
        with self.assertRaises(ValueError):config.validate(config.migrate({'interfaces':[first,second]}))

    def test_http_save_redacts_and_preserves_secrets(self):
        cfg=config.load_config();cfg['interfaces'][0]['user_password']='hidden secret'
        config.save_config(cfg)
        server=web.ThreadedHTTPServer(('127.0.0.1',0),web.APIHandler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        url=f'http://127.0.0.1:{server.server_port}/api/config'
        with urllib.request.urlopen(url) as r: public=json.load(r)
        self.assertNotIn('hidden secret',json.dumps(public))
        self.assertTrue(public['interfaces'][0]['user_password_set'])
        req=urllib.request.Request(url,json.dumps(public).encode(),{'Content-Type':'application/json'})
        with urllib.request.urlopen(req) as r: result=json.load(r)
        self.assertTrue(result['persisted'])
        self.assertEqual(config.load_config()['interfaces'][0]['user_password'],'hidden secret')
        with self.assertRaises(urllib.error.HTTPError) as cm: urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code,409)
        cm.exception.close()


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.entries=[interface('usb',kind='usb'),interface('ip'),interface('monitor','monitor')]
        self.states={i['id']:{'healthy':True} for i in self.entries}
        self.policy=Selection()
    def choose(self,t=0,mode='auto',manual=None):
        return self.policy.choose(self.entries,self.states,t,mode,10,manual)
    def test_usb_primary_ip_backup_monitor_excluded(self):
        self.assertEqual(self.choose(),'usb')
        self.states['usb']['healthy']=False
        self.assertEqual(self.choose(),'ip')
        self.states['ip']['healthy']=False
        self.assertIsNone(self.choose())
    def test_recovery_must_be_continuously_stable(self):
        self.states['usb']['healthy']=False;self.choose()
        self.states['usb']['healthy']=True;self.assertEqual(self.choose(1),'ip')
        self.states['usb']['healthy']=False;self.choose(9)
        self.states['usb']['healthy']=True;self.assertEqual(self.choose(10),'ip')
        self.assertEqual(self.choose(19),'ip');self.assertEqual(self.choose(20),'usb')
    def test_zero_failback_delay_still_has_stability_guard(self):
        self.states['usb']['healthy']=False
        self.assertEqual(self.policy.choose(self.entries,self.states,0,'auto',0),'ip')
        self.states['usb']['healthy']=True
        self.assertEqual(self.policy.choose(self.entries,self.states,0.1,'auto',0),'ip')
        self.assertEqual(self.policy.choose(self.entries,self.states,2.9,'auto',0),'ip')
        self.assertEqual(self.policy.choose(self.entries,self.states,3.1,'auto',0),'usb')

    def test_manual_and_disabled_stay_but_still_fail_over(self):
        for mode in ('manual','disabled'):
            self.policy=Selection();self.states['usb']['healthy']=False;self.choose(mode=mode)
            self.states['usb']['healthy']=True
            self.assertEqual(self.choose(100,mode),'ip')
            self.assertEqual(self.choose(101,mode,manual='monitor'),'ip')
            self.assertEqual(self.choose(102,mode,manual='usb'),'usb')


class ProtocolTests(unittest.TestCase):
    def test_discovery_rejects_truncated_or_invalid_dib(self):
        valid=make_frame(SEARCH_RESP,make_hpai('192.168.1.2',3671)+b'\x04\x02\x04\x01')
        self.assertTrue(parse_search(valid,('192.168.1.2',3671))['tunnelling'])
        self.assertIsNone(parse_search(valid[:-1],('192.168.1.2',3671)))
        self.assertIsNone(parse_search(make_frame(SEARCH_RESP,make_hpai('1.2.3.4',3671)+b'\0\1'),('1.2.3.4',3671)))
    def test_fragmented_tcp_description(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen()
        self.addCleanup(listener.close)
        response=make_frame(DESCRIPTION_RESP,b'\x04\x02\x04\x01')
        def serve():
            with listener.accept()[0] as sock:
                sock.recv(1024)
                for b in response: sock.sendall(bytes([b]))
        t=threading.Thread(target=serve);t.start()
        self.assertTrue(probe_description_tcp('127.0.0.1',listener.getsockname()[1],2).ok)
        t.join(3)
    def test_udp_probe_requires_knx_response(self):
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0))
        self.addCleanup(server.close)
        def serve():
            _,addr=server.recvfrom(1024);server.sendto(b'not knx',addr)
        t=threading.Thread(target=serve);t.start()
        self.assertFalse(probe_description_udp('127.0.0.1',server.getsockname()[1],1).ok);t.join(2)
    def test_connector_socket_handoff_is_thread_local(self):
        connector=BackendConnector();barrier=threading.Barrier(2);results=[]
        def run(value):
            connector._last_good_sock=value;barrier.wait();results.append(connector._last_good_sock==value)
        threads=[threading.Thread(target=run,args=(object(),)) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(results,[True,True])


class SwapTests(unittest.TestCase):
    def setUp(self):
        self.old=Mock();self.new=Mock()
        self.sess=Session(1,'udp',('ha',1),('ha',1),None,'udp',('old',3671),self.old)
        self.proxy=object.__new__(KNXProxy);self.proxy.connector=Mock()
        self.proxy.connector.open_socket.return_value=self.new
        self.proxy.connector._last_good_sock=None
        self.proxy._get_secure_config=Mock(return_value=(False,'','',1))
    def test_failed_swap_preserves_old_tunnel_and_secure_state(self):
        old_secure=object();self.sess._secure_session=old_secure
        self.proxy.connector.negotiate_tunnel.return_value=(None,None,0x24)
        with self.assertRaises(RuntimeError):self.proxy._hot_swap_backend(self.sess,'new',3671,'udp')
        self.assertIs(self.sess.backend_sock,self.old)
        self.assertIs(self.sess._secure_session,old_secure)
        self.old.send.assert_not_called();self.old.close.assert_not_called();self.new.close.assert_called_once()
    def test_success_preserves_client_channel_and_updates_backend_address(self):
        self.proxy.connector.negotiate_tunnel.return_value=(8,b'\x04\x04\x11\x22',0)
        self.sess._last_out_seq=254;self.sess._last_in_seq=12
        self.proxy._hot_swap_backend(self.sess,'new',3671,'udp')
        self.assertEqual(self.sess.channel_id,1);self.assertEqual(self.sess._backend_ch,8)
        self.assertEqual(self.sess._backend_ia,(17,34));self.assertEqual(self.sess._seq_out_offset,255)
        self.assertEqual(self.sess._seq_in_offset,13);self.assertIs(self.sess.backend_sock,self.new)
        self.old.close.assert_called_once()
    def test_stale_relay_does_not_reconnect_a_replaced_socket(self):
        self.proxy._hot_swap_backend(self.sess,'new',3671,'udp',expected_socket=object())
        self.proxy.connector.open_socket.assert_not_called()


class EventTests(unittest.TestCase):
    def test_history_survives_reopen(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(events,'DB',str(Path(tmp)/'events.sqlite3')):
            events.record('one','down','timeout');events.record('one','up','recovered')
            self.assertEqual([r['kind'] for r in events.recent()],['up','down'])


class NativeUSBTests(unittest.TestCase):
    """Exercise the real TCP bridge with a fake USB transport, without hardware."""
    def setUp(self):
        self.usb=Mock(individual_addr=(17,20),running=False)
        self.bridge=KNXUSBBridge(self.usb,0)
        self.assertTrue(self.bridge.start())
        self.addCleanup(self.bridge.stop)
        self.port=self.bridge.server_sock.getsockname()[1]
    def connect(self):
        sock=socket.create_connection(('127.0.0.1',self.port),2)
        self.addCleanup(sock.close)
        sock.sendall(make_frame(CONNECT_REQ,make_hpai('0.0.0.0',0,2)*2+b'\x04\x04\x02\0'))
        svc,body=read_tcp_frame(sock)
        self.assertEqual(svc,CONNECT_RESP)
        return sock,body
    def test_health_probe_does_not_evict_active_tunnel(self):
        client,body=self.connect();ch=body[0];self.assertEqual(body[1],0)
        for _ in range(3):
            self.assertTrue(probe_description_tcp('127.0.0.1',self.port,2).ok)
        client.sendall(make_frame(CONNSTATE_REQ,bytes([ch,0])+make_hpai('0.0.0.0',0,2)))
        self.assertEqual(read_tcp_frame(client),(CONNSTATE_RESP,bytes([ch,0])))
        self.assertEqual(self.bridge.active_channel,ch)
    def test_second_tunnel_rejected_without_displacing_first(self):
        client,body=self.connect();ch=body[0]
        _,second=self.connect();self.assertEqual(second[1],0x24)
        client.sendall(make_frame(CONNSTATE_REQ,bytes([ch,0])+make_hpai('0.0.0.0',0,2)))
        self.assertEqual(read_tcp_frame(client),(CONNSTATE_RESP,bytes([ch,0])))

    def test_retransmission_is_not_sent_to_bus_twice(self):
        client,body=self.connect();ch=body[0]
        frame=make_frame(TUNNELLING_REQ,bytes([4,ch,0,0])+b'\x11\0\xbc\xe0\0\0\0\1\1\0\x81')
        for _ in range(2):
            client.sendall(frame);self.assertEqual(read_tcp_frame(client)[1][3],0)
        self.assertEqual(self.usb.send_cemi.call_count,1)


class FakeGateway:
    def __init__(self,channel):
        self.channel=channel
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1',0));self.sock.settimeout(.2)
        self.address=self.sock.getsockname();self.peer=None;self.running=True
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while self.running:
            try:raw,addr=self.sock.recvfrom(4096)
            except socket.timeout:continue
            except OSError:return
            svc,body=parse_frame(raw)
            if svc==CONNECT_REQ:
                self.peer=addr
                self.sock.sendto(make_frame(CONNECT_RESP,bytes([self.channel,0])+
                    make_hpai(*self.address)+b'\x04\x04\x11\x21'),addr)
    def telegram(self,seq):
        self.sock.sendto(make_frame(TUNNELLING_REQ,bytes([4,self.channel,seq,0])+b'\x29\0'),self.peer)
    def close(self):
        self.running=False;self.sock.close();self.thread.join(1)


class RelayIntegrationTests(unittest.TestCase):
    def test_real_udp_relay_survives_switch_and_preserves_sequence(self):
        first,second=FakeGateway(7),FakeGateway(19)
        self.addCleanup(first.close);self.addCleanup(second.close)
        connector=BackendConnector(1)
        backend=connector.open_socket(*first.address,'udp')
        ch,_,_=connector.negotiate_tunnel(backend,*first.address,'udp')
        client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        client.bind(('127.0.0.1',0));client.settimeout(3);self.addCleanup(client.close)
        frontend=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.addCleanup(frontend.close)
        sess=Session(ch,'udp',client.getsockname(),client.getsockname(),None,'udp',first.address,backend)
        self.addCleanup(sess.close)
        proxy=object.__new__(KNXProxy);proxy.running=True;proxy.udp=Mock(sock=frontend)
        proxy.connector=connector;proxy.sessions=SessionManager();proxy.sessions.add(sess)
        proxy._get_secure_config=Mock(return_value=(False,'','',1))
        relay=threading.Thread(target=proxy._relay_from_backend,args=(sess,),daemon=True);relay.start()
        first.telegram(0);svc,body=parse_frame(client.recv(4096))
        self.assertEqual((svc,body[1],body[2]),(TUNNELLING_REQ,7,0))
        proxy._hot_swap_backend(sess,*second.address,'udp')
        second.telegram(0);svc,body=parse_frame(client.recv(4096))
        self.assertEqual((svc,body[1],body[2]),(TUNNELLING_REQ,7,1))
        self.assertTrue(sess.alive);self.assertEqual(proxy.sessions.active_count,1)
        proxy.running=False
        sess.backend_sock.shutdown(socket.SHUT_RDWR)
        sess.close();relay.join(2)
        self.assertFalse(relay.is_alive())


if __name__=='__main__':unittest.main()
