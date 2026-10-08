import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from analyze import analyze, parse_traces, clone_has_flag

class CloneFlagTests(unittest.TestCase):
    def test_clone3_numeric_flags_are_decoded(self):
        args='{flags=0x10400, exit_signal=SIGCHLD}'
        self.assertTrue(clone_has_flag(args,'CLONE_FILES'))
        self.assertTrue(clone_has_flag(args,'CLONE_THREAD'))
        self.assertFalse(clone_has_flag('{flags=0x400}', 'CLONE_THREAD'))
        self.assertTrue(clone_has_flag('{flags=CLONE_FILES, exit_signal=SIGCHLD}', 'CLONE_FILES'))

class TraceTests(unittest.TestCase):
    def test_socket_endpoint_arrows_are_not_annotation_terminators(self):
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory)
            endpoint='TCP:[127.0.0.1:1234->127.0.0.1:5678]'
            (d/'strace.100').write_text(
                f'1.000001 read(4<{endpoint}>, "payload > /tmp/not-a-path", 64) = 23\n'
                '1.000002 read(5<TCPv6:[[::1]:1234->[::1]:5678]>, "x", 1) = 1\n')
            events,quality=parse_traces(d)
            self.assertEqual(events[0]['paths'],[endpoint])
            self.assertEqual(events[1]['paths'],['TCPv6:[[::1]:1234->[::1]:5678]'])

    def test_message_syscalls_keep_fd_annotation_not_payload_path(self):
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory)
            calls=['sendto','recvfrom','sendmsg','recvmsg']
            (d/'strace.100').write_text(''.join(
                f'1.00000{i} {call}(3<(null):[11->12]>, "payload /tmp/not-resource", 64, 0) = 25\n'
                for i,call in enumerate(calls,1)))
            events,_=parse_traces(d)
            self.assertEqual(len(events),4)
            self.assertTrue(all(e['paths']==['(null):[11->12]'] for e in events))

    def test_threads_children_resumed_and_payload_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d/'strace.100').write_text(
                '10.000001 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 101\n'
                '10.000002 clone(child_stack=NULL, flags=SIGCHLD) = 102\n')
            (d/'strace.101').write_text(
                '10.000003 openat(AT_FDCWD, "/tmp/fixture", O_RDONLY <unfinished ...>\n'
                '10.000005 <... openat resumed>) = 7</tmp/fixture> <0.000002>\n'
                '10.000006 read(7</tmp/fixture>, "payload /tmp/other", 64) = 18 <0.000001>\n'
                '10.000007 write(1<pipe:[123]>, "/tmp/fixture", 12) = 12\n')
            (d/'strace.102').write_text('10.000008 close(3</tmp/child>) = 0\n')
            events, quality = parse_traces(d)
            self.assertEqual(quality['rejoined'], 1)
            self.assertEqual(events[2]['timestamp_ns'], 10000003000)
            self.assertEqual(events[2]['pid'], 100)
            self.assertEqual(events[3]['paths'], ['/tmp/fixture'])
            self.assertEqual(events[4]['paths'], ['pipe:[123]'])
            self.assertEqual(events[5]['pid'], 102)

class ReturnTests(unittest.TestCase):
    def test_interrupted_and_pointer_return(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)
            (path/'strace.10').write_text(
                '1.000001 read(4<pipe:[42]>, 0xffffee, 4) = ? ERESTARTSYS (To be restarted) <0.001>\n'
                '1.000002 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, -1, 0) = 0xffff0000\n')
            events,quality=parse_traces(path)
            self.assertIsNone(events[0]['return_value'])
            self.assertEqual(events[0]['completion'],'restart')
            self.assertEqual(events[1]['return_value'],0xffff0000)
            self.assertFalse(quality.get('unparsed'))

    def test_blocked_syscall_at_explicit_tracee_termination_is_not_capture_truncation(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)
            (path/'strace.10').write_text(
                '1.000001 epoll_pwait(4<anon_inode:[eventpoll]>,  <unfinished ...>) = ?\n'
                '1.500000 +++ killed by SIGTERM +++\n')
            events,quality=parse_traces(path)
            self.assertEqual(events,[])
            self.assertEqual(quality['terminal_interrupted'],1)
            self.assertFalse(quality.get('incomplete_at_eof'))

class OracleTests(unittest.TestCase):
    def test_shared_paths_remove_labels_without_changing_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run/'traces').mkdir()
            path = str(run/'sandbox/a.txt')
            (run/'traces/strace.100').write_text(
                '1.000000 execve("/bin/node", ["node", "server-filesystem/dist/index.js"], []) = 0\n'
                f'1.500000 openat(AT_FDCWD, "{path}", O_RDONLY) = 7<{path}>\n')
            def evaluate(second_path):
                rows = [dict(wall_ns=1_100_000_000, direction='request', message={
                    'id':i, 'method':'tools/call', 'params':{'name':'read_text_file',
                    'arguments':{'path':p}}}) for i,p in [(1,path),(2,second_path)]]
                rows += [dict(wall_ns=1_900_000_000, direction='response',
                              message={'id':i,'result':{}}) for i in [1,2]]
                (run/'protocol.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
                with contextlib.redirect_stdout(io.StringIO()): report=analyze(run)
                event=json.loads((run/'attribution.jsonl').read_text())
                return report,event
            unique,u=evaluate(str(run/'sandbox/b.txt'))
            shared,s=evaluate(path)
            self.assertEqual(unique['oracle_labelled'],1)
            self.assertEqual(shared['oracle_labelled'],0)
            self.assertEqual(u['candidates'],s['candidates'])
            self.assertEqual(s['candidates']['request_window'],[1,2])

if __name__ == '__main__': unittest.main()

class CompletionTimeTests(unittest.TestCase):
    def test_blocked_receive_completion_follows_send_despite_entry_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'strace.10').write_text(
                '1.000000 recvmsg(4<UNIX:[2->1]>,  <unfinished ...>\n'
                '1.003000 <... recvmsg resumed>{msg_flags=0}, 0) = 1 <0.003000>\n'
                '1.004000 read(4<UNIX:[2->1]>, "x", 1) = 1\n'
                '1.005000 read(4<UNIX:[2->1]>, 0xffff, 1) = ? ERESTARTSYS <0.000100>\n')
            (root/'strace.11').write_text(
                '1.002000 sendmsg(3<UNIX:[1->2]>, {msg_flags=0}, 0) = 1 <0.000100>\n')
            events, _ = parse_traces(root)
            receive, send, untimed, interrupted = events
            self.assertLess(receive['timestamp_ns'], send['timestamp_ns'])
            self.assertEqual(receive['duration_ns'], 3000000)
            self.assertGreater(receive['completion_ns'], send['completion_ns'])
            self.assertIsNone(untimed['duration_ns'])
            self.assertIsNone(untimed['completion_ns'])
            self.assertEqual(interrupted['duration_ns'], 100000)
            self.assertIsNone(interrupted['completion_ns'])

class DescriptorRightsTests(unittest.TestCase):
    def test_ancillary_descriptors_are_observations_not_file_data_access(self):
        from analyze import descriptor_rights
        args = '3<UNIX:[1->2]>, {msg_iov=[{iov_base="payload", iov_len=7}], msg_control=[{cmsg_len=24, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[4</tmp/a>, 5</tmp/b>]}], msg_flags=0}, 0'
        rights = descriptor_rights('sendmsg', args, 7)
        self.assertEqual(rights['fds'], [4, 5])
        self.assertTrue(rights['decoded'])
        self.assertTrue(rights['succeeded'])
        self.assertFalse(rights['control_truncated'])
        self.assertEqual(rights['direction'], 'send')
        failed = descriptor_rights('sendmsg', args, -1)
        self.assertFalse(failed['succeeded'])
        truncated = descriptor_rights('recvmsg', args.replace('msg_flags=0', 'msg_flags=MSG_CTRUNC'), 7)
        self.assertTrue(truncated['control_truncated'])
        self.assertEqual(truncated['direction'], 'receive')
        malformed = descriptor_rights('recvmsg', args.replace('4</tmp/a>, 5</tmp/b>', '4</tmp/a>, ...'), 7)
        self.assertFalse(malformed['decoded'])
        self.assertEqual(malformed['fds'], [])

    def test_payload_cannot_forge_ancillary_control(self):
        from analyze import descriptor_rights
        payload = '{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[99]}'
        args = '3<UNIX:[1->2]>, {msg_iov=[{iov_base=' + json.dumps(payload) + ', iov_len=100}], msg_control=[], msg_flags=0}, 0'
        self.assertIsNone(descriptor_rights('recvmsg', args, 100))
        self.assertIsNone(descriptor_rights('read', payload, 100))
