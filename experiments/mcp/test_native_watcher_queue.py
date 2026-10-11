import unittest
from native_watcher_queue import join

class WatcherQueueTests(unittest.TestCase):
    def test_repeated_pointer_is_new_episode(self):
        insert='WATCHER_ENQUEUE loop=1 watcher=2 fd=7 pevents=4 events=0'
        remove=insert.replace('ENQUEUE','DEQUEUE')
        result=join('\n'.join(['WATCHER_THREAD tid=101',insert,remove,insert,remove]))
        self.assertEqual(len(result['matches']),2)
        self.assertEqual(result['unmatched'],[])

    def test_missing_removal_and_changed_descriptor_are_explicit(self):
        lines=['WATCHER_THREAD tid=101',
               'WATCHER_ENQUEUE loop=1 watcher=2 fd=7 pevents=4 events=0',
               'WATCHER_ENQUEUE loop=1 watcher=2 fd=8 pevents=4 events=0',
               'WATCHER_DEQUEUE loop=1 watcher=2 fd=9 pevents=4 events=0']
        result=join('\n'.join(lines))
        self.assertEqual(result['matches'],[])
        self.assertEqual([x['reason'] for x in result['unmatched']],
                         ['replacement_without_observed_removal','descriptor_changed'])

    def test_update_while_queued_retains_second_context(self):
        import json
        def marker(context):
            return 'MARKER_WRITE '+json.dumps(dict(tid=101,marker=dict(kind='JS_CONTEXT',request=context)))
        lines=['WATCHER_THREAD tid=101',marker(1),
               'WATCHER_ENQUEUE loop=1 watcher=2 fd=7 pevents=4 events=0',marker(2),
               'WATCHER_UPDATE loop=1 watcher=2 fd=7 pevents=5 events=0',marker(0),
               'WATCHER_DEQUEUE loop=1 watcher=2 fd=7 pevents=5 events=0']
        episode=join('\n'.join(lines))['matches'][0]
        self.assertEqual(episode['insertion']['context'],1)
        self.assertEqual(episode['observed_updates'][0]['context'],2)
        self.assertFalse(episode['masks_unchanged'])

    def test_cancel_does_not_reach_later_removal(self):
        lines=['WATCHER_THREAD tid=101',
               'WATCHER_ENQUEUE loop=1 watcher=2 fd=7 pevents=4 events=0',
               'WATCHER_CANCEL loop=1 watcher=2 fd=7 pevents=0 events=0',
               'WATCHER_DEQUEUE loop=1 watcher=2 fd=7 pevents=4 events=0']
        result=join('\n'.join(lines))
        self.assertEqual(len(result['canceled']),1)
        self.assertEqual(result['matches'],[])
        self.assertEqual(result['unmatched'][0]['reason'],'no_observed_insertion')
