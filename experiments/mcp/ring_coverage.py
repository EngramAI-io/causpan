"""Report ring observation scope without equating enter calls with I/O operations."""
from collections import Counter
import re


def ring_coverage(events,graph):
    operations=[n for n in graph if n['type']=='node' and n['kind']=='ring_operation']
    methods=Counter(n['evidence'] for n in operations)
    covered={n['syscall_evidence'] for n in operations}
    enters=[e for e in events if e['syscall']=='io_uring_enter']
    sources={e['source'] for e in enters}
    if not covered<=sources:raise ValueError('ring operation references absent enter')
    uncovered=[]
    for event in enters:
        if event['source'] in covered:continue
        match=re.match(r'\d+(?:<[^>]*>)?, (\d+), (\d+), ',event['args'])
        result=event.get('return_value')
        uncovered.append(dict(source=event['source'],pid=event.get('pid'),tid=event.get('tid'),
            requested_submissions=int(match[1]) if match else None,
            minimum_completions=int(match[2]) if match else None,
            accepted_submissions=result if type(result) is int and result>=0 else None))
    return dict(setup_attempts=sum(e['syscall']=='io_uring_setup' for e in events),
        successful_setups=sum(e['syscall']=='io_uring_setup' and e['return_value'] is not None and e['return_value']>=0 for e in events),
        enter_calls=len(enters),submissions_decoded=False,
        submissions_decoded_meaning='generic kernel submission decoding is unavailable',
        attributed_operations_by_evidence=dict(methods),
        enters_with_attributed_operations=len(covered),
        enters_without_attributed_operations=len(sources-covered),
        uncovered_enters=uncovered,
        observed_uncovered_accepted_submissions=sum(e['accepted_submissions'] or 0 for e in uncovered),
        completeness='Accepted submissions are syscall return counts, not decoded operations or completions; SQPOLL and other unobserved activity prevent a universal denominator.')
