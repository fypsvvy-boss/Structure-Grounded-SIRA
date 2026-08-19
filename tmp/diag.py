import json
b = json.load(open('data/raw/attack/enterprise-attack.json'))
objs = b['objects']
by_stix = {o['id']: o for o in objs}

tgt = by_stix['attack-pattern--bbde9781-60aa-4b8a-a911-895b0c1b3872']
ext = [r.get('external_id') for r in tgt.get('external_references', [])
       if r.get('source_name') == 'mitre-attack']
print('replacement:', ext, '|', tgt.get('name'), '| revoked:', tgt.get('revoked'))

orphans = ['T1053.001', 'T1070.001', 'T1070.002', 'T1547.011']
orphans += ['T1562.%03d' % i for i in (1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13)]

print('')
print('--- orphan statuses ---')
for o in objs:
    for r in o.get('external_references') or []:
        if r.get('external_id') in orphans:
            print('%-12s revoked=%s deprecated=%s' % (
                r['external_id'], bool(o.get('revoked')), bool(o.get('x_mitre_deprecated'))))

print('')
print('--- collection version ---')
for o in objs:
    if o.get('type') == 'x-mitre-collection':
        print(o.get('name'), o.get('x_mitre_version'))