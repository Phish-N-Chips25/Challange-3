"""Probe OTRF atomic _metadata YAML files to build a ZIP -> T-code mapping."""
import yaml
from pathlib import Path
from collections import Counter

meta_dir       = Path(r'h:\Challenge-3-4\OTRF\datasets\atomic\_metadata')
atomic_windows = Path(r'h:\Challenge-3-4\OTRF\datasets\atomic\windows')

# All local Windows ZIP basenames
local_zips = {zp.name: zp for zp in atomic_windows.rglob('*.zip')}
print(f'Local Windows ZIPs       : {len(local_zips)}')
print(f'YAML metadata files      : {len(list(meta_dir.glob("SDWIN*.yaml")))}')

zip_to_tcode: dict[str, str] = {}
yaml_no_match: list[tuple] = []

for yaml_file in sorted(meta_dir.glob('SDWIN*.yaml')):
    with open(yaml_file, encoding='utf-8') as f:
        try:
            doc = yaml.safe_load(f)
        except Exception as e:
            print(f'  Parse error {yaml_file.name}: {e}')
            continue

    mappings = doc.get('attack_mappings', [])
    if not mappings:
        continue

    m         = mappings[0]
    technique = str(m.get('technique', ''))
    sub       = m.get('sub-technique', '')
    tcode     = f'{technique}.{str(sub).zfill(3)}' if sub else technique

    files   = doc.get('files', [])
    matched = False
    for fentry in files:
        link     = fentry.get('link', '')
        zip_name = link.rsplit('/', 1)[-1]
        if zip_name in local_zips:
            zip_to_tcode[zip_name] = tcode
            matched = True

    if not matched and files:
        zip_names = [fe.get('link', '').rsplit('/', 1)[-1] for fe in files]
        yaml_no_match.append((yaml_file.name, tcode, zip_names))

print(f'\nMatched ZIPs -> T-code   : {len(zip_to_tcode)}')
print(f'YAML with no local ZIP   : {len(yaml_no_match)}')
print(f'Local ZIPs without T-code: {len(local_zips) - len(zip_to_tcode)}')

tcode_counts = Counter(zip_to_tcode.values())
print(f'\nUnique T-codes covered   : {len(tcode_counts)}')
print('\nTop T-codes by ZIP count:')
for tcode, count in tcode_counts.most_common(20):
    print(f'  {tcode:15s}: {count} ZIPs')

print('\nSample zip -> tcode:')
for k, v in list(zip_to_tcode.items())[:10]:
    print(f'  {v:12s} <- {k}')

if yaml_no_match:
    print(f'\nSample unmatched YAMLs (ZIP not downloaded locally):')
    for name, tcode, zips in yaml_no_match[:5]:
        print(f'  {name}: {tcode} -> {zips}')
