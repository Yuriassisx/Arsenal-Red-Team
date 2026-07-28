import json, sys
d = json.load(open(sys.argv[1]))
print(f"  -> {len(d)} achado(s)")
for x in d[:5]:
    print(f"     {x['detectors']} conf={x['confidence']} [{x['transform']}] "
          f"{x['base_payload'][:48]!r} => {x['evidence'][:60]}")
