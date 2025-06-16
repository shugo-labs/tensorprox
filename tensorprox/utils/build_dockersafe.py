#!/usr/bin/env python3
import hashlib, secrets, subprocess, pathlib, json, os
ROOT = pathlib.Path(os.path.expanduser("~/tensorprox"))
IMM  = ROOT/'tensorprox/core/immutable'
CLI  = IMM/'docker-cli'

sha = hashlib.sha256(CLI.read_bytes()).hexdigest()
tok = secrets.token_hex(16)

CFLAGS = [f'-DEXPECTED_DOCKER_HASH_MACRO="{sha}"',
          f'-DROUND_TOKEN_MACRO="{tok}"']

DOCKERSAFE_C = ROOT/'tensorprox/utils/dockersafe.c'
subprocess.check_call(['gcc','-static','-O2','-pipe','-s','-D_GNU_SOURCE',
                       *CFLAGS,str(DOCKERSAFE_C),'-lcrypto','-o','dockersafe'])

sh = subprocess.check_output(['sha256sum','dockersafe']).split()[0].decode()
json.dump({'token': tok, 'sha': sh}, open('meta.json','w'))
open('dockersafe.sha256','w').write(f"{sh}  dockersafe\n")
print(json.dumps({'token': tok, 'sha': sh}))