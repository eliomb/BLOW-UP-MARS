"""SSH key management + remote tcpdump streaming.
Local commands are argv lists (never a shell). Remote arguments are allow-listed AND shlex-quoted.
Private keys never leave DATA_DIR/keys and are never returned by any API or written to logs."""
import os, re, select, shlex, shutil, subprocess, tempfile, secrets, threading, time
import pcap

DATA = os.environ.get('DATA_DIR', '/data')
KEYS, KNOWN = os.path.join(DATA, 'keys'), os.path.join(DATA, 'known_hosts')
ENV = {'PATH': '/usr/bin:/bin', 'HOME': DATA, 'LANG': 'C'}
NAME, HOST = re.compile(r'[a-z0-9][a-z0-9_-]{0,31}'), re.compile(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}')
USER, IFACE = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}'), re.compile(r'[A-Za-z0-9_.:@-]{1,32}')
FILT = re.compile(r'[A-Za-z0-9 .:/()!=<>&|\[\]_,-]{0,200}')
KLINE = re.compile(r'\S+ (?:ssh-ed25519|ecdsa-sha2-nistp\d+|ssh-rsa) [A-Za-z0-9+/=]+')
PENDING = {}
# Remote wrapper (fd 3 preserves the real stdin: POSIX makes a background job's stdin /dev/null): keep the SSH session's stdin open and stop tcpdump when it closes (so a dropped link never leaves
# an orphaned tcpdump), and finish as soon as tcpdump itself exits, with its exit status.
WRAP = 'exec 3<&0; "$@" </dev/null 3<&- & p=$!; { cat <&3; kill $p; } >/dev/null 2>&1 & w=$!; exec 3<&-; wait $p; r=$?; kill $w 2>/dev/null; exit $r'

def init():
    os.umask(0o077); os.makedirs(KEYS, mode=0o700, exist_ok=True); os.chmod(KEYS, 0o700)
    if not os.path.exists(KNOWN): open(KNOWN, 'a').close()
    os.chmod(KNOWN, 0o600)

def run(cmd, timeout=20, inp=None):
    r = subprocess.run(cmd, input=inp, capture_output=True, timeout=timeout, env=ENV, stdin=None if inp else subprocess.DEVNULL)
    return r.returncode, r.stdout.decode('utf-8', 'replace'), r.stderr.decode('utf-8', 'replace')

def tail(t, n=2): return ' | '.join(l.strip()[:160] for l in t.strip().splitlines()[-n:]) or 'unknown error'

def keys():
    out = []
    for f in sorted(os.listdir(KEYS)):
        if f.endswith('.pub') and NAME.fullmatch(f[:-4]):
            p = os.path.join(KEYS, f)
            out.append(dict(name=f[:-4], pub=open(p).read().strip(), fp=(run(['ssh-keygen', '-lf', p])[1].split() + ['', ''])[1]))
    return out

def gen(name):
    if not NAME.fullmatch(name): raise ValueError('Key name: lowercase letters, digits, - or _ (max 32)')
    priv = os.path.join(KEYS, name)
    if os.path.exists(priv): raise ValueError('A key with that name already exists')
    tmp = tempfile.mkdtemp(prefix='k')            # tmpfs; removed in finally
    try:
        if run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'wirelight-' + name, '-f', tmp + '/k'])[0]: raise ValueError('Key generation failed')
        with os.fdopen(os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as f: f.write(open(tmp + '/k', 'rb').read())
        shutil.copyfile(tmp + '/k.pub', priv + '.pub')
    finally: shutil.rmtree(tmp, ignore_errors=True)

def delete(name):
    if not NAME.fullmatch(name): raise ValueError('Bad key name')
    for p in (os.path.join(KEYS, name), os.path.join(KEYS, name + '.pub')):
        if os.path.exists(p): os.remove(p)

def _hp(b):
    host = str(b.get('host', '')).strip()
    try: port = int(b.get('port', 22))
    except (TypeError, ValueError): port = 0
    if not HOST.fullmatch(host) or not 0 < port < 65536: raise ValueError('Invalid host or port')
    return host, port

def conn(b):
    host, port = _hp(b); user, key = str(b.get('user', '')).strip(), str(b.get('key', ''))
    if not USER.fullmatch(user): raise ValueError('Invalid user name')
    if not NAME.fullmatch(key) or not os.path.isfile(os.path.join(KEYS, key)): raise ValueError('Choose an SSH key')
    return dict(host=host, port=port, user=user, key=key, sudo=bool(b.get('sudo')))

def spec(host, port): return host if port == 22 else f'[{host}]:{port}'

def cmd(c, remote):
    return ['ssh', '-F', '/dev/null', '-T', '-i', os.path.join(KEYS, c['key']), '-p', str(c['port']), '-l', c['user'],
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + KNOWN, '-o', 'IdentitiesOnly=yes',
            '-o', 'PasswordAuthentication=no', '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=15', '-o', 'ForwardAgent=no',
            '-o', 'ClearAllForwardings=yes', '-o', 'LogLevel=ERROR', '--', c['host'], remote]

def hostkey(b):
    host, port = _hp(b)
    out = run(['ssh-keyscan', '-T', '8', '-p', str(port), '-t', 'ed25519,ecdsa,rsa', host])[1]
    lines = [l.strip() for l in out.splitlines() if KLINE.fullmatch(l.strip())]
    if not lines: raise ValueError('Could not read a host key from that server')
    fps = []
    for l in lines:
        o = run(['ssh-keygen', '-lf', '-'], inp=(l.split(None, 1)[1] + '\n').encode())[1].split()
        if len(o) > 1: fps.append(f"{o[-1].strip('()')}  {o[1]}")
    tok = secrets.token_urlsafe(12); PENDING.clear(); PENDING[tok] = lines
    return dict(token=tok, fingerprints=fps, trusted=run(['ssh-keygen', '-F', spec(host, port), '-f', KNOWN])[0] == 0)

def trust(tok):
    lines = PENDING.pop(str(tok), None)
    if not lines: raise ValueError('Verify the host again first')
    with open(KNOWN, 'a') as f: f.write('\n'.join(lines) + '\n')

def forget(b):
    host, port = _hp(b); run(['ssh-keygen', '-R', spec(host, port), '-f', KNOWN])

def interfaces(c):
    rc, out, err = run(cmd(c, 'ls /sys/class/net'), timeout=25)
    if rc: raise ValueError('SSH failed: ' + tail(err))
    return ['any'] + [l for l in out.split() if IFACE.fullmatch(l)][:64]

def live(s, c, iface, flt, secs):
    if not IFACE.fullmatch(iface) or not FILT.fullmatch(flt): raise ValueError('Invalid interface or capture filter')
    f = f'not port {c["port"]}' if not flt.strip() else f'({flt}) and not port {c["port"]}'   # never capture our own SSH session
    t = (['sudo', '-n'] if c['sudo'] else []) + ['tcpdump', '-i', iface, '-U', '-n', '-s', '0', '-w', '-', f]
    remote = 'sh -c ' + shlex.quote(WRAP) + ' sh ' + ' '.join(shlex.quote(x) for x in t)
    p = subprocess.Popen(cmd(c, remote), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    s['live'] = dict(running=True, stop=False, error='', proc=p)
    threading.Thread(target=_pump, args=(s, min(max(secs, 10), 3600)), daemon=True).start()

def _pump(s, secs):
    L = s['live']; p = L['proc']; sp = pcap.Stream(); end = time.time() + secs
    try:
        while not L['stop'] and time.time() < end and len(s['pk']) < pcap.MAXPKT:
            if select.select([p.stdout], [], [], 1)[0]:
                d = os.read(p.stdout.fileno(), 65536)
                if not d: break
                for r in sp.feed(d):
                    s['raw'].append(r[3][:pcap.SNAP]); s['pk'].append(pcap.dissect(len(s['pk']), r))
    except ValueError: L['error'] = 'remote did not send a valid pcap stream'
    finally:
        early = not L['stop'] and time.time() < end and len(s['pk']) < pcap.MAXPKT
        if early:
            try: p.wait(timeout=3)          # get the real exit status of an unexpected end
            except subprocess.TimeoutExpired: pass
        rc = p.poll(); p.kill(); p.wait()
        try: p.stdin.close()
        except OSError: pass
        err = os.read(p.stderr.fileno(), 4096).decode('utf-8', 'replace') if select.select([p.stderr], [], [], 0.5)[0] else ''
        if early and not L['error']: L['error'] = f'capture ended early (exit {rc}): ' + tail(err, 3)
        L['running'] = False

def stop(s):
    L = s.get('live')
    if L and L['running']:
        L['stop'] = True
        try: L['proc'].kill()
        except OSError: pass
