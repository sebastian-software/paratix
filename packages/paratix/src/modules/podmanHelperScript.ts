import { PODMAN_TOKEN_LIMIT, PODMAN_USERNAME_LIMIT } from "./podmanTypes.js"

/** Python runs only inside the pinned container; no host interpreter is used. */
export const PODMAN_HELPER_SCRIPT = String.raw`
import base64, decimal, hmac, json, os, stat, sys

TOKEN_LIMIT = ${String(PODMAN_TOKEN_LIMIT)}
USERNAME_LIMIT = ${String(PODMAN_USERNAME_LIMIT)}
AUTH_FILE_LIMIT = 8 * 1024 * 1024
METADATA_LIMIT = 4096
# State includes the original bytes and expected credentials, both Base64 encoded.
AUTH_BASE64_LIMIT = 4 * ((AUTH_FILE_LIMIT + 2) // 3)
CREDENTIAL_AUTH_LIMIT = 4 * ((USERNAME_LIMIT + 1 + TOKEN_LIMIT + 2) // 3)
STATE_FILE_LIMIT = AUTH_BASE64_LIMIT + CREDENTIAL_AUTH_LIMIT + METADATA_LIMIT
COMPAT_FILE_LIMIT = AUTH_FILE_LIMIT + METADATA_LIMIT
PAYLOAD_LIMIT = 4 * (USERNAME_LIMIT + TOKEN_LIMIT) + METADATA_LIMIT
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK

class Invalid(Exception): pass
class Conflict(Exception): pass

def require(condition):
    if not condition: raise Invalid()

def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result

def invalid_constant(value): raise Invalid()

def decode(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_float=decimal.Decimal, parse_constant=invalid_constant)

def encode(value):
    # Decimal avoids changing unrelated JSON numbers through binary float conversion.
    if isinstance(value, dict):
        return '{' + ','.join(json.dumps(k) + ':' + encode(v) for k,v in value.items()) + '}'
    if isinstance(value, list): return '[' + ','.join(encode(v) for v in value) + ']'
    if isinstance(value, decimal.Decimal): return str(value)
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':'))

def directory(path, private=False, parent=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(fd)
    require(info.st_uid == 0 and info.st_mode & 0o022 == 0)
    if private: require(stat.S_IMODE(info.st_mode) == 0o700)
    return fd

def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]

def read_file(parent, name, limit=AUTH_FILE_LIMIT, token=False, missing=False):
    try: fd = os.open(name, FLAGS, dir_fd=parent)
    except FileNotFoundError:
        if missing: return None, None
        raise
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1)
        if token: require(stat.S_IMODE(info.st_mode) == 0o400)
        require(info.st_size <= limit)
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        require(len(data) <= limit and metadata(info) == metadata(os.fstat(fd)))
        return bytes(data), info
    finally: os.close(fd)

def write_file(parent, name, data, limit):
    require(len(data) <= limit)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        require(os.fstat(fd).st_uid == 0)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally: os.close(fd)

def token_value(value, limit=TOKEN_LIMIT):
    require(isinstance(value, str) and 0 < len(value.encode('utf-8')) <= limit)
    require(value.strip() == value and not value.startswith('\ufeff') and not value.endswith('\ufeff') and not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in '\u2028\u2029' for c in value))
    return value

def username_value(value):
    token_value(value, USERNAME_LIMIT)
    require(':' not in value and not any(c.isspace() for c in value))
    return value

def credential_auth(entry):
    require(isinstance(entry, dict))
    if 'auth' not in entry: return None
    require(isinstance(entry['auth'], str))
    decoded = base64.b64decode(entry['auth'], validate=True)
    require(base64.b64encode(decoded).decode('ascii') == entry['auth'] and b':' in decoded)
    decoded.decode('utf-8')
    return decoded

def normalized_key(key):
    host = key.lower()
    for prefix in ['https://', 'http://']:
        if host.startswith(prefix): host = host[len(prefix):]
    host = host.split('/')[0]
    if host in ['index.docker.io', 'registry-1.docker.io']: host = 'docker.io'
    return host

def auth_document(raw, registry):
    doc = {} if raw is None else decode(raw)
    require(isinstance(doc, dict))
    auths = doc.get('auths', {})
    require(isinstance(auths, dict))
    for key, entry in auths.items():
        require(isinstance(entry, dict))
        credential_auth(entry)
        if normalized_key(key) == registry:
            require(key == registry and 'identitytoken' not in entry and 'identityToken' not in entry)
    helpers = doc.get('credHelpers', {})
    require(isinstance(helpers, dict))
    require(not any(normalized_key(key) == registry for key in helpers))
    require(not doc.get('credsStore') and not doc.get('credStore'))
    return doc, auths

def incoming(target_parent, target_leaf, auth_info):
    raw = sys.stdin.buffer.read(PAYLOAD_LIMIT + 1)
    require(len(raw) <= PAYLOAD_LIMIT and raw.endswith(b'\n'))
    payload = decode(raw)
    require(isinstance(payload, dict) and payload.get('version') == 1)
    username = username_value(payload.get('username'))
    if target_leaf:
        require(set(payload) == {'version', 'username'})
        value, info = read_file(target_parent, target_leaf, limit=TOKEN_LIMIT + 2, token=True)
        require(auth_info is None or (info.st_dev, info.st_ino) != (auth_info.st_dev, auth_info.st_ino))
        if value.endswith(b'\r\n'): value = value[:-2]
        elif value.endswith(b'\n'): value = value[:-1]
        password = token_value(value.decode('utf-8'))
    else:
        require(set(payload) == {'version', 'username', 'password'})
        password = token_value(payload.get('password'))
    return username, password

def save_state(work, raw, info, expected, mode_only):
    state = {'original': None if raw is None else base64.b64encode(raw).decode('ascii'),
             'metadata': None if info is None else metadata(info),
             'expected': expected, 'modeOnly': mode_only}
    write_file(work, 'state', encode(state).encode('utf-8'), STATE_FILE_LIMIT)

def load_state(work):
    raw, info = read_file(work, 'state', limit=STATE_FILE_LIMIT)
    require(stat.S_IMODE(info.st_mode) == 0o600)
    state = decode(raw)
    require(isinstance(state, dict) and set(state) == {'original', 'metadata', 'expected', 'modeOnly'})
    return state

def commit(auth_parent, auth_leaf, work, operation, registry):
    state = load_state(work)
    original = None if state['original'] is None else base64.b64decode(state['original'], validate=True)
    doc, auths = auth_document(original, registry)
    if state['modeOnly']:
        candidate = original
        require(operation == 'login' and candidate is not None)
    else:
        raw, _ = read_file(work, 'compat', limit=COMPAT_FILE_LIMIT)
        result = decode(raw)
        require(isinstance(result, dict) and set(result).issubset({'auths'}))
        entries = result.get('auths', {})
        require(isinstance(entries, dict))
        compat_key = 'https://index.docker.io/v1/' if registry == 'docker.io' else registry
        if operation == 'login':
            require(set(entries) == {compat_key})
            entry = entries[compat_key]
            decoded = credential_auth(entry)
            require(set(entry) == {'auth'} and decoded is not None)
            require(hmac.compare_digest(entry['auth'], state['expected']))
            auths[registry] = entry
        else:
            require(not entries)
            auths.pop(registry, None)
        doc['auths'] = auths
        candidate = encode(doc).encode('utf-8')
    # Never publish a candidate that a subsequent auth-file read would reject.
    require(len(candidate) <= AUTH_FILE_LIMIT)
    # Create and sync privately before the final conflict check and atomic replace.
    write_file(work, 'candidate', candidate, AUTH_FILE_LIMIT)
    current, info = read_file(auth_parent, auth_leaf, missing=True)
    if current != original or (None if info is None else metadata(info)) != state['metadata']:
        raise Conflict()
    os.replace('candidate', auth_leaf, src_dir_fd=work, dst_dir_fd=auth_parent)
    try: os.fsync(auth_parent)
    except BaseException: return 22
    return 12

def main():
    phase, operation, registry, auth_leaf, target_leaf, mounted, work_leaf = sys.argv[1:]
    require(phase in ['check', 'prepare', 'commit'] and operation in ['login', 'logout'])
    auth_parent = directory('/auth') if mounted == '1' else None
    raw, info = (None, None) if auth_parent is None else read_file(auth_parent, auth_leaf, missing=True)
    if phase == 'commit':
        require(auth_parent is not None)
        require(work_leaf.startswith('.paratix-auth.') and '/' not in work_leaf)
        return commit(auth_parent, auth_leaf, directory(work_leaf, True, auth_parent), operation, registry)
    doc, auths = auth_document(raw, registry)
    entry = auths.get(registry)
    username = password = expected = None
    if operation == 'login':
        target_parent = directory('/pat') if target_leaf else None
        username, password = incoming(target_parent, target_leaf, info)
        expected = base64.b64encode((username + ':' + password).encode('utf-8')).decode('ascii')
        same = entry is not None and credential_auth(entry) is not None and hmac.compare_digest(entry['auth'], expected)
        mode_only = same and stat.S_IMODE(info.st_mode) != 0o600
        needed = not same or mode_only
    else:
        needed = entry is not None
        mode_only = False
    if not needed: return 0
    if phase == 'check': return 10
    work = directory('/work', True)
    save_state(work, raw, info, expected, mode_only)
    if mode_only: return 11
    compat_key = 'https://index.docker.io/v1/' if registry == 'docker.io' else registry
    compat = {'auths': {} if operation == 'login' else {compat_key: {'auth': entry.get('auth', '')}}}
    write_file(work, 'compat', encode(compat).encode('utf-8'), COMPAT_FILE_LIMIT)
    if operation == 'login':
        write_file(work, 'username', username.encode('utf-8'), USERNAME_LIMIT)
        write_file(work, 'token', password.encode('utf-8'), TOKEN_LIMIT)
    return 10

try:
    os.umask(0o077)
    sys.exit(main())
except Conflict: sys.exit(21)
except BaseException as error:
    if isinstance(error, SystemExit): raise
    sys.exit(20)
`
