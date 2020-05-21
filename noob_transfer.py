# Script to simulate the transferral of OOB data
# for the EAP-NOOB method.
# Copyright (c) 2020, Max Crone <max@maxcrone.org>

import base64
from collections import OrderedDict
import hashlib
import json
import os
import sqlite3

db_path_server = '/tmp/noob_server.db'
db_path_peer = '/tmp/noob_peer.db'

def exec_query(query, db_path, args=[]):
    if not os.path.isfile(db_path_server):
        print(f'Server database file does not exist: {db_path_server}')
    if not os.path.isfile(db_path_peer):
        print(f'Peer database file does not exist: {db_path_peer}')

    conn = sqlite3.connect(db_path)

    out = []
    c = conn.cursor()
    c.execute(query, args)
    conn.commit()
    out = c.fetchone()
    conn.close()
    return out

def gen_noob():
    """Generate a random 16 byte secret nonce"""

    noob = os.urandom(16)
    noob_b64 = base64.urlsafe_b64encode(noob)
    noob_b64 = str(noob_b64, 'utf-8').strip('=')
    return noob_b64

def compute_noob_id(noob_b64):
    """Compute identifier for the OOB message"""

    noob_id = 'NoobId' + noob_b64
    noob_id = noob_id.encode('utf-8')
    noob_id = hashlib.sha256(noob_id).digest()
    noob_id_b64 = base64.urlsafe_b64encode(noob_id[0:16])
    noob_id_b64 = str(noob_id_b64, 'utf-8').strip('=')
    return noob_id_b64

def compute_hoob(peer_id, noob, direction):
    """Compute 16-byte fingerprint from all exchanged parameters"""

    query = 'SELECT MacInput FROM EphemeralState WHERE PeerId=?'
    data = exec_query(query, db_path_peer, [peer_id])
    if data is None:
        print('Query returned None in gen_noob')
        return None

    hoob_array = json.loads(data[0])
    hoob_array[len(hoob_array) - 1] = noob
    hoob_str = json.dumps(hoob_array, separators=(',', ':')).encode()
    hoob = hashlib.sha256(hoob_str).digest()
    hoob_b64 = base64.urlsafe_b64encode(hoob[0:16]).decode('ascii').strip('=')
    return hoob_b64

hoob = compute_hoob('Yr8hohFMCqmJW8eYFAE2Jy', gen_noob(), 1)
print(f'[Hoob] {hoob}')
