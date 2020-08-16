import os
import time
import json
import base64
import hashlib
import threading
import requests
from web3 import Web3
from web3.middleware import geth_poa_middleware
import ed25519
from flask import Flask, request, jsonify
from config import *

w3 = Web3(Web3.WebsocketProvider(RPC_URL))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
brightid = w3.eth.contract(address=BRIGHTID_ADDRESS, abi=BRIGHTID_ABI)
sahm = w3.eth.contract(address=SAHM_ADDRESS, abi=SAHM_ABI)
nonce = w3.eth.getTransactionCount(RELAYER_ADDRESS)

app = Flask(__name__)

def waitForLink(addr):
    for i in range(LINK_CHECK_NUM):
        data = requests.get(VERIFICATIONS_URL + addr).json()
        if 'errorMessage' not in data or data['errorMessage'] != NOT_FOUND:
            return True
        print('{} not found'.format(addr))
        time.sleep(LINK_CHECK_PERIOD)

    print('{} monitoring expired'.format(addr))
    return False

def sponsor(addr):
    addr = addr.lower()
    data = requests.get(VERIFICATIONS_URL + addr).json()
    if 'errorMessage' not in data or data['errorMessage'] != NOT_SPONSORED:
        print(addr, 'sponsored before')
        return True
    op = {
        'name': 'Sponsor',
        'app': 'sahm',
        'contextId': addr,
        'timestamp': int(time.time()*1000),
        'v': 5
    }
    signing_key = ed25519.SigningKey(base64.b64decode(SPONSORSHIP_PRIVATEKEY))
    message = json.dumps(op, sort_keys=True, separators=(',', ':')).encode('ascii')
    sig = signing_key.sign(message)
    op['sig'] = base64.b64encode(sig).decode('ascii')
    r = requests.post(OPERATION_URL, json.dumps(op))
    if r.status_code != 200:
        print('error in sponsoring {}, error: {}'.format(addr, r.text))
        return False
    for i in range(SPONSOR_CHECK_NUM):
        print('waiting for sponsor operation get applied')
        time.sleep(SPONSOR_CHECK_PERIOD)
        data = requests.get(VERIFICATIONS_URL + addr).json()
        if 'errorMessage' not in data or data['errorMessage'] != NOT_SPONSORED:
            print('{} sponsored'.format(addr))
            return True
    print('sponsoring {} failed'.format(addr))
    return False

def publish(addr):
    r = requests.post(PUBLISH_URL, json={'addr': addr})
    if not r.json()['success']:
        print('error in publishing {}, error: {}'.format(addr, r.text))
        return
    for i in range(PUBLISH_CHECK_NUM):
        block = brightid.functions.verifications(
            Web3.toChecksumAddress(addr)).call()
        if block > 0:
            print('verification for {} published'.format(addr))
            return True
        print('waiting for verification get published')
        time.sleep(PUBLISH_CHECK_PERIOD)

    print('publishing verification {} failed'.format(addr))
    return False

def send_eidi(addr):
    global nonce
    addr = addr.lower()
    data = requests.get(VERIFICATIONS_URL + addr).json()
    addrs = data.get('data', {}).get('contextIds', [])
    addrs = list(map(Web3.toChecksumAddress, addrs))
    if len(addrs) <= 1 or addrs[0].lower() != addr.lower() or len(addrs) > 10 or w3.eth.getBalance(addrs[0]) >= SEND_EIDI_AMOUNT or w3.eth.getTransactionCount(addrs[0]) > 0:
        print('{} is not eligible to receive eidi'.format(addr))
        return False

    tx = {
        'to': Web3.toChecksumAddress(addr),
        'value': SEND_EIDI_AMOUNT,
        'gas': GAS,
        'gasPrice': GAS_PRICE,
        'nonce': nonce,
        'chainId': CHAINID
    }
    print('sending {} Eidi to {}'.format(SEND_EIDI_AMOUNT/10**18, addr))
    signed_txn = w3.eth.account.sign_transaction(tx, private_key=RELAYER_PRIVATEKEY)
    w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    nonce += 1
    receipt = w3.eth.waitForTransactionReceipt(signed_txn['hash'])
    if not receipt['status']:
        print('sending Eidi to {} via {} failed, error: {}'.format(addr, tx, receipt))
        return False
    print('Eidi sent to {}'.format(addr))
    return True

def claim_sahm(addrs, parent, r, s, v):
    global nonce
    addrs = list(map(Web3.toChecksumAddress, addrs))
    for addr in addrs:
        if sahm.functions.claimed(addr).call():
            print('{} claimed sahm before'.format(addr))
            return
    f = sahm.functions.claim(addrs[0], parent, v, r, s)
    tx = f.buildTransaction({
        'chainId': CHAINID,
        'gas': GAS,
        'gasPrice': GAS_PRICE,
        'nonce': nonce,
    })
    signed_txn = w3.eth.account.sign_transaction(tx, private_key=RELAYER_PRIVATEKEY)
    w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    nonce += 1
    receipt = w3.eth.waitForTransactionReceipt(signed_txn['hash'])
    if not receipt['status']:
        print('claiming Sahm tokens for {} failed. tx: {}, error: {}'.format(addr, tx, receipt))
        return False
    print('{} claimed Sahm tokens with {} as parent'.format(addrs[0], parent))

def reclaim_sahm(addr):
    global nonce
    addr = addr.lower()
    data = requests.get(VERIFICATIONS_URL + addr).json()
    addrs = data.get('data', {}).get('contextIds', [])
    addrs = list(map(Web3.toChecksumAddress, addrs))

    for addr in addrs[1:]:
        if sahm.functions.balanceOf(addr).call() > 0:
            print('{} has sahm tokens to claim in {}'.format(addrs[0], addr))
            break
    else:
        print('nothing to reclaim for {}'.format(addrs[0]))
        return
    f = sahm.functions.reclaim(addrs[0])
    tx = f.buildTransaction({
        'chainId': CHAINID,
        'gas': GAS,
        'gasPrice': GAS_PRICE,
        'nonce': nonce,
    })
    signed_txn = w3.eth.account.sign_transaction(tx, private_key=RELAYER_PRIVATEKEY)
    w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    nonce += 1
    receipt = w3.eth.waitForTransactionReceipt(signed_txn['hash'])
    if not receipt['status']:
        print('reclaiming Sahm tokens for {} failed. tx: {}, error: {}'.format(addrs[0], tx, receipt))
        return False
    print('{} reclaimed Sahm tokens'.format(addrs[0]))

processing = {}
def process(addr, parent, r, s, v):
    if addr in processing:
        return
    processing[addr] = True
    try:
        print('processing {}'.format(addr))
        if not waitForLink(addr):
            return
        if not sponsor(addr):
            return
        # return if user does not have BrightID verification
        # or there are other errors
        data = requests.get(VERIFICATIONS_URL + addr).json()
        if 'errorMessage' in data:
            print(addr, data['errorMessage'])
            return
        if not publish(addr):
            return
        send_eidi(addr)
        claim_sahm(data['data']['contextIds'], parent, r, s, v)
        reclaim_sahm(addr)
    except:
        raise
    finally:
        del processing[addr]

@app.route('/process', methods=['POST'])
def _process():
    d = request.json
    print('process', d)
    if not d:
        return jsonify({'success': False, 'error': 'addr, r, s, v should be provided as json param'})
    for k in ('addr', 'parent', 'r', 's', 'v'):
        if k not in d:
            print('process failed', k)
            return jsonify({'success': False, 'error': '{} parameter missed'.format(k)})
    addr = d['addr'].lower()
    parent = d['parent'].lower()
    data = requests.get(VERIFICATIONS_URL + addr).json()
    contextIds = data.get('data', {}).get('contextIds', [])
    if contextIds and contextIds[0] != addr:
        e = 'This address is used before. Link a new address or use {} as your last linked address!'.format(contextIds[0])
        return jsonify({'success': False, 'error': e})
    threading.Thread(target=process, args=(addr, parent, d['r'], d['s'], d['v'])).start()
    return jsonify({'success': True})

parents = {}
@app.route('/parents/<addr>/<parent>', methods=['GET'])
def set_parent(addr, parent):
    addr = addr.lower()
    parent = parent.lower()
    # do not allow overriding parent
    if addr in parents:
        return jsonify({'success': False})
    parents[addr] = parent
    return jsonify({'success': True})

@app.route('/parents/<addr>', methods=['GET'])
def get_parent(addr):
    addr = addr.lower()
    parent = parents.get(addr, '')
    return jsonify({'success': parent != '', 'parent': parent})

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=DEBUG)
