#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a -blackhole node serves no transactions via reconciliation.

A blackhole receives and keeps everything but adds nothing to any reconciliation
set. So, acting as a reconciliation responder, it always answers with an EMPTY
sketch, even while holding transactions it would otherwise have queued for its
peers. Nothing can therefore be reconciled out of it.

This reuses the Erlay reconciliation harness. The non-blackhole counterpart
(sketches that actually encode the node's transactions) is covered by
p2p_txrecon_responder.py.
"""

import math
import time

from test_framework.messages import CInv, MSG_WTX, msg_inv
from test_framework.p2p_txrecon import (
    INBOUND_INVENTORY_BROADCAST_INTERVAL,
    Q_PRECISION,
    RECON_Q,
    ReconciliationTest,
    TxReconTestP2PConn,
)
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class BlackholeReconciliationTest(ReconciliationTest):
    def set_test_params(self):
        super().set_test_params()
        # Same reconciliation-enabled node as the responder test, but a blackhole.
        self.extra_args[0].append("-blackhole")

    def run_test(self):
        self.test_node = self.nodes[0]
        self.test_node.setmocktime(int(time.time()))
        self.wallet = MiniWallet(self.nodes[0])
        self.generate(self.wallet, 200)

        peer = self.test_node.add_p2p_connection(TxReconTestP2PConn())

        # Transactions the node already holds (in its mempool), plus one it does
        # not hold that only the peer has.
        held = [self.wallet.create_self_transfer() for _ in range(15)]
        for tx in held:
            self.test_node.sendrawtransaction(tx["hex"])
        new_tx = self.wallet.create_self_transfer()  # not submitted to the node
        held_wtxids = [int(tx["wtxid"], 16) for tx in held]
        new_wtxid = int(new_tx["wtxid"], 16)

        # Bump well past the trickle interval so that, on a normal node, the held
        # txs would have populated the reconciliation set before reconciling.
        self.bump_mocktime_past_trickle(INBOUND_INVENTORY_BROADCAST_INTERVAL)
        peer.sync_with_ping()

        self.log.info("A blackhole answers reconciliation with an empty sketch even while holding txs")
        peer.send_reqtxrcncl(0, int(math.ceil(RECON_Q * Q_PRECISION)))
        self.wait_until(lambda: len(peer.last_sketch) > 0, timeout=30)
        assert_equal(peer.last_sketch.pop().skdata, [])

        self.log.info("Seeing the empty sketch, the peer dumps its whole set; the blackhole must "
                      "not re-download txs it already holds (but still fetches a genuinely new one)")
        # The peer announces everything: the txs the blackhole already holds and
        # the one it is missing.
        peer.send_without_ping(msg_inv([CInv(MSG_WTX, w) for w in held_wtxids + [new_wtxid]]))
        # Record the INV before advancing, else the request is scheduled past the bump.
        peer.sync_with_ping()
        # Advance past the tx-request delay so the intended GETDATA goes out.
        self.test_node.bumpmocktime(60)
        peer.sync_with_ping()

        # It must request the one it is missing (it receives everything)...
        self.wait_until(lambda: new_wtxid in peer.getdata_requests, timeout=30)
        # ...but never re-request any it already had.
        for w in held_wtxids:
            assert w not in peer.getdata_requests

        peer.peer_disconnect()
        peer.wait_for_disconnect()


if __name__ == "__main__":
    BlackholeReconciliationTest(__file__).main()
