#!/usr/bin/env python3
# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the test-only -blackhole option.

A -blackhole node must receive and keep everything (so it never re-downloads),
but forward nothing: it announces/serves no transactions or blocks and adds
nothing to any reconciliation set.

Each behaviour is checked against a normal "control" node (node0) that is
expected to do the opposite, so that the negative assertions on the blackhole
node (node1) are meaningful: if the control did not relay/serve, the harness
itself would be at fault.
"""

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CInv,
    MSG_BLOCK,
    MSG_WTX,
    msg_getdata,
    msg_inv,
    msg_tx,
)
from test_framework.p2p import (
    P2PDataStore,
    P2PInterface,
    P2PTxInvStore,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# Comfortably larger than INBOUND_INVENTORY_BROADCAST_INTERVAL so a mocktime
# bump reliably triggers the (suppressed, on the blackhole) tx trickle relay.
INV_TRICKLE_BUMP = 30


class P2PBlackholeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # node0: normal control. node1: blackhole. Reconciliation is enabled on
        # both so we also exercise the "adds nothing to any reconciliation set"
        # path (the blackhole must still not relay with -txreconciliation on).
        self.extra_args = [
            ["-txreconciliation=1"],
            ["-txreconciliation=1", "-blackhole"],
        ]

    def setup_network(self):
        # Bring the nodes up and give them a shared chain (so a tx built against
        # that chain validates on either node), then disconnect them so each is
        # driven independently through its own P2P peers.
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.wallet_node = self.nodes[0]
        from test_framework.wallet import MiniWallet
        self.wallet = MiniWallet(self.wallet_node)
        self.generate(self.wallet, 120)  # mine + sync coinbase maturity to node1
        self.disconnect_nodes(0, 1)

        # Freeze time so a mocktime bump deterministically fires tx relay.
        tip_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())["time"]
        self.mocktime = tip_time + 1
        for node in self.nodes:
            node.setmocktime(self.mocktime)

    # --- helpers -------------------------------------------------------------

    def make_tx(self):
        """Build (but do not submit) a tx valid on both nodes."""
        return self.wallet.create_self_transfer()

    def advance_time(self, node):
        # Advance mocktime past the tx-request / inventory-relay delays so the
        # relevant timers fire (they are mocktime-driven).
        self.mocktime += INV_TRICKLE_BUMP
        node.setmocktime(self.mocktime)

    def bump_and_sync(self, node, peer):
        self.advance_time(node)
        peer.sync_with_ping()

    # --- transaction behaviour ----------------------------------------------

    def check_tx_receive_keep_forward(self, node, *, is_blackhole):
        label = "blackhole" if is_blackhole else "control"
        self.log.info(f"[{label}] tx: receives+keeps, and {'does NOT' if is_blackhole else 'does'} forward")

        src = node.add_p2p_connection(P2PInterface())
        sink = node.add_p2p_connection(P2PTxInvStore())
        tx = self.make_tx()
        wtxid_int = int(tx["wtxid"], 16)

        # Offer the tx: the node must request it (it downloads everything).
        src.send_and_ping(msg_inv([CInv(MSG_WTX, wtxid_int)]))
        self.advance_time(node)  # let the tx-request timer fire
        src.wait_for_getdata([wtxid_int])
        # Provide it; the node must keep it in the mempool.
        src.send_and_ping(msg_tx(tx["tx"]))
        self.wait_until(lambda: tx["txid"] in node.getrawmempool())

        # Force a trickle relay cycle towards the sink and check forwarding.
        # Peers are wtxid-relay, so announced invs are keyed by wtxid.
        self.bump_and_sync(node, sink)
        if is_blackhole:
            assert_equal(sink.get_invs(), [])
            # The blackhole must not accumulate an outbound backlog: the
            # to-be-sent queue is still drained each trickle even though nothing
            # is sent, so inv_to_send returns to 0 (no unbounded queue growth).
            self.wait_until(lambda: all(p["inv_to_send"] == 0 for p in node.getpeerinfo()))
        else:
            self.wait_until(lambda: wtxid_int in sink.tx_invs_received)
        return tx

    def check_no_redownload(self, node, tx, *, is_blackhole):
        label = "blackhole" if is_blackhole else "control"
        self.log.info(f"[{label}] tx: does not re-download an already-held tx")
        # A fresh peer re-announces a tx the node already has: it must not ask
        # for it again (AlreadyHaveTx is true because the tx was kept).
        peer = node.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_inv([CInv(MSG_WTX, int(tx["wtxid"], 16))]))
        # Advance past the request delay so that, if the node were going to
        # re-request, it would have; then confirm it did not.
        self.advance_time(node)
        peer.sync_with_ping()
        assert "getdata" not in peer.last_message

    def check_getdata_serving(self, node, tx, *, is_blackhole):
        label = "blackhole" if is_blackhole else "control"
        self.log.info(f"[{label}] tx: {'refuses to' if is_blackhole else 'will'} serve GETDATA")
        peer = node.add_p2p_connection(P2PInterface())
        peer.send_and_ping(msg_getdata([CInv(MSG_WTX, int(tx["wtxid"], 16))]))
        if is_blackhole:
            peer.sync_with_ping()
            # A blackhole drops the request entirely: no tx, and no notfound.
            assert "tx" not in peer.last_message
            assert "notfound" not in peer.last_message
        else:
            peer.wait_for_tx(tx["txid"])

    # --- block behaviour -----------------------------------------------------

    def check_block_receive_keep_forward(self, node, *, is_blackhole):
        label = "blackhole" if is_blackhole else "control"
        self.log.info(f"[{label}] block: receives+keeps, and {'does NOT' if is_blackhole else 'does'} forward")

        sink = node.add_p2p_connection(P2PInterface())
        feeder = node.add_p2p_connection(P2PDataStore())

        tip = int(node.getbestblockhash(), 16)
        height = node.getblockcount() + 1
        block = create_block(tip, create_coinbase(height), ntime=self.mocktime + 1)
        block.solve()

        # The node must accept and keep the block (chain advances).
        feeder.send_blocks_and_test([block], node, success=True)
        assert_equal(node.getbestblockhash(), block.hash_hex)

        # Whether it re-announces the new block to the other peer.
        sink.sync_with_ping()
        if is_blackhole:
            assert "headers" not in sink.last_message
            assert "cmpctblock" not in sink.last_message
            inv = sink.last_message.get("inv")
            if inv is not None:
                assert block.hash_int not in [i.hash for i in inv.inv]
        else:
            sink.wait_for_inv([CInv(MSG_BLOCK, block.hash_int)])

    # --- driver --------------------------------------------------------------

    def run_test(self):
        # Reconciliation behaviour (a blackhole adds nothing to any reconciliation
        # set, so it answers reconciliation with an empty sketch) is covered
        # separately in p2p_blackhole_txrecon.py, which reuses the Erlay harness.
        for node, is_blackhole in ((self.nodes[1], True), (self.nodes[0], False)):
            tx = self.check_tx_receive_keep_forward(node, is_blackhole=is_blackhole)
            self.check_no_redownload(node, tx, is_blackhole=is_blackhole)
            self.check_getdata_serving(node, tx, is_blackhole=is_blackhole)
            self.check_block_receive_keep_forward(node, is_blackhole=is_blackhole)
            node.disconnect_p2ps()


if __name__ == "__main__":
    P2PBlackholeTest(__file__).main()
