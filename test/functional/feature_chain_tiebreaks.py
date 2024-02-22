#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the correct active block is chosen in complex reorgs."""

from test_framework.blocktools import create_block
from test_framework.messages import CBlockHeader
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class ChainTiebreaksTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    @staticmethod
    def send_headers(node, blocks):
        """Submit headers for blocks to node."""
        for block in blocks:
            # Use RPC rather than P2P, to prevent the message from being interpreted as a block
            # announcement.
            node.submitheader(hexdata=CBlockHeader(block).serialize().hex())
            
    def run_test(self):
        node = self.nodes[0]
        # Add P2P connection to bitcoind
        peer = node.add_p2p_connection(P2PDataStore())

        self.log.info('Precomputing blocks')
        #
        #       B  - C
        #      /  
        #    A
        #      \  
        #       B' - C'
        #
        blocks = []

        # Construct A, building off genesis.
        start_height = node.getblockcount()
        blocks.append(create_block(
            hashprev=int(node.getbestblockhash(), 16),
            tmpl={"height": start_height + 1}
        ))
        blocks[-1].solve()

        # Construct all blocks.
        for i in range(0, 4):
            if i%2==0:
                prev_idx = 0
            else:
                prev_idx = len(blocks) - 1
                
            blocks.append(create_block(
            hashprev=int(blocks[prev_idx].hash, 16),
            tmpl={
                "height": start_height + 1 + (i % 2) + 1,
                # Make sure each block has a different hash.
                "curtime": blocks[-1].nTime + 1,
            }
            ))
            blocks[-1].solve()

        self.log.info('Make sure A is accepted normally')
        peer.send_blocks_and_test([blocks[0]], node, success=True)
        # A must be active chain now.
        assert_equal(node.getbestblockhash(), blocks[0].hash)

        self.log.info('Send B header and C')
        self.send_headers(node, [blocks[1]])
        peer.send_blocks_and_test([blocks[2]], node, success=False)

        # A must still be the active chain, given we only have the header of B (therefore C cannot be connected)
        assert_equal(node.getbestblockhash(), blocks[0].hash)

        self.log.info("Send B' and C'")
        peer.send_blocks_and_test(blocks[3:], node, success=True)
        # C' should be the active chain
        assert_equal(node.getbestblockhash(), blocks[4].hash)

        self.log.info("Send B and check that the active chain is still C'")
        peer.send_blocks_and_test([blocks[1]], node, success=False)
        assert_equal(node.getbestblockhash(), blocks[4].hash)

if __name__ == '__main__':
    ChainTiebreaksTest().main()