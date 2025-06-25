// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_TXRECONCILIATION_H
#define BITCOIN_NODE_TXRECONCILIATION_H

#include <net.h>
#include <sync.h>

#include <memory>
#include <tuple>
#include <optional>

/** Supported transaction reconciliation protocol version */
static constexpr uint32_t TXRECONCILIATION_VERSION{1};

/**
 * Maximum number of wtxids stored in a peer local set, bounded to protect the memory use of
 * reconciliation sets and short ids mappings, and CPU used for sketch computation.
 */
constexpr size_t MAX_RECONSET_SIZE = 3000;

/**
 * Announce transactions via full wtxid to a limited number of inbound and outbound peers.
 * Justification for these values are provided here:
 * TODO: ADD link to justification based on simulation results */
constexpr double INBOUND_FANOUT_DESTINATIONS_FRACTION = 0.1;
constexpr size_t OUTBOUND_FANOUT_THRESHOLD = 4;

/**
 * Interval for inbound peer fanout selection. The subset is rotated on a timer.
 */
static constexpr auto INBOUND_FANOUT_ROTATION_INTERVAL{10min};

/**
 * Interval between initiating reconciliations with peers.
 * This value allows to reconcile ~(7 tx/s * 8s) transactions during normal operation.
 * More frequent reconciliations would cause significant constant bandwidth overhead
 * due to reconciliation metadata (sketch sizes etc.), which would nullify the efficiency.
 * Less frequent reconciliations would introduce high transaction relay latency.
 */
constexpr std::chrono::microseconds RECON_REQUEST_INTERVAL{8s};

enum class ReconciliationRegisterResult {
    NOT_FOUND,
    SUCCESS,
    ALREADY_REGISTERED,
    PROTOCOL_VIOLATION,
};

/**
 * Record whether or not a wtxid was successfully added to a reconciliation set.
 * In case of failure, check whether this was due to a shortid collision and record
 * the colliding wtxid.
*/
class AddToSetResult
{
    public:
        bool m_succeeded;
        std::optional<Wtxid> m_collision;

        explicit AddToSetResult(bool added, std::optional<Wtxid> conflict);
        static AddToSetResult Succeeded();
        static AddToSetResult Failed();
        static AddToSetResult Collision(Wtxid);
};

/**
 * Transaction reconciliation is a way for nodes to efficiently announce transactions.
 * This object keeps track of all txreconciliation-related communications with the peers.
 * The high-level protocol is:
 * 0.  Txreconciliation protocol handshake.
 * 1.  Once we receive a new transaction, add it to the set instead of announcing immediately.
 * 2.  At regular intervals, a txreconciliation initiator requests a sketch from a peer, where a
 *     sketch is a compressed representation of short form IDs of the transactions in their set.
 * 3.  Once the initiator received a sketch from the peer, the initiator computes a local sketch,
 *     and combines the two sketches to attempt finding the difference in *sets*.
 * 4a. If the difference was not larger than estimated, see SUCCESS below.
 * 4b. If the difference was larger than estimated, initial txreconciliation fails. The initiator
 *     requests a larger sketch via an extension round (allowed only once).
 *     - If extension succeeds (a larger sketch is sufficient), see SUCCESS below.
 *     - If extension fails (a larger sketch is insufficient), see FAILURE below.
 *
 * SUCCESS. The initiator knows full symmetrical difference and can request what the initiator is
 *          missing and announce to the peer what the peer is missing.
 *
 * FAILURE. The initiator notifies the peer about the failure and announces all transactions from
 *          the corresponding set. Once the peer received the failure notification, the peer
 *          announces all transactions from their set.

 * This is a modification of the Erlay protocol (https://arxiv.org/abs/1905.10518) with two
 * changes (sketch extensions instead of bisections, and an extra INV exchange round), both
 * are motivated in BIP-330.
 */
class TxReconciliationTracker
{
private:
    class Impl;
    const std::unique_ptr<Impl> m_impl;

public:
    explicit TxReconciliationTracker(uint32_t recon_version);
    ~TxReconciliationTracker();

    /**
     * Step 0. Generates initial part of the state (salt) required to reconcile txs with the peer.
     * The salt is used for short ID computation required for txreconciliation.
     * The function returns the salt.
     * A peer can't participate in future txreconciliations without this call.
     * This function must be called only once per peer.
     */
    uint64_t PreRegisterPeer(NodeId peer_id);

    /**
     * For testing purposes only. This SHOULD NEVER be used in production.
    */
    void PreRegisterPeerWithSalt(NodeId peer_id, uint64_t local_salt);

    /**
     * Step 0. Once the peer agreed to reconcile txs with us, generate the state required to track
     * ongoing reconciliations. Must be called only after pre-registering the peer and only once.
     */
    ReconciliationRegisterResult RegisterPeer(NodeId peer_id, bool is_peer_inbound,
                                              uint32_t peer_recon_version, uint64_t remote_salt);

    /**
     * Step 1. Add a to-be-announced transaction to the local reconciliation set of the target peer.
     * Returns false if the set is at capacity, or if the set contains a colliding transaction (alongside
     * the colliding wtxid). Returns true if the transaction is added to the set (or if it was already in it).
     */
    AddToSetResult AddToSet(NodeId peer_id, const Wtxid& wtxid);

    /**
     * Checks whether a transaction is part of the peer's reconciliation set.
     */
    bool IsTransactionInSet(NodeId peer_id, const Wtxid& wtxid);

    /**
     * Before Step 2, we might want to remove a wtxid from the reconciliation set, for example if
     * the peer just announced the transaction to us.
     * Returns whether the wtxid was removed.
     */
    bool TryRemovingFromSet(NodeId peer_id, const Wtxid& wtxid);

    /**
     * Returns whether it's time to initiate reconciliation (Step 2) with a given peer, based on:
     * - time passed since the last reconciliation;
     * - reconciliation queue;
     * - whether previous reconciliations for the given peer were finalized.
     */
    bool IsPeerNextToReconcileWith(NodeId peer_id, std::chrono::microseconds now);

    /**
     * Adds a collection of transactions (identified by short_id) to m_recently_requested_short_ids.
     * This should be called with the short_ids of the transaction being requested to a peer when sending
     * out a RECONCILDIFF.
     */
    void TrackRecentlyRequestedTransactions(std::vector<uint32_t>& requested_txs);

    /**
     * Checks whether a given transaction was requested by us to any of our Erlay outbound peers (during RECONCILDIFF).
     */
    bool WasTransactionRecentlyRequested(const Wtxid& wtxid);

    /**
     * Step 2. Unless the peer hasn't finished a previous reconciliation round, this function will
     * return the details of our local state, which should be communicated to the peer so that they
     * better know what we need:
     * - size of our reconciliation set for the peer
     * - our q-coefficient with the peer, formatted to be transmitted as integer value
     * Assumes the peer was previously registered for reconciliations.
     */
    std::optional<std::pair<uint16_t, uint16_t>> InitiateReconciliationRequest(NodeId peer_id);

    /**
     * Step 2. Record an reconciliation request with parameters to respond when its time.
     * If peer violates the protocol, disconnect.
     */
    bool HandleReconciliationRequest(NodeId peer_id, uint16_t peer_recon_set_size, uint16_t peer_q);

    /**
     * Step 2. Once it's time to respond to reconciliation requests, we construct a sketch from
     * the local reconciliation set, and send it to the initiator.
     * If the peer was not previously registered for reconciliations or the peers didn't request
     * to reconcile with us, return false.
     */
    bool ShouldRespondToReconciliationRequest(NodeId peer_id, std::vector<uint8_t>& skdata);

    /**
     * Step 3. Process a response to our reconciliation request.
     * Returns false if the peer seems to violate the protocol.
     * Populates the vectors so that we know which transactions should be requested and announced,
     * and whether reconciliation succeeded (nullopt if the reconciliation is not over yet and
     * extension should be requested).
     */
    bool HandleSketch(NodeId peer_id, const std::vector<uint8_t>& skdata,
                      // returning values
                      std::vector<uint32_t>& txs_to_request, std::vector<uint256>& txs_to_announce, std::optional<bool>& result);

    /**
     * Step 5. Peer requesting extension after reconciliation they initiated failed on their side:
     * the sketch we sent to them was not sufficient to find the difference.
     * No privacy leak can happen here because sketch extension is constructed over the snapshot.
     * If the peer seems to violate the protocol, do nothing.
     */
    void HandleExtensionRequest(NodeId peer_id);

    /**
     * Step 4. Once we received a signal of reconciliation finalization with a given result from the
     * initiating peer, announce the following transactions:
     * - in case of a failure, all transactions we had for that peer
     * - in case of a success, transactions the peer asked for by short id (ask_shortids)
     * Return false if the peer seems to violate the protocol.
     */
    bool FinalizeInitByThem(NodeId peer_id, bool recon_result,
        const std::vector<uint32_t>& remote_missing_short_ids, std::vector<uint256>& remote_missing);

    /**
     * Attempts to forget txreconciliation-related state of the peer (if we previously stored any).
     * After this, we won't be able to reconcile transactions with the peer.
     */
    void ForgetPeer(NodeId peer_id);

    /**
     * Check if a peer is registered to reconcile transactions with us.
     */
    bool IsPeerRegistered(NodeId peer_id) const;

    /**
     * Whether a given peer is currently flagged for fanout.
    */
    bool IsInboundFanoutTarget(NodeId peer_id);

    /**
     * Get the next time the inbound peer subset should be rotated.
     */
    std::chrono::microseconds GetNextInboundPeerRotationTime();

    /**
     * Update the next inbound peer rotation time.
     */
    void SetNextInboundPeerRotationTime(std::chrono::microseconds next_time);

   /**
    * Picks a different subset of inbound peers to fanout to.
    */
   void RotateInboundFanoutTargets();
};

#endif // BITCOIN_NODE_TXRECONCILIATION_H
