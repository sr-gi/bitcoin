// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/txreconciliation.h>

#include <common/system.h>
#include <logging.h>
#include <util/check.h>
#include <util/hasher.h>

#include <cmath>
#include <unordered_map>
#include <variant>


namespace {

/** Static salt component used to compute short txids for sketch construction, see BIP-330. */
const std::string RECON_STATIC_SALT = "Tx Relay Salting";
const HashWriter RECON_SALT_HASHER = TaggedHash(RECON_STATIC_SALT);

/**
 * Salt (specified by BIP-330) constructed from contributions from both peers. It is used
 * to compute transaction short IDs, which are then used to construct a sketch representing a set
 * of transactions we want to announce to the peer.
 */
uint256 ComputeSalt(uint64_t salt1, uint64_t salt2)
{
    // According to BIP-330, salts should be combined in ascending order.
    return (HashWriter(RECON_SALT_HASHER) << std::min(salt1, salt2) << std::max(salt1, salt2)).GetSHA256();
}

/**
 * Keeps track of txreconciliation-related per-peer state.
 */
class TxReconciliationState
{
public:
    /**
     * Reconciliation protocol assumes using one role consistently: either a reconciliation
     * initiator (requesting sketches), or responder (sending sketches). This defines our role,
     * based on the direction of the p2p connection.
     */
    bool m_we_initiate;

    /**
     * Store all wtxids which we would announce to the peer (policy checks passed, etc.)
     * in this set instead of announcing them right away. When reconciliation time comes, we will
     * compute a compressed representation of this set ("sketch") and use it to efficiently
     * reconcile this set with a set on the peer's side.
     */
    std::unordered_set<Wtxid, SaltedTxidHasher> m_local_set;

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * This is a cache of these IDs enabling faster lookups of full wtxids,
     * useful when peer will ask for missing transactions by short IDs
     * at the end of a reconciliation round.
     * We also use this to keep track of short ID collisions. In case of a
     * collision, both transactions should be fanout.
     */
    std::map<uint32_t, Wtxid> m_short_id_mapping;

    TxReconciliationState(bool we_initiate, uint64_t k0, uint64_t k1) : m_we_initiate(we_initiate), m_k0(k0), m_k1(k1) {}

    /**
     * Reconciliation sketches are computed over short transaction IDs.
     * Short IDs are salted with a link-specific constant value.
     */
    uint32_t ComputeShortID(const uint256 wtxid) const
    {
        const uint64_t s = SipHashUint256(m_k0, m_k1, wtxid);
        const uint32_t short_txid = 1 + (s & 0xFFFFFFFF);
        return short_txid;
    }

private:
    /**
     * These values are used to salt short IDs, which is necessary for transaction reconciliations.
     */
    uint64_t m_k0, m_k1;
};
} // namespace

/** Actual implementation for TxReconciliationTracker's data structure. */
class TxReconciliationTracker::Impl
{
private:
    mutable Mutex m_txreconciliation_mutex;

    // Local protocol version
    uint32_t m_recon_version;

    /**
     * Keeps track of txreconciliation states of eligible peers.
     * For pre-registered peers, the locally generated salt is stored.
     * For registered peers, the locally generated salt is forgotten, and the state (including
     * "full" salt) is stored instead.
     */
    std::unordered_map<NodeId, std::variant<uint64_t, TxReconciliationState>> m_states GUARDED_BY(m_txreconciliation_mutex);

    /*
     * Keeps track of how many of the registered peers are inbound. Updated on registering or
     * forgetting peers.
     */
    size_t m_inbounds_count GUARDED_BY(m_txreconciliation_mutex){0};

    /**
     * Collection of inbound peers selected for fanout. Should get periodically rotated using RotateInboundFanoutTargets.
     */
    std::unordered_set<NodeId> m_inbound_fanout_targets;

    /**
     * Next time m_inbound_fanout_targets need to be rotated.
     */
    std::chrono::microseconds GUARDED_BY(m_txreconciliation_mutex) m_next_inbound_peer_rotation_time{0};

    TxReconciliationState* GetRegisteredPeerState(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(m_txreconciliation_mutex)
    {
        AssertLockHeld(m_txreconciliation_mutex);
        auto salt_or_state = m_states.find(peer_id);
        if (salt_or_state == m_states.end()) return nullptr;

        return std::get_if<TxReconciliationState>(&salt_or_state->second);
    }

public:
    explicit Impl(uint32_t recon_version) : m_recon_version(recon_version) {}

    uint64_t PreRegisterPeer(NodeId peer_id, uint64_t local_salt) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Pre-register peer=%d\n", peer_id);

        // We do this exactly once per peer (which are unique by NodeId, see GetNewNodeId) so it's
        // safe to assume we don't have this record yet.
        Assume(m_states.emplace(peer_id, local_salt).second);
        return local_salt;
    }

    bool HasCollision(TxReconciliationState *peer_state, const Wtxid& wtxid, Wtxid& collision, uint32_t &short_id) EXCLUSIVE_LOCKS_REQUIRED(m_txreconciliation_mutex)
    {
        AssertLockHeld(m_txreconciliation_mutex);

        short_id = peer_state->ComputeShortID(wtxid);
        const auto iter = peer_state->m_short_id_mapping.find(short_id);

        if (iter != peer_state->m_short_id_mapping.end()) {
            collision = iter->second;
            return true;
        }

        return false;
    }

    ReconciliationRegisterResult RegisterPeer(NodeId peer_id, bool is_peer_inbound, uint32_t peer_recon_version,
                                              uint64_t remote_salt) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);

        if (recon_state == m_states.end()) return ReconciliationRegisterResult::NOT_FOUND;

        if (std::holds_alternative<TxReconciliationState>(recon_state->second)) {
            return ReconciliationRegisterResult::ALREADY_REGISTERED;
        }

        uint64_t local_salt = *std::get_if<uint64_t>(&recon_state->second);

        // If the peer supports the version which is lower than ours, we downgrade to the version
        // it supports. For now, this only guarantees that nodes with future reconciliation
        // versions have the choice of reconciling with this current version. However, they also
        // have the choice to refuse supporting reconciliations if the common version is not
        // satisfactory (e.g. too low).
        const uint32_t recon_version{std::min(peer_recon_version, m_recon_version)};
        // v1 is the lowest version, so suggesting something below must be a protocol violation.
        if (recon_version < 1) return ReconciliationRegisterResult::PROTOCOL_VIOLATION;

        LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Register peer=%d (inbound=%i)\n",
                      peer_id, is_peer_inbound);

        const uint256 full_salt{ComputeSalt(local_salt, remote_salt)};

        auto new_state = TxReconciliationState(!is_peer_inbound, full_salt.GetUint64(0), full_salt.GetUint64(1));;
        m_states.erase(recon_state);
        bool emplaced = m_states.emplace(peer_id, std::move(new_state)).second;
        Assume(emplaced);

        if (is_peer_inbound && m_inbounds_count < std::numeric_limits<size_t>::max()) {
            ++m_inbounds_count;

            if (m_inbound_fanout_targets.size() <  std::floor(m_inbounds_count * INBOUND_FANOUT_DESTINATIONS_FRACTION)) {
                // Scale up fanout targets as we get more connections. Targets will be rotated periodically via RotateInboundFanoutTargets
                if (FastRandomContext().randrange(10) <= INBOUND_FANOUT_DESTINATIONS_FRACTION * 10) {
                    m_inbound_fanout_targets.insert(peer_id);
                }
            }
        }
        return ReconciliationRegisterResult::SUCCESS;
    }

    AddToSetResult AddToSet(NodeId peer_id, const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return AddToSetResult::Failed();

        // Bypass if the wtxid is already in the set
        if (peer_state->m_local_set.contains(wtxid)) {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "%s already in reconciliation set for peer=%d. Bypassing.\n",
                          wtxid.ToString(), peer_id);
            return AddToSetResult::Succeeded();
        }

        // Make sure there is no short id collision between the wtxid we are trying to add
        // and any existing one in the reconciliation set
        Wtxid collision;
        uint32_t short_id;
        if (HasCollision(peer_state, wtxid, collision, short_id)) {
            return AddToSetResult::Collision(collision);
        }

        // Transactions which don't make it to the set due to the limit are announced via fanout.
        if (peer_state->m_local_set.size() >= MAX_RECONSET_SIZE) {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Reconciliation set maximum size reached for peer=%d.\n", peer_id);
            return AddToSetResult::Failed();
        }

        if (peer_state->m_local_set.insert(wtxid).second) {
            peer_state->m_short_id_mapping.emplace(short_id, wtxid);
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Added %s to the reconciliation set for peer=%d. "
                                                                        "Now the set contains %i transactions.\n",
                          wtxid.ToString(), peer_id, peer_state->m_local_set.size());
        }
        return AddToSetResult::Succeeded();
    }

    bool IsTransactionInSet(NodeId peer_id, const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return false;

        return peer_state->m_local_set.contains(wtxid);
    }

    bool TryRemovingFromSet(NodeId peer_id, const Wtxid& wtxid) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto peer_state = GetRegisteredPeerState(peer_id);
        if (!peer_state) return false;

        auto removed = peer_state->m_local_set.erase(wtxid) > 0;
        if (removed) {
            peer_state->m_short_id_mapping.erase(peer_state->ComputeShortID(wtxid));
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Removed %s from the reconciliation set for peer=%d. "
                                                                        "Now the set contains %i transactions.\n",
                          wtxid.ToString(), peer_id, peer_state->m_local_set.size());
        } else {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Couldn't remove %s from the reconciliation set for peer=%d. "
                                                                        "Transaction not found\n",
                          wtxid.ToString(), peer_id);
        }

        return removed;
    }

    void ForgetPeer(NodeId peer_id) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        const auto peer = m_states.find(peer_id);
        if (peer == m_states.end()) return;

        const auto registered = std::get_if<TxReconciliationState>(&peer->second);
        if (registered && !registered->m_we_initiate) {
            Assert(m_inbounds_count > 0);
            --m_inbounds_count;
            m_inbound_fanout_targets.erase(peer_id);
        }

        if (m_states.erase(peer_id)) {
            LogPrintLevel(BCLog::TXRECONCILIATION, BCLog::Level::Debug, "Forget txreconciliation state of peer=%d\n", peer_id);
        }
    }

    /**
     * For calls within this class use GetRegisteredPeerState instead.
     */
    bool IsPeerRegistered(NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex)
    {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        auto recon_state = m_states.find(peer_id);
        return (recon_state != m_states.end() &&
                std::holds_alternative<TxReconciliationState>(recon_state->second));
    }

    bool IsInboundFanoutTarget(NodeId peer_id) const EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex) {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        return m_inbound_fanout_targets.contains(peer_id);
    }

    std::chrono::microseconds GetNextInboundPeerRotationTime() EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex) {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        return m_next_inbound_peer_rotation_time;
    }

    void SetNextInboundPeerRotationTime(std::chrono::microseconds next_time) EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex) {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);
        m_next_inbound_peer_rotation_time = next_time;
    }

    void RotateInboundFanoutTargets() EXCLUSIVE_LOCKS_REQUIRED(!m_txreconciliation_mutex) {
        AssertLockNotHeld(m_txreconciliation_mutex);
        LOCK(m_txreconciliation_mutex);

        auto targets_size = std::floor(m_inbounds_count * INBOUND_FANOUT_DESTINATIONS_FRACTION);
        if (targets_size == 0) {
            return;
        }

        std::vector<NodeId> inbound_recon_peers;
        inbound_recon_peers.reserve(m_inbounds_count);

        // Collect all inbound reconciling peers ids in a vector and shuffle it
        for (const auto& [peer_id, op_peer_state]: m_states) {
            const auto peer_state = std::get_if<TxReconciliationState>(&op_peer_state);
            if (peer_state && !peer_state->m_we_initiate) {
                inbound_recon_peers.push_back(peer_id);
            }
        }
        std::shuffle(inbound_recon_peers.begin(), inbound_recon_peers.end(), FastRandomContext());

        // Pick the new selection of inbound fanout peers
        Assume(inbound_recon_peers.size() > targets_size);
        m_inbound_fanout_targets.clear();
        m_inbound_fanout_targets.reserve(targets_size);
        m_inbound_fanout_targets.insert(inbound_recon_peers.begin(), inbound_recon_peers.begin() + targets_size);

    }
};

AddToSetResult::AddToSetResult(bool succeeded, std::optional<Wtxid> collision)
{
    m_succeeded = succeeded;
    m_collision = collision;
}

AddToSetResult AddToSetResult::Succeeded()
{
    return AddToSetResult(true, std::nullopt);
}

AddToSetResult AddToSetResult::Failed()
{
    return AddToSetResult(false, std::nullopt);
}

AddToSetResult AddToSetResult::Collision(Wtxid wtxid)
{
    return AddToSetResult(false, std::make_optional(wtxid));
}

TxReconciliationTracker::TxReconciliationTracker(uint32_t recon_version) : m_impl{std::make_unique<TxReconciliationTracker::Impl>(recon_version)} {}

TxReconciliationTracker::~TxReconciliationTracker() = default;

uint64_t TxReconciliationTracker::PreRegisterPeer(NodeId peer_id)
{
    const uint64_t local_salt{FastRandomContext().rand64()};
    return m_impl->PreRegisterPeer(peer_id, local_salt);
}

void TxReconciliationTracker::PreRegisterPeerWithSalt(NodeId peer_id, uint64_t local_salt)
{
    m_impl->PreRegisterPeer(peer_id, local_salt);
}

ReconciliationRegisterResult TxReconciliationTracker::RegisterPeer(NodeId peer_id, bool is_peer_inbound,
                                                          uint32_t peer_recon_version, uint64_t remote_salt)
{
    return m_impl->RegisterPeer(peer_id, is_peer_inbound, peer_recon_version, remote_salt);
}

AddToSetResult TxReconciliationTracker::AddToSet(NodeId peer_id, const Wtxid& wtxid)
{
    return m_impl->AddToSet(peer_id, wtxid);
}

bool TxReconciliationTracker::IsTransactionInSet(NodeId peer_id, const Wtxid& wtxid)
{
    return m_impl->IsTransactionInSet(peer_id, wtxid);
}


bool TxReconciliationTracker::TryRemovingFromSet(NodeId peer_id, const Wtxid& wtxid)
{
    return m_impl->TryRemovingFromSet(peer_id, wtxid);
}

void TxReconciliationTracker::ForgetPeer(NodeId peer_id)
{
    m_impl->ForgetPeer(peer_id);
}

bool TxReconciliationTracker::IsPeerRegistered(NodeId peer_id) const
{
    return m_impl->IsPeerRegistered(peer_id);
}

bool TxReconciliationTracker::IsInboundFanoutTarget(NodeId peer_id)
{
    return m_impl->IsInboundFanoutTarget(peer_id);
}

std::chrono::microseconds TxReconciliationTracker::GetNextInboundPeerRotationTime(){
    return m_impl->GetNextInboundPeerRotationTime();
}

void TxReconciliationTracker::SetNextInboundPeerRotationTime(std::chrono::microseconds next_time) {
    return m_impl->SetNextInboundPeerRotationTime(next_time);
}

void TxReconciliationTracker::RotateInboundFanoutTargets()
{
    return m_impl->RotateInboundFanoutTargets();
}
