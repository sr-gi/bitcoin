BOOST_AUTO_TEST_CASE(HandleSketchBasicFlowTest) {
    TxReconciliationTracker tracker(TXRECONCILIATION_VERSION, INBOUND_FANOUT_DESTINATIONS_FRACTION, OUTBOUND_FANOUT_THRESHOLD);
    NodeId peer_id0 = 0;

    std::vector<uint8_t> skdata{};
    std::vector<uint32_t> txs_to_request{};
    std::vector<Wtxid> txs_to_announce{};
    std::optional<bool> recon_result;

    // We cannot respond to partially registered peers
    BOOST_CHECK(!tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
    tracker.PreRegisterPeer(peer_id0);
    BOOST_CHECK(!tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));

    // Only reply if we have initiated a request
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, /*is_peer_inbound*/false, TXRECONCILIATION_VERSION, 1), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(!tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
    BOOST_CHECK(tracker.InitiateReconciliationRequest(peer_id0).has_value());
    BOOST_CHECK(tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));

    // Only reply if we are the initiator (peer is outbound)
    tracker.ForgetPeer(peer_id0);
    tracker.PreRegisterPeer(peer_id0);
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, /*is_peer_inbound*/true, TXRECONCILIATION_VERSION, 1), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(!tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
}

BOOST_AUTO_TEST_CASE(HandleSketchTest) {
    TxReconciliationTracker tracker(TXRECONCILIATION_VERSION, INBOUND_FANOUT_DESTINATIONS_FRACTION, OUTBOUND_FANOUT_THRESHOLD);
    NodeId peer_id0 = 0;
    FastRandomContext frc{/*fDeterministic=*/true};

    std::vector<uint8_t> skdata{};
    std::vector<uint32_t> txs_to_request{};
    std::vector<Wtxid> txs_to_announce{};
    std::optional<bool> recon_result;

    // Lambda to add random wtxids to a peer's reconciliation set
    auto add_txs_to_reconset = [&](NodeId peer_id, std::vector<Wtxid>& added_txs, int n_txs_to_add) {
        added_txs.clear();
        auto n_added_txs{0};

        while(n_added_txs < n_txs_to_add) {
            auto wtxid = Wtxid::FromUint256(frc.rand256());
            if (tracker.AddToSet(peer_id, wtxid).m_succeeded) {
                added_txs.push_back(wtxid);
                ++n_added_txs;
            }
        }
    };

    // Setup a peer we have initiated a reconciliation with
    tracker.ForgetPeer(peer_id0);
    tracker.PreRegisterPeer(peer_id0);
    BOOST_REQUIRE_EQUAL(tracker.RegisterPeer(peer_id0, /*is_peer_inbound*/false, TXRECONCILIATION_VERSION, 1), ReconciliationRegisterResult::SUCCESS);
    BOOST_CHECK(tracker.InitiateReconciliationRequest(peer_id0).has_value());

    // If we have nothing to reconcile with the peer, shortcut and send all transactions.
    // This will trigger the peer sending all their pending transactions to us
    skdata.resize(0, BYTES_PER_SKETCH_CAPACITY);
    BOOST_CHECK(tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
    BOOST_REQUIRE_EQUAL(recon_result, std::optional(false));
    BOOST_CHECK(txs_to_announce.empty());
    BOOST_CHECK(txs_to_request.empty());

    // If their sketch is empty, reconciliation shortcuts and we announce all pending transactions
    BOOST_CHECK(tracker.InitiateReconciliationRequest(peer_id0).has_value());
    skdata.clear();
    auto n_txs_to_add = frc.randrange(42) + 1;
    std::vector<Wtxid> added_txs{};
    add_txs_to_reconset(peer_id0, added_txs, n_txs_to_add);

    BOOST_CHECK(tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
    BOOST_REQUIRE_EQUAL(recon_result, std::optional(false));
    BOOST_CHECK(std::is_permutation(txs_to_announce.begin(), txs_to_announce.end(), added_txs.begin(), added_txs.end()));
    BOOST_CHECK(txs_to_request.empty());
     // After a successful reconciliation, the sets are emptied
    add_txs_to_reconset(peer_id0, added_txs, n_txs_to_add);
    txs_to_announce.clear();

    // After successfully handling a Sketch the peer's phase is reset to NONE (even if we shortcut), so we won't handle another one
    BOOST_CHECK(!tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
    BOOST_CHECK(txs_to_announce.empty());
    BOOST_CHECK(txs_to_request.empty());

    // If the peer provided a non-empty sketch, its size need to be valid (multiple of the element size and within bounds)
    BOOST_CHECK(tracker.InitiateReconciliationRequest(peer_id0).has_value()); // Re set the peer's phase
    recon_result = std::nullopt;
    BOOST_CHECK(txs_to_announce.empty());
    BOOST_CHECK(txs_to_request.empty());

    // Not multiple of the element size
    skdata.push_back(0);
    BOOST_CHECK(!tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
    BOOST_CHECK(recon_result == std::nullopt);
    BOOST_CHECK(txs_to_announce.empty());
    BOOST_CHECK(txs_to_request.empty());

    // Over the limit
    skdata.resize((MAX_SKETCH_CAPACITY + 1) * BYTES_PER_SKETCH_CAPACITY, 0);
    BOOST_CHECK(!tracker.HandleSketch(peer_id0, skdata, txs_to_request, txs_to_announce, recon_result));
    BOOST_CHECK(recon_result == std::nullopt);
    BOOST_CHECK(txs_to_announce.empty());
    BOOST_CHECK(txs_to_request.empty());

    // If the peer sketch has data and we also have data for the peer, we reconcile normally:
    // Create a valid sketch with part of the data we have for the peer. Give enough capacity for
    // all transactions to differ, even though not all will
    std::vector<Wtxid> expected_txs_to_announce{};
    std::vector<uint32_t> expected_txs_to_request{};
    std::set<uint32_t> added_shortids{};

    Minisketch remote_sketch = node::MakeMinisketch32(BYTES_PER_SKETCH_CAPACITY * n_txs_to_add);
    // Add a few transaction we already know to the peer's sketch
    for (size_t i=0; i < added_txs.size(); i++) {
        auto* state = TxReconciliationTestHelper::GetState(tracker, peer_id0);
        auto short_id = tracker.ComputeShortIDForPeer(peer_id0, added_txs[i]);
        if (i % 2 == 0) {
            remote_sketch.Add(short_id);
            added_shortids.insert(short_id);
        } else {
            expected_txs_to_announce.push_back(added_txs[i]);
        }
    }
    // Also add a few that we don't know
    for (size_t i=0; i < added_txs.size() / 2; i++) {
        auto short_id = tracker.ComputeShortIDForPeer(peer_id0, Wtxid::FromUint256(frc.rand256()));
        // Make sure there are no collisions
        if (!added_shortids.contains(short_id)) {
            remote_sketch.Add(short_id);
            expected_txs_to_request.push_back(short_id);
        }
    }

    BOOST_CHECK(tracker.HandleSketch(peer_id0, remote_sketch.Serialize(), txs_to_request, txs_to_announce, recon_result));
    BOOST_CHECK(recon_result == std::optional(true));
    BOOST_CHECK(std::is_permutation(txs_to_request.begin(), txs_to_request.end(), expected_txs_to_request.begin(), expected_txs_to_request.end()));
    BOOST_CHECK(std::is_permutation(txs_to_announce.begin(), txs_to_announce.end(), expected_txs_to_announce.begin(), expected_txs_to_announce.end()));
}
