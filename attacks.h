#pragma once
// attacks.h
// Les 4 attaques demandées, construites sur les classes Block/Blockchain/
// Validator réutilisées telles quelles depuis l'atelier 1 (blockchain2.h).
// Simulation par "rounds" : à chaque round, un tirage pondéré par la part de
// hash-rate (PoW) ou de stake (PoS) décide qui mine le prochain bloc.
#include "blockchain2.h"
#include <random>
#include <algorithm>
#include <map>
#include <deque>

struct RoundMetric {
    int round;
    double orphan_rate_window;   // part de blocs orphelins sur une fenêtre glissante
    int reorg_depth;             // profondeur du dernier reorg survenu à ce round (0 sinon)
    double top_miner_share;      // part de blocs du mineur/validateur dominant sur une fenêtre
};

// ---------------------------------------------------------------------
// 1) 51% ATTACK (PoW) : double dépense + réorganisation de chaîne
// ---------------------------------------------------------------------
struct FiftyOneResult {
    Blockchain finalChain;
    int totalOrphans = 0;
    int reorgCount = 0;
    int doubleSpendAttempts = 0;
    int doubleSpendSuccesses = 0;
    vector<RoundMetric> metrics;
    FiftyOneResult(Consensus m, int diff, unsigned seed) : finalChain(m, diff, seed) {}
};

// forward-déclaré ici, défini dans detector.h (inclus après dans les .cpp) ;
// on utilise un pointeur void + callback pour éviter une dépendance circulaire.
struct ReorgGuard {
    int maxDepth;
    int blockedCount = 0;
    bool allow(int depth) { if (depth > maxDepth) { blockedCount++; return false; } return true; }
};

inline FiftyOneResult runFiftyOnePercentAttack(double attackerShare, int rounds,
                                                int leadToRelease, int difficulty, unsigned seed,
                                                ReorgGuard* guard = nullptr) {
    FiftyOneResult res(Consensus::POW, difficulty, seed);
    Blockchain& honest = res.finalChain;
    Blockchain attackerView(Consensus::POW, difficulty, seed + 1); // moteur de minage de l'attaquant
    mt19937 coin(seed + 2);
    bernoulli_distribution attackerWins(attackerShare);

    vector<Block> privateChain;
    string forkPoint = honest.chain.back().hash;
    int forkHeight = (int)honest.chain.size() - 1;

    deque<int> recentOrphanFlags; // fenêtre glissante pour le détecteur
    const size_t WINDOW = 10;

    auto pushMetric = [&](int round, int reorgDepthThisRound) {
        double orphanRate = recentOrphanFlags.empty() ? 0.0 :
            (double)std::count(recentOrphanFlags.begin(), recentOrphanFlags.end(), 1) / recentOrphanFlags.size();
        res.metrics.push_back({round, orphanRate, reorgDepthThisRound, attackerShare});
    };

    for (int r = 0; r < rounds; ++r) {
        honest.addTransaction("Alice", "Bob", 1);
        bool won = attackerWins(coin);
        int reorgDepthThisRound = 0;

        if (!won) {
            // bloc honnête : mine et publie normalement
            honest.minePending();
            recentOrphanFlags.push_back(0);
        } else {
            // bloc attaquant : retenu (construit sur le dernier bloc privé, ou sur le fork point)
            string parent = privateChain.empty() ? forkPoint : privateChain.back().hash;
            Block b = attackerView.mineOneDetached(honest.pending, parent);
            b.index = forkHeight + 1 + (int)privateChain.size();
            honest.pending.clear();
            privateChain.push_back(b);
            recentOrphanFlags.push_back(0);

            if ((int)privateChain.size() >= leadToRelease) {
                res.doubleSpendAttempts++;
                int publicHeight = (int)honest.chain.size() - 1;
                int privateTipHeight = forkHeight + (int)privateChain.size();
                if (privateTipHeight > publicHeight) {
                    int orphanedHonestBlocks = publicHeight - forkHeight;
                    bool allowed = (guard == nullptr) || guard->allow(orphanedHonestBlocks);
                    if (allowed) {
                        if (orphanedHonestBlocks > 0) {
                            res.reorgCount++;
                            res.totalOrphans += orphanedHonestBlocks;
                            reorgDepthThisRound = orphanedHonestBlocks;
                            for (int k = 0; k < orphanedHonestBlocks; ++k) recentOrphanFlags.push_back(1);
                        }
                        honest.chain.resize(forkHeight + 1);
                        for (auto& pb : privateChain) honest.chain.push_back(pb);
                        res.doubleSpendSuccesses++;
                    }
                    // si refusé par la contre-mesure : la chaîne privée est abandonnée
                    // (le reorg n'a pas lieu, la chaîne publique reste inchangée)
                }
                privateChain.clear();
                forkPoint = honest.chain.back().hash;
                forkHeight = (int)honest.chain.size() - 1;
            }
        }
        while (recentOrphanFlags.size() > WINDOW) recentOrphanFlags.pop_front();
        pushMetric(r, reorgDepthThisRound);
    }
    return res;
}

// ---------------------------------------------------------------------
// 2) SELFISH MINING (PoW) : rétention + publication stratégique
// ---------------------------------------------------------------------
struct SelfishResult {
    Blockchain finalChain;
    int attackerBlocksWon = 0;
    int wastedHonestBlocks = 0;
    int totalBlocksMined = 0;
    vector<RoundMetric> metrics;
    SelfishResult(Consensus m, int diff, unsigned seed) : finalChain(m, diff, seed) {}
};

inline SelfishResult runSelfishMining(double attackerShare, int rounds, int difficulty, unsigned seed) {
    SelfishResult res(Consensus::POW, difficulty, seed);
    Blockchain& honest = res.finalChain;
    Blockchain attackerView(Consensus::POW, difficulty, seed + 1);
    mt19937 coin(seed + 2);
    bernoulli_distribution attackerWins(attackerShare);

    vector<Block> lead; // avance privée de l'attaquant (0 ou 1 bloc typiquement)
    string base = honest.chain.back().hash;
    int baseHeight = (int)honest.chain.size() - 1;
    deque<int> recentOrphanFlags;
    const size_t WINDOW = 10;

    auto publishLead = [&]() {
        if (lead.empty()) return;
        int publicHeight = (int)honest.chain.size() - 1;
        int leadTipHeight = baseHeight + (int)lead.size();
        if (leadTipHeight > publicHeight) {
            int orphaned = publicHeight - baseHeight;
            if (orphaned > 0) { res.wastedHonestBlocks += orphaned; }
            honest.chain.resize(baseHeight + 1);
            for (auto& b : lead) honest.chain.push_back(b);
            res.attackerBlocksWon += (int)lead.size();
        }
        lead.clear();
        base = honest.chain.back().hash;
        baseHeight = (int)honest.chain.size() - 1;
    };

    for (int r = 0; r < rounds; ++r) {
        honest.addTransaction("Alice", "Bob", 1);
        bool won = attackerWins(coin);
        res.totalBlocksMined++;
        if (!won) {
            honest.minePending();
            recentOrphanFlags.push_back(0);
            // un bloc honnête vient d'être publié : si on a 1 bloc d'avance, on la relâche pour contrer
            if (!lead.empty()) publishLead();
        } else {
            string parent = lead.empty() ? base : lead.back().hash;
            Block b = attackerView.mineOneDetached(honest.pending, parent);
            b.index = baseHeight + 1 + (int)lead.size();
            honest.pending.clear();
            lead.push_back(b);
            recentOrphanFlags.push_back(0);
            if (lead.size() >= 2) publishLead(); // publie dès 2 blocs d'avance
        }
        while (recentOrphanFlags.size() > WINDOW) recentOrphanFlags.pop_front();
        double orphanRate = recentOrphanFlags.empty() ? 0.0 :
            (double)std::count(recentOrphanFlags.begin(), recentOrphanFlags.end(), 1) / recentOrphanFlags.size();
        res.metrics.push_back({r, orphanRate, 0, attackerShare});
    }
    return res;
}

// ---------------------------------------------------------------------
// 3) BLOCK WITHHOLDING (PoS) : un membre de la pool retient ses blocs
// ---------------------------------------------------------------------
struct WithholdResult {
    Blockchain finalChain;
    int withheldCount = 0;
    int roundsRun = 0;
    map<string, int> blocksWonByValidator;
    WithholdResult(Consensus m, int diff, unsigned seed) : finalChain(m, diff, seed) {}
};

inline WithholdResult runBlockWithholding(const string& saboteurName, double withholdProb,
                                          int rounds, unsigned seed) {
    WithholdResult res(Consensus::POS, 0, seed);
    Blockchain& bc = res.finalChain;
    mt19937 coin(seed + 7);
    uniform_real_distribution<double> u(0.0, 1.0);

    for (int r = 0; r < rounds; ++r) {
        bc.addTransaction("Alice", "Bob", 1);
        int idx = bc.selectValidator();
        string chosen = bc.validators[idx].name;
        res.roundsRun++;
        if (chosen == saboteurName && u(coin) < withholdProb) {
            // le validateur saboteur a été choisi mais ne soumet pas de bloc : tour perdu
            res.withheldCount++;
            bc.pending.clear(); // transactions non traitées ce tour (perte pour la pool)
            continue;
        }
        bc.minePending();
        res.blocksWonByValidator[chosen]++;
    }
    return res;
}

// ---------------------------------------------------------------------
// 4) SYBIL ATTACK (PoS) : multiplication d'identités contrôlées par un
//    même attaquant pour gonfler sa probabilité d'être choisi.
// ---------------------------------------------------------------------
struct SybilResult {
    Blockchain finalChain;
    double realStakeShare = 0.0;     // part de stake "légitime" réellement apportée par l'attaquant
    double blocksWonShare = 0.0;     // part de blocs effectivement remportés par ses identités
    map<string, int> blocksWonByValidator;
    SybilResult(Consensus m, int diff, unsigned seed) : finalChain(m, diff, seed) {}
};

inline SybilResult runSybilAttack(int nSybilIdentities, double stakePerIdentity, int rounds, unsigned seed) {
    SybilResult res(Consensus::POS, 0, seed);
    Blockchain& bc = res.finalChain;

    double honestStakeBefore = 0;
    for (auto& v : bc.validators) honestStakeBefore += v.stake;

    vector<string> sybilIds;
    for (int i = 0; i < nSybilIdentities; ++i) {
        string name = "sybil_" + to_string(i);
        bc.validators.push_back({name, stakePerIdentity, "secret_" + name});
        sybilIds.push_back(name);
    }
    double sybilStakeTotal = nSybilIdentities * stakePerIdentity;
    res.realStakeShare = sybilStakeTotal / (honestStakeBefore + sybilStakeTotal);

    for (int r = 0; r < rounds; ++r) {
        bc.addTransaction("Alice", "Bob", 1);
        bc.minePending();
        res.blocksWonByValidator[bc.chain.back().validator]++;
    }

    int sybilWins = 0, totalWins = 0;
    for (auto& [name, n] : res.blocksWonByValidator) {
        totalWins += n;
        if (std::find(sybilIds.begin(), sybilIds.end(), name) != sybilIds.end()) sybilWins += n;
    }
    res.blocksWonShare = totalWins ? (double)sybilWins / totalWins : 0.0;
    return res;
}
