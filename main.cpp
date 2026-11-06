// main.cpp — Atelier 2 : plateforme de simulation/détection d'attaques
// Construit directement sur blockchain2.h (= classes de l'atelier 1, ex4.cpp)
#include "blockchain2.h"
#include "attacks.h"
#include "detector.h"
#include <iostream>
#include <fstream>
#include <iomanip>

using namespace std;

void section(const string& title) {
    cout << "\n==================================================================\n";
    cout << "  " << title << "\n";
    cout << "==================================================================\n";
}

// ---------------------------------------------------------------------
// Expérience 1 : 51% Attack — référence / attaquée / protégée, pour
// plusieurs parts de hash-rate de l'attaquant.
// ---------------------------------------------------------------------
void experiment_fifty_one(ofstream& csv) {
    section("EXPERIENCE 1 : 51% ATTACK (double depense + reorg)");
    vector<double> shares = {0.10, 0.30, 0.45, 0.51, 0.60};
    int rounds = 120, leadToRelease = 2, difficulty = 3;

    cout << left << setw(8) << "share" << setw(12) << "config"
         << setw(10) << "orphans" << setw(12) << "reorgs"
         << setw(16) << "ds_success_%" << setw(14) << "fixed_P/R"
         << setw(16) << "adaptive_P/R" << "\n";

    for (double share : shares) {
        for (int protectedMode = 0; protectedMode <= 1; ++protectedMode) {
            if (share < 0.5 && protectedMode == 1) continue; // protection surtout utile >=0.5
            ReorgGuard guard{0};
            auto res = runFiftyOnePercentAttack(share, rounds, leadToRelease, difficulty, 42,
                                                 protectedMode ? &guard : nullptr);

            FixedThresholdDetector fixedDet(0.15, 1);
            AdaptiveDetector adaptDet(3.0, 20, 8);
            for (auto& m : res.metrics) { fixedDet.update(m); adaptDet.update(m); }
            auto fixedEval = evaluate(res.metrics, fixedDet.alerts);
            auto adaptEval = evaluate(res.metrics, adaptDet.alerts);

            double dsRate = res.doubleSpendAttempts ? 100.0 * res.doubleSpendSuccesses / res.doubleSpendAttempts : 0.0;
            string config = protectedMode ? "protected" : "attacked";

            cout << left << setw(8) << share << setw(12) << config
                 << setw(10) << res.totalOrphans << setw(12) << res.reorgCount
                 << setw(16) << dsRate
                 << setw(16) << (to_string(fixedEval.precision).substr(0,4) + "/" + to_string(fixedEval.recall).substr(0,4))
                 << setw(16) << (to_string(adaptEval.precision).substr(0,4) + "/" + to_string(adaptEval.recall).substr(0,4))
                 << "\n";

            csv << "fifty_one," << share << "," << config << "," << res.totalOrphans << ","
                << res.reorgCount << "," << dsRate << "," << fixedEval.precision << "," << fixedEval.recall
                << "," << adaptEval.precision << "," << adaptEval.recall << ","
                << (protectedMode ? guard.blockedCount : 0) << "," << res.finalChain.isValid() << "\n";
        }
    }
}

// ---------------------------------------------------------------------
// Expérience 2 : Selfish Mining
// ---------------------------------------------------------------------
void experiment_selfish(ofstream& csv) {
    section("EXPERIENCE 2 : SELFISH MINING");
    vector<double> shares = {0.10, 0.25, 0.33, 0.45};
    int rounds = 150, difficulty = 3;

    cout << left << setw(10) << "share" << setw(16) << "attacker_won"
         << setw(18) << "wasted_honest" << setw(16) << "reward_share_%\n";

    for (double share : shares) {
        auto res = runSelfishMining(share, rounds, difficulty, 42);
        double rewardShare = res.totalBlocksMined ? 100.0 * res.attackerBlocksWon / res.totalBlocksMined : 0.0;
        cout << left << setw(10) << share << setw(16) << res.attackerBlocksWon
             << setw(18) << res.wastedHonestBlocks << setw(16) << rewardShare << "\n";
        csv << "selfish_mining," << share << ",attacked," << res.wastedHonestBlocks << ","
            << res.attackerBlocksWon << "," << rewardShare << ",,,,,,"
            << res.finalChain.isValid() << "\n";
    }
}

// ---------------------------------------------------------------------
// Expérience 3 : Block Withholding (PoS, sabotage de pool)
// ---------------------------------------------------------------------
void experiment_withholding(ofstream& csv) {
    section("EXPERIENCE 3 : BLOCK WITHHOLDING (sabotage dans une pool PoS)");
    vector<double> probs = {0.0, 0.3, 0.6, 1.0};
    int rounds = 150;

    cout << left << setw(14) << "withhold_p" << setw(16) << "rounds_lost"
         << setw(20) << "pct_rounds_lost" << "blocks_by_Alice\n";

    for (double p : probs) {
        auto res = runBlockWithholding("Alice", p, rounds, 42);
        double pctLost = 100.0 * res.withheldCount / res.roundsRun;
        cout << left << setw(14) << p << setw(16) << res.withheldCount
             << setw(20) << pctLost << res.blocksWonByValidator["Alice"] << "\n";
        csv << "block_withholding," << p << ",attacked," << res.withheldCount << ",,"
            << pctLost << ",,,,,," << res.finalChain.isValid() << "\n";
    }
}

// ---------------------------------------------------------------------
// Expérience 4 : Sybil Attack (PoS, multiplication d'identités)
// ---------------------------------------------------------------------
void experiment_sybil(ofstream& csv) {
    section("EXPERIENCE 4 : SYBIL ATTACK (multiplication d'identites PoS)");
    vector<int> nIds = {0, 5, 10, 20};
    double stakePerId = 2.0;
    int rounds = 150;

    cout << left << setw(14) << "n_identites" << setw(18) << "stake_reel_%"
         << setw(18) << "blocs_gagnes_%" << "amplification\n";

    for (int n : nIds) {
        auto res = runSybilAttack(n, stakePerId, rounds, 42);
        double amp = res.realStakeShare > 0 ? res.blocksWonShare / res.realStakeShare : 0.0;
        cout << left << setw(14) << n << setw(18) << (100.0 * res.realStakeShare)
             << setw(18) << (100.0 * res.blocksWonShare) << amp << "\n";
        csv << "sybil," << n << ",attacked,,," << (100.0 * res.blocksWonShare) << ",,,,,"
            << (100.0 * res.realStakeShare) << "," << res.finalChain.isValid() << "\n";
    }
}

int main() {
    cout << "########## ATELIER 2 : SIMULATION ET DETECTION D'ATTAQUES BLOCKCHAIN ##########\n";
    cout << "(construit sur les classes Block/Blockchain/Validator de l'atelier 1)\n";

    ofstream csv("results.csv");
    csv << "attack,param,config,orphans_or_count,reorgs_or_won,rate_pct,fixed_precision,fixed_recall,"
        << "adaptive_precision,adaptive_recall,extra,chain_valid\n";

    experiment_fifty_one(csv);
    experiment_selfish(csv);
    experiment_withholding(csv);
    experiment_sybil(csv);

    csv.close();
    cout << "\nCSV ecrit : results.csv\n";
    return 0;
}
