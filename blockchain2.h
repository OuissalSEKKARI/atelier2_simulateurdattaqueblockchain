#pragma once
// blockchain2.h
// Reprise QUASI-VERBATIM des classes Transaction / Validator / Block / Blockchain
// de l'atelier 1 (ex4.cpp), factorisées ici dans un header pour être réutilisées
// par la plateforme de l'atelier 2 (simulation/détection d'attaques).
// Seuls ajouts : quelques accesseurs utilitaires nécessaires aux attaques
// (clairement marqués "AJOUT ATELIER 2"), le reste est inchangé.

#include "sha256.h"
#include "merkle.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <ctime>
#include <cstdint>

using namespace std;
using Clock = chrono::steady_clock;

enum class Consensus { POW, POS };
inline string cname(Consensus c) { return c == Consensus::POW ? "PoW" : "PoS"; }

struct Transaction {
    string from, to;
    double amount;
    string str() const {
        ostringstream o;
        o << from << "->" << to << ":" << fixed << setprecision(2) << amount;
        return o.str();
    }
};

struct Validator { string name; double stake; string secret; };

struct Block {
    int index = 0;
    long timestamp = 0;
    vector<Transaction> txs;
    string merkleRoot;
    string prevHash;
    uint64_t nonce = 0;
    string validator;
    string signature;
    string hash;

    string computeMerkle() const {
        vector<string> v;
        for (auto& t : txs) v.push_back(t.str());
        return MerkleTree(v).root();
    }
    string computeHash() const {
        return sha256(to_string(index) + "|" + to_string(timestamp) + "|" + merkleRoot + "|" +
                      prevHash + "|" + to_string(nonce) + "|" + validator);
    }
};

class Blockchain {
public:
    vector<Block> chain;
    vector<Transaction> pending;
    vector<Validator> validators;
    Consensus mode;
    int difficulty;
    mt19937 rng;

    Blockchain(Consensus m, int diff = 4, unsigned seed = 42) : mode(m), difficulty(diff), rng(seed) {
        validators = {{"Alice", 50, "kA"}, {"Bob", 30, "kB"}, {"Carol", 20, "kC"}};

        Block g;
        g.index = 0; g.timestamp = time(nullptr); g.prevHash = "0"; g.validator = "GENESIS";
        g.txs = {{"SYSTEM", "Alice", 100}, {"SYSTEM", "Bob", 100}, {"SYSTEM", "Carol", 100}};
        g.merkleRoot = g.computeMerkle();
        g.hash = g.computeHash();
        chain.push_back(g);
    }

    double balanceOf(const string& who, bool includePending = true) const {
        double b = 0;
        auto apply = [&](const Transaction& t) {
            if (t.to == who) b += t.amount;
            if (t.from == who) b -= t.amount;
        };
        for (auto& blk : chain) for (auto& t : blk.txs) apply(t);
        if (includePending) for (auto& t : pending) apply(t);
        return b;
    }

    bool addTransaction(const string& from, const string& to, double amount) {
        if (amount <= 0) return false;
        if (from != "SYSTEM" && balanceOf(from) < amount) return false;
        pending.push_back({from, to, amount});
        return true;
    }

    int selectValidator() {
        vector<double> w;
        for (auto& v : validators) w.push_back(v.stake);
        discrete_distribution<int> d(w.begin(), w.end());
        return d(rng);
    }

    double minePending() {
        if (pending.empty()) return 0;
        auto t0 = Clock::now();
        Block b;
        b.index = (int)chain.size();
        b.timestamp = time(nullptr);
        b.txs = pending;
        b.merkleRoot = b.computeMerkle();
        b.prevHash = chain.back().hash;
        if (mode == Consensus::POW) {
            string target(difficulty, '0');
            b.hash = b.computeHash();
            while (b.hash.compare(0, difficulty, target) != 0) { ++b.nonce; b.hash = b.computeHash(); }
        } else {
            Validator& v = validators[selectValidator()];
            b.validator = v.name;
            b.hash = b.computeHash();
            b.signature = sha256(v.secret + b.hash);
            v.stake += 1;
        }
        chain.push_back(b);
        pending.clear();
        return chrono::duration<double, milli>(Clock::now() - t0).count();
    }

    const Validator* findValidator(const string& n) const {
        for (auto& v : validators) if (v.name == n) return &v;
        return nullptr;
    }

    bool isValid(int* bad = nullptr, string* reason = nullptr) const {
        string target(difficulty, '0');
        for (size_t i = 0; i < chain.size(); ++i) {
            const Block& b = chain[i];
            string why;
            if (b.merkleRoot != b.computeMerkle()) why = "racine de Merkle incoherente";
            else if (b.hash != b.computeHash()) why = "hash du bloc incoherent";
            else if (i > 0 && b.prevHash != chain[i-1].hash) why = "chainage rompu";
            else if (i > 0 && mode == Consensus::POW && b.hash.compare(0, difficulty, target) != 0)
                why = "preuve de travail invalide";
            else if (i > 0 && mode == Consensus::POS) {
                const Validator* v = findValidator(b.validator);
                if (!v) why = "validateur inconnu";
                else if (b.signature != sha256(v->secret + b.hash)) why = "signature du validateur invalide";
            }
            if (!why.empty()) { if (bad) *bad = (int)i; if (reason) *reason = why; return false; }
        }
        return true;
    }

    // ---------------- AJOUT ATELIER 2 ----------------
    // Mine un seul bloc à partir de "pending" SANS le committer dans "chain" :
    // utilisé par les attaques pour construire une chaîne privée / retenue.
    Block mineOneDetached(const vector<Transaction>& txs, const string& prevHash) {
        Block b;
        b.index = 0; // recalculé par l'appelant selon la position dans la fourche
        b.timestamp = time(nullptr);
        b.txs = txs;
        b.merkleRoot = b.computeMerkle();
        b.prevHash = prevHash;
        if (mode == Consensus::POW) {
            string target(difficulty, '0');
            b.hash = b.computeHash();
            while (b.hash.compare(0, difficulty, target) != 0) { ++b.nonce; b.hash = b.computeHash(); }
        } else {
            Validator& v = validators[selectValidator()];
            b.validator = v.name;
            b.hash = b.computeHash();
            b.signature = sha256(v.secret + b.hash);
        }
        return b;
    }
    // ---------------------------------------------------
};
