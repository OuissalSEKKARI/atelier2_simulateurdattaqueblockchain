#pragma once
#include "sha256.h"
#include <vector>
#include <string>
#include <iostream>

struct ProofStep {
    std::string hash;  
    bool siblingIsLeft; 
};

class MerkleTree {
public:
   
    std::vector<std::vector<std::string>> levels;

    explicit MerkleTree(const std::vector<std::string>& data) {
        if (data.empty()) { levels.push_back({sha256("")}); return; }
        std::vector<std::string> cur;
        for (const auto& d : data) cur.push_back(sha256(d));
        levels.push_back(cur);
        while (cur.size() > 1) {
            std::vector<std::string> next;
            for (size_t i = 0; i < cur.size(); i += 2) {
                const std::string& left = cur[i];
                const std::string& right = (i + 1 < cur.size()) ? cur[i + 1] : cur[i];
                next.push_back(sha256(left + right));
            }
            levels.push_back(next);
            cur = next;
        }
    }

    std::string root() const { return levels.back()[0]; }

   
    std::vector<ProofStep> proof(size_t idx) const {
        std::vector<ProofStep> p;
        for (size_t lvl = 0; lvl + 1 < levels.size(); ++lvl) {
            const auto& nodes = levels[lvl];
            size_t sib = (idx % 2 == 0) ? idx + 1 : idx - 1;
            if (sib >= nodes.size()) sib = idx;   
            p.push_back({nodes[sib], idx % 2 == 1});
            idx /= 2;
        }
        return p;
    }

    
    static bool verify(const std::string& data, const std::vector<ProofStep>& proof,
                       const std::string& expectedRoot) {
        std::string h = sha256(data);
        for (const auto& s : proof)
            h = s.siblingIsLeft ? sha256(s.hash + h) : sha256(h + s.hash);
        return h == expectedRoot;
    }

    void print() const {
        for (int lvl = (int)levels.size() - 1; lvl >= 0; --lvl) {
            if (lvl == (int)levels.size() - 1) std::cout << "  Racine   : ";
            else if (lvl == 0)                 std::cout << "  Feuilles : ";
            else                               std::cout << "  Niveau " << lvl << "  : ";
            for (const auto& h : levels[lvl]) std::cout << h.substr(0, 8) << "  ";
            std::cout << "\n";
        }
    }
};
