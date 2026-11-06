#pragma once
// detector.h
// FixedThresholdDetector (référence) vs AdaptiveDetector (contribution :
// seuil = moyenne mobile + k * écart-type), + évaluation précision/rappel,
// + une contre-mesure simple (limite de profondeur de reorg).
#include "attacks.h"
#include <deque>
#include <cmath>

struct DetectorEval {
    double precision = 0, recall = 0;
    int tp = 0, fp = 0, fn = 0, tn = 0;
};

class FixedThresholdDetector {
public:
    double orphanRateTh;
    int reorgDepthTh;
    vector<int> alerts; // rounds où une alerte a été levée

    FixedThresholdDetector(double orphanTh = 0.15, int reorgTh = 1)
        : orphanRateTh(orphanTh), reorgDepthTh(reorgTh) {}

    bool update(const RoundMetric& m) {
        bool fired = (m.orphan_rate_window > orphanRateTh) || (m.reorg_depth > reorgDepthTh);
        if (fired) alerts.push_back(m.round);
        return fired;
    }
};

class AdaptiveDetector {
public:
    double k;
    size_t windowSize;
    size_t minSamples;
    deque<double> window;
    vector<int> alerts;

    AdaptiveDetector(double k_ = 3.0, size_t windowSize_ = 20, size_t minSamples_ = 8)
        : k(k_), windowSize(windowSize_), minSamples(minSamples_) {}

    double mean() const {
        if (window.empty()) return 0.0;
        double s = 0; for (double v : window) s += v; return s / window.size();
    }
    double stdev() const {
        if (window.size() < 2) return 0.0;
        double m = mean(), s = 0;
        for (double v : window) s += (v - m) * (v - m);
        return sqrt(s / window.size());
    }

    bool update(const RoundMetric& m) {
        bool fired = false;
        if (window.size() >= minSamples) {
            double threshold = mean() + k * stdev();
            if (m.orphan_rate_window > threshold) fired = true;
        }
        window.push_back(m.orphan_rate_window);
        if (window.size() > windowSize) window.pop_front();
        if (fired) alerts.push_back(m.round);
        return fired;
    }
};

// Vérité terrain simple : un round est "attaque active" s'il a provoqué un
// reorg (reorg_depth > 0). Permet de calculer précision/rappel au niveau
// "round" pour comparer les deux détecteurs sur une même campagne.
inline DetectorEval evaluate(const vector<RoundMetric>& metrics, const vector<int>& alertRounds) {
    DetectorEval e;
    vector<bool> isAlert(metrics.size(), false);
    for (int r : alertRounds) if (r >= 0 && r < (int)metrics.size()) isAlert[r] = true;
    for (size_t i = 0; i < metrics.size(); ++i) {
        bool actual = metrics[i].reorg_depth > 0;
        bool predicted = isAlert[i];
        if (actual && predicted) e.tp++;
        else if (!actual && predicted) e.fp++;
        else if (actual && !predicted) e.fn++;
        else e.tn++;
    }
    e.precision = (e.tp + e.fp) ? (double)e.tp / (e.tp + e.fp) : 0.0;
    e.recall = (e.tp + e.fn) ? (double)e.tp / (e.tp + e.fn) : 0.0;
    return e;
}

// Note : la contre-mesure "ReorgGuard" (limite de profondeur de reorg) est
// définie dans attacks.h et directement branchée dans runFiftyOnePercentAttack().
