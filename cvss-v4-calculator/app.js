const express = require('express');
const app = express();
const port = 22177;

// Import necessary functions and data
//const { cvss_score } = require('./cvss_score.js');
const { cvss_score, macroVector } = require('./cvss_score.js');
const cvssLookup_global = require('./cvss_lookup.js');
const { maxSeverity } = require('./max_severity.js');
const metrics = require('./metrics.js');


// Check if expectedMetricOrder exists in metrics.js, if not, define it
const expectedMetricOrder = metrics.expectedMetricOrder || {
    AV: ['N', 'A', 'L', 'P'],
    AC: ['L', 'H'],
    AT: ['N', 'P'],
    PR: ['N', 'L', 'H'],
    UI: ['N', 'P', 'A'],
    VC: ['H', 'L', 'N'],
    VI: ['H', 'L', 'N'],
    VA: ['H', 'L', 'N'],
    SC: ['H', 'L', 'N'],
    SI: ['H', 'L', 'N'],
    SA: ['H', 'L', 'N']
};

// Helper function to parse the CVSS vector
function parseVector(vector) {
    const metrics = vector.split('/');
    const cvssSelected = {};
    
    // Remove CVSS:4.0 prefix
    metrics.shift();

    metrics.forEach(metric => {
        const [key, value] = metric.split(':');
        cvssSelected[key] = value;
    });
    
    if (!("E" in cvssSelected)){
	cvssSelected["E"] = "X"
	}
    if (!("CR" in cvssSelected)){
        cvssSelected["CR"] = "X"
        }
    if (!("IR" in cvssSelected)){
        cvssSelected["IR"] = "X"
        }
    if (!("AR" in cvssSelected)){
        cvssSelected["AR"] = "X"
        }

console.log("added", cvssSelected)

    return cvssSelected;
}

// Function to calculate qualitative score
function calculateQualScore(score) {
    if (score === 0) return "None";
    if (score < 4.0) return "Low";
    if (score < 7.0) return "Medium";
    if (score < 9.0) return "High";
    return "Critical";
}

// Function to validate vector
function validateVector(cvssSelected) {
    for (const [metric, expectedValues] of Object.entries(expectedMetricOrder)) {
        if (cvssSelected[metric] && !expectedValues.includes(cvssSelected[metric])) {
            return false;
        }
    }
    return true;
}

app.get('/cvss', (req, res) => {
    const vectorString = req.query.q;
    
    if (!vectorString) {
        return res.status(400).json({ error: 'Missing vector string' });
    }

    const cvssSelected = parseVector(vectorString);
    
    if (!validateVector(cvssSelected)) {
        return res.status(400).json({ error: 'Invalid vector string' });
    }

    try {
        const macrov = macroVector(cvssSelected)
    //    console.log("select:", cvssSelected, "lookup:", cvssLookup_global,"maxs:",  maxSeverity, "macv:", macroVector)
        const score = cvss_score(cvssSelected, cvssLookup_global, maxSeverity, macrov);
        const qualScore = calculateQualScore(score);

        res.json({
            vector: vectorString,
            score: score,
            severity: qualScore
        });
    } catch (error) {
        console.error('Error calculating CVSS score:', error);
        res.status(500).json({ error: 'Error calculating CVSS score' });
    }
});

app.listen(port,'0.0.0.0', () => {
    console.log(`CVSS calculator app listening at http://localhost:${port}`);
});
