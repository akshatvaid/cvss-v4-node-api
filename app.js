const express = require('express');
const app = express();
const port = 22177;     //Set as required
const ipad = '0.0.0.0'; //Set as required

const { cvss_score, macroVector } = require('./cvss-v4-calculator/cvss_score.js');
const cvssLookup_global = require('./cvss-v4-calculator/cvss_lookup.js');
const { maxSeverity } = require('./cvss-v4-calculator/max_severity.js');
const expectedMetricOrder = require('./cvss-v4-calculator/metrics.js');
const metrics  = require('./cvss-v4-calculator/metrics.js');


// Function to validate vector
function validateVector(vectorString) {
    let metrics = vectorString.split("/")
    prefix = metrics[0];
    if (prefix != "CVSS:4.0") {
        return { valid: false, error: "Invalid vector prefix" };
    }
    
    metrics.shift()
    
    let oi = 0;
    let expectedIndex = 0;
    const toSelect = {};
    const expectedEntries = Object.entries(this.expectedMetricOrder);
    const mandatoryMetrics = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

    for (const metric of metrics) {
        const [key, value] = metric.split(":");
        const expectedEntry = expectedEntries.find(entry => entry[0] === key);

	if (key in toSelect) {
            return { valid: false, error: `Invalid vector, repeated metric: ${key}` };
        }

        while (expectedIndex < expectedEntries.length && expectedEntries[expectedIndex][0] !== key) {
            expectedIndex++;
        }
        if (expectedIndex >= expectedEntries.length) {
            return { valid: false, error: `Invalid vector, metric out of sequence: ${key}` };
        }

	if (!expectedEntry) {
	    return { valid: false, error: `Invalid vector, unexpected metric: ${key}` };
        }
	
	if (!expectedEntry[1].includes(value)) {
            return { valid: false, error: `Invalid vector, for key ${key}, value ${value} is not in [${expectedEntry[1]}]` };
        }

        toSelect[key] = value;
    }

    const missingMandatoryMetrics = mandatoryMetrics.filter(metric => !(metric in toSelect));
    if (missingMandatoryMetrics.length > 0) {
	return { valid: false, error: `Invalid vector, missing mandatory metrics: ${missingMandatoryMetrics.join(', ')}` };
    }

    return { valid: true, selectedMetrics: toSelect };

} 


//Function to add the default "X"s
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


app.get('/cvss', (req, res) => {
    const vectorString = req.query.q;
    
    if (!vectorString) {
        return res.status(400).json({ error: 'Missing vector string' });
    }
    
    const vvres = validateVector(vectorString);
    if (!vvres.valid) {
        return res.json({ 
		    vector: vectorString,
                    score: "error",
                    severity: "error",
		    error: vvres.error 
               });
    }
    
    const cvssSelected = parseVector(vectorString);
    try {
        const macrov = macroVector(cvssSelected)
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

app.listen(port,ipad, () => {
    console.log(`CVSS calculator API listening at http://localhost:${port}`);
});
