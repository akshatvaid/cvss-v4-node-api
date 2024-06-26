import os, json

metrics = {
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
    "E": ["X", "A", "P", "U"],
    "CR": ["X", "H", "M", "L"],
    "IR": ["X", "H", "M", "L"],
    "AR": ["X", "H", "M", "L"]
}


def getJSON(vector):
	q = """curl -s http://localhost:22177/cvss?q="""
	cm = q + vector
	js = os.popen(cm)
	jr = js.read()
	return json.loads(jr)

def generate_vectors(current_metrics, metric_keys, current_vector, all_vectors, ctr):
    
    if not metric_keys:
        current_vector = "CVSS:4.0" + current_vector
        if "VC:N/VI:N/VA:N/SC:N/SI:N/SA:N" not in current_vector: 
            vector_json = getJSON(current_vector)
            ctr[0] = ctr[0] + 1
            print(vector_json)
            all_vectors.append(vector_json)
        else:
             print("Skipping: ",current_vector)
        return
    
    current_key = metric_keys[0]
    for value in current_metrics[current_key]:
        generate_vectors(current_metrics, metric_keys[1:], current_vector + f"/{current_key}:{value}", all_vectors, ctr)
#        if ctr[0] == 100:
 #           break
ctr = [0]
all_vectors = []
generate_vectors(metrics, list(metrics.keys()), "", all_vectors, ctr)

with open("cvss_vectors.txt", "w") as file:
    json.dump(all_vectors, file, indent=2)
