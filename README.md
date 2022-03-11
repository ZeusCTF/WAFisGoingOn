# WAFisGoingOn

The goal of this project is to create a "smart" WAF that detects common attack methods (mainly injection attempts) or discovery techniques, and prevent them, while also not impacting the overall delay between the requests too much.  In it's current form, this project relies upon an initial dataset that the user provides, and compares the information the client is sending to the information in the dataset - if there is a similar match (determined by cosine similarity) the request is blocked by the WAF and the attacker is returned a useless response, with the attack then being added to the payloads list.


