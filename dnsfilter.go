package main

// filterAnswers filters DNS records according to RFC CNAME rules - need to still understand the RFC
// like why txxt and all records should also be like returned by the cname server
func filterAnswers(qType uint16, answers []rr) []rr {
	var cnameAnswers []rr
	for _, r := range answers {
		if r.Type_ == 5 { // CNAME
			cnameAnswers = append(cnameAnswers, r)
		}
	}

	var filteredAnswers []rr
	if qType == 255 { // ANY
		filteredAnswers = answers
	} else if qType == 5 { // CNAME query
		for _, r := range answers {
			if r.Type_ == 5 {
				filteredAnswers = append(filteredAnswers, r)
			}
		}
	} else if len(cnameAnswers) > 0 {
		// for non-CNAME queries, if CNAME exists, return only CNAME
		filteredAnswers = cnameAnswers
	} else {
		for _, r := range answers {
			if r.Type_ == qType {
				filteredAnswers = append(filteredAnswers, r)
			}
		}
	}
	return filteredAnswers
}

//this entire codebase is just patch upon patch cause i am figuring out dns specs and as i do and understand just adding a patch
// TODO: refactor this into proper functions
