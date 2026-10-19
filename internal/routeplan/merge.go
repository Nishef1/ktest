package routeplan

import (
	"math"
	"time"
)

// MergeAge bounds how old a previous test may be and still steady the next.
const MergeAge = 7 * 24 * time.Hour

// lowerBound is the Wilson 95% lower bound of a success rate: three of three
// is trusted less than thirty of thirty, and one lucky sample counts little.
func lowerBound(successes, attempts int) float64 {
	if attempts <= 0 {
		return 0
	}
	const z = 1.96
	n := float64(attempts)
	phat := float64(successes) / n
	return (phat + z*z/(2*n) - z*math.Sqrt((phat*(1-phat)+z*z/(4*n))/n)) / (1 + z*z/n)
}

func rowTotals(r Result) (successes, attempts int) {
	if r.TotalAttempts > 0 {
		return r.TotalSuccesses, r.TotalAttempts
	}
	return r.Successes, r.Attempts
}

// Merge folds the fresh test into the previous profile of the same network
// and targets, then reselects with hysteresis:
//   - every row's totals add the fresh samples to two thirds of the earlier
//     ones, so the record follows the network without forgetting it at once;
//   - a target keeps its earlier method while that method still worked in
//     this run and the challenger is not clearly better (more reliable over
//     all tests, or at least 30% faster with comparable reliability);
//   - a method that stopped working is replaced by this run's best at once.
//
// The result says the same thing test after test unless the network really
// changed, and a better method found later is adopted.
func Merge(previous, fresh *Profile) *Profile {
	if previous == nil || fresh == nil {
		return fresh
	}
	old := map[[2]string]Result{}
	for _, r := range previous.Rows {
		old[[2]string{r.TargetID, r.Method}] = r
	}
	out := *fresh
	out.Rows = append([]Result(nil), fresh.Rows...)
	out.Runs = max(previous.Runs, 1) + 1
	index := map[[2]string]int{}
	for i, r := range out.Rows {
		key := [2]string{r.TargetID, r.Method}
		index[key] = i
		if before, ok := old[key]; ok {
			s, a := rowTotals(before)
			r.TotalSuccesses = r.Successes + s - s/3
			r.TotalAttempts = r.Attempts + a - a/3
		} else {
			r.TotalSuccesses, r.TotalAttempts = r.Successes, r.Attempts
		}
		out.Rows[i] = r
	}
	row := func(target, method string) (Result, bool) {
		i, ok := index[[2]string{target, method}]
		if !ok {
			return Result{}, false
		}
		return out.Rows[i], true
	}
	works := func(r Result) bool { return r.Attempts > 0 && r.Successes == r.Attempts }
	clearlyBetter := func(challenger, incumbent Result) bool {
		cs, ca := rowTotals(challenger)
		is, ia := rowTotals(incumbent)
		cl, il := lowerBound(cs, ca), lowerBound(is, ia)
		if cl > il+0.15 {
			return true
		}
		return cl >= il-0.2 && challenger.MedianMS > 0 && incumbent.MedianMS > 0 &&
			float64(challenger.MedianMS) < 0.7*float64(incumbent.MedianMS)
	}
	out.Selections = append([]Selection(nil), fresh.Selections...)
	for i, sel := range out.Selections {
		was := previous.selection(sel.TargetID)
		if was == "" || was == sel.Method {
			if was != "" {
				out.Selections[i].Kept = true
			}
			continue
		}
		incumbent, ok := row(sel.TargetID, was)
		if !ok || !works(incumbent) {
			continue // the earlier choice no longer works here
		}
		if challenger, ok := row(sel.TargetID, sel.Method); ok && sel.Method != "" && clearlyBetter(challenger, incumbent) {
			continue
		}
		out.Selections[i] = Selection{TargetID: sel.TargetID, URL: sel.URL, Method: incumbent.Method,
			Assessment: "https_verified", MedianMS: incumbent.MedianMS, JitterMS: incumbent.JitterMS,
			Successes: incumbent.Successes, Attempts: incumbent.Attempts, Kept: true}
	}
	if previous.Default != "" && previous.Default != fresh.Default {
		score := func(method string) (float64, bool) {
			total, working := 0.0, false
			for _, r := range out.Rows {
				if r.Method == method {
					s, a := rowTotals(r)
					total += lowerBound(s, a)
					working = working || works(r)
				}
			}
			return total, working
		}
		oldScore, oldWorks := score(previous.Default)
		newScore, _ := score(fresh.Default)
		if oldWorks && (fresh.Default == "" || newScore <= oldScore*1.15) {
			out.Default = previous.Default
		}
	}
	return &out
}
