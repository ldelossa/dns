package dns

import "fmt"

type Stater interface {
	AddQuery(*Query)
	String() string
}

type Top struct {
	Count    uint64
	Hostname string
}

// asyncStater asynchronously processes Query statistics.
// a the String method is called you SHOULD NOT call the AddQuery
// method as the underlying channel will be closed. correct usage
// would be to call AddQuery until caller exhausts all queries, call
// String or pass struct to fmt.Print* method, and then discard struct
type asyncStater struct {
	inChan          chan *Query
	processedQ      chan struct{}
	payloadCount    int
	rcodeHist       map[string]uint64
	topAnswersQuery *Query
	topAnswersCount int
	hostNameHist    map[string]uint64
	hostNameTop     [5]Top
}

// NewAsyncStater returns an async implementation of our Stater interface
// the returned Stater is immediately ready for calls to AddQuery()
func NewAsyncStater() Stater {
	// make buffered channel
	inChan := make(chan *Query, 1024)
	processedQ := make(chan struct{})

	s := &asyncStater{
		inChan:       inChan,
		processedQ:   processedQ,
		rcodeHist:    map[string]uint64{},
		hostNameHist: map[string]uint64{},
		hostNameTop:  [5]Top{},
	}

	// launch start() in go routine to async ingest Queries.
	go s.start()

	return s
}

// start begins ranging over the input channel and processing
// Query structs adding to it's counters. when String is called
// the channel is closed exhausting the range loop. we then place a
// empty struct on procssedQ to indicate to string that all messages
// have been processed.
func (a *asyncStater) start() {
	// begin range over inChan
	for q := range a.inChan {
		// add to payloadCount
		a.payloadCount++

		// add to reponse code histagram
		if _, ok := a.rcodeHist[q.RCode]; !ok {
			a.rcodeHist[q.RCode] = 1
		} else {
			a.rcodeHist[q.RCode] = a.rcodeHist[q.RCode] + 1
		}

		// add hostName to hostNameHist
		_, ok := a.hostNameHist[q.Question.QueryName]
		if !ok && q.Question.QueryName != "" {
			a.hostNameHist[q.Question.QueryName] = 1
		}
		if ok && q.Question.QueryName != "" {
			a.hostNameHist[q.Question.QueryName] = a.hostNameHist[q.Question.QueryName] + 1
		}

		// check for top answer
		if q.ANCount > a.topAnswersCount {
			a.topAnswersCount = q.ANCount
			a.topAnswersQuery = q
		}
	}
	// range will end when inChan is closed. once we are done draining the closed channel send indicator that all messages are processed
	a.processedQ <- struct{}{}
}

// AddQuery ingresses a Query struct to our asyncStater. It's the caller's responsibility
// to not call AddQuery after calling String() or passing our struct to a fmt.Print* method
// in the event of slow consumption this method will begin to block. we pick blocking
// over dropping to maintain accurate statistics
func (a *asyncStater) AddQuery(q *Query) {
	a.inChan <- q
}

func (a *asyncStater) String() string {
	// close our inChan indicating to the range loop in start that there will be no more ingress queries
	close(a.inChan)

	// wait for all messages to be procesed
	<-a.processedQ

	// compute top5
	for k, v := range a.hostNameHist {
		for i, t := range a.hostNameTop {
			if v > uint64(t.Count) {
				a.hostNameTop[i] = Top{
					Count:    v,
					Hostname: k,
				}
				break
			}
		}
	}

	// return our statistics
	s := fmt.Sprintf(`
	Total DNS Payloads found (TCP and UDP, Queries and Responses): %d
	Histogram of Response Codes: %v
	Query with most Answers:{%v}
	Top Five Hostnames: %v

	`, a.payloadCount, a.rcodeHist, a.topAnswersQuery, a.hostNameTop)

	return s
}
