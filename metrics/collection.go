package metrics

import (
	"fmt"

	"github.com/codeclysm/introspector/v3"
	"github.com/joeshaw/multierror"
	"github.com/prometheus/client_golang/prometheus"
)

// MetricsCollection allows you to query multiple introspector
type MetricsCollection struct {
	Collection []introspector.Introspector
	namespace  string
	counter    *prometheus.CounterVec
}

func NewMetricsCollection(namespace string, collection ...introspector.Introspector) MetricsCollection {
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "introspector_counts",
		Help: "The requests to introspect a token and which introspector responds",
	}, []string{"namespace", "introspector"})
	prometheus.MustRegister(counter)

	return MetricsCollection{
		Collection: collection,
		namespace:  namespace,
		counter:    counter,
	}
}

// Introspect queries every introspector returning the result of the first one
// that succeeds or a MetricsCollection of errors
func (c MetricsCollection) Introspect(token string) (introspector.Introspection, error) {
	errs := multierror.Errors{}

	for i := range c.Collection {
		intro, err := c.Collection[i].Introspect(token)
		if err == nil {
			c.counter.WithLabelValues(c.namespace, fmt.Sprintf("%T", c.Collection[i])).Inc()
			return intro, nil
		}
		errs = append(errs, err)
	}

	c.counter.WithLabelValues(c.namespace, "none").Inc()
	return introspector.Introspection{}, errs.Err()
}
