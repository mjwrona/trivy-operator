package jobs

import (
	"context"
	"regexp"
	"strconv"

	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const ScannerName = "Trivy"

type LimitChecker interface {
	Check(ctx context.Context) (bool, []int, error)
	CheckNodes(ctx context.Context) (bool, int, error)
}

func NewLimitChecker(config etc.Config, c client.Client, trivyOperatorConfig trivyoperator.ConfigData) LimitChecker {
	return &checker{
		config:              config,
		client:              c,
		trivyOperatorConfig: trivyOperatorConfig,
	}
}

type checker struct {
	config              etc.Config
	client              client.Client
	trivyOperatorConfig trivyoperator.ConfigData
}

func (c *checker) Check(ctx context.Context) (bool, []int, error) {
	matchinglabels := client.MatchingLabels{
		trivyoperator.LabelK8SAppManagedBy:            trivyoperator.AppTrivyOperator,
		trivyoperator.LabelVulnerabilityReportScanner: ScannerName,
	}

	jobSuffixes := c.GenerateIntArray(1,c.config.ConcurrentScanJobsLimit)

	usedJobSuffixes, err := c.usedJobSuffixes(ctx, matchinglabels)
	if err != nil {
		return false, []int{}, err
	}

	// Create a map to track used suffixes for quick lookup
	usedMap := make(map[int]struct{}, len(usedJobSuffixes))
	for _, suffix := range usedJobSuffixes {
		usedMap[suffix] = struct{}{}
	}

	// Filter out used suffixes from jobSuffixes
	var unusedJobSuffixes []int
	for _, suffix := range jobSuffixes {
		if _, exists := usedMap[suffix]; !exists {
			unusedJobSuffixes = append(unusedJobSuffixes, suffix)
		}
	}

	return len(usedJobSuffixes) >= c.config.ConcurrentScanJobsLimit, unusedJobSuffixes, nil
}

func (c *checker) CheckNodes(ctx context.Context) (bool, int, error) {
	matchinglabels := client.MatchingLabels{
		trivyoperator.LabelK8SAppManagedBy:   trivyoperator.AppTrivyOperator,
		trivyoperator.LabelNodeInfoCollector: ScannerName,
	}
	scanJobsCount, err := c.countJobs(ctx, matchinglabels)
	if err != nil {
		return false, 0, err
	}

	return scanJobsCount >= c.config.ConcurrentNodeCollectorLimit, scanJobsCount, nil
}

func (c *checker) countJobs(ctx context.Context, matchingLabels client.MatchingLabels) (int, error) {
	var scanJobs batchv1.JobList
	listOptions := []client.ListOption{matchingLabels}
	if !c.trivyOperatorConfig.VulnerabilityScanJobsInSameNamespace() {
		// scan jobs are running in only trivyoperator operator namespace
		listOptions = append(listOptions, client.InNamespace(c.config.Namespace))
	}
	err := c.client.List(ctx, &scanJobs, listOptions...)
	if err != nil {
		return 0, err
	}

	return len(scanJobs.Items), nil
}

var prefixRegex = regexp.MustCompile(`^scan-vulnerabilityreport-(\d+)$`)

func (c *checker) usedJobSuffixes(ctx context.Context, matchingLabels client.MatchingLabels) ([]int, error) {
	var scanJobs batchv1.JobList
	listOptions := []client.ListOption{matchingLabels}
	if !c.trivyOperatorConfig.VulnerabilityScanJobsInSameNamespace() {
		// scan jobs are running in only trivyoperator operator namespace
		listOptions = append(listOptions, client.InNamespace(c.config.Namespace))
	}
	err := c.client.List(ctx, &scanJobs, listOptions...)
	if err != nil {
		return []int{}, err
	}

	jobSuffixes := make([]int, 0, len(scanJobs.Items))
	for _, job := range scanJobs.Items {
		matches := prefixRegex.FindStringSubmatch(job.Name)
		if len(matches) > 1 {
			num, _ := strconv.Atoi(matches[1])
			jobSuffixes = append(jobSuffixes, num) // Capture group contains the part after the prefix
		}
	}

	return jobSuffixes, nil
}

func (c *checker) GenerateIntArray(start, end int) []int {
	if start > end {
		return []int{} // Return an empty slice if start is greater than end
	}

	result := make([]int, end-start+1)
	for i := range result {
		result[i] = start + i
	}
	return result
}