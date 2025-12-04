package metrics
import (
	"net/http"
"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)
var (
	// ExecutionCounter 任务执行计数器
	ExecutionCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aws_automation_executions_total",
			Help: "Total number of AWS automation executions",
		},
		[]string{"service", "status"},
	)
// ExecutionDuration 任务执行耗时
	ExecutionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aws_automation_duration_seconds",
			Help:    "Execution duration of AWS automation tasks",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"service", "operation"},
	)
// AuditDuration 审计任务耗时
	AuditDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aws_audit_duration_seconds",
			Help:    "Duration of audit operations",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"resource_type"},
	)
// ResourceCount 资源数量统计
	ResourceCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aws_resource_count",
			Help: "Number of AWS resources by type and region",
		},
		[]string{"resource_type", "region"},
	)
)
// InitMetrics 初始化所有metrics
func InitMetrics() {
	prometheus.MustRegister(ExecutionCounter)
	prometheus.MustRegister(ExecutionDuration)
	prometheus.MustRegister(AuditDuration)
	prometheus.MustRegister(ResourceCount)
}
// Handler 返回Prometheus metrics handler
func Handler() http.Handler {
	return promhttp.Handler()
