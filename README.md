AWS资源审计与自动化管理工具 - 完整实现方案
项目架构概述
text
aws-automation-tool/
├── Dockerfile
├── docker-compose.yml
├── Jenkinsfile
├── scripts/
│   ├── deploy.sh
│   └── setup.sh
├── configs/
│   ├── prometheus.yml
│   └── grafana-dashboard.json
├── src/
│   ├── main.go
│   ├── pkg/
│   │   ├── ec2/
│   │   ├── s3/
│   │   ├── vpc/
│   │   ├── metrics/
│   │   └── utils/
│   └── config/
└── README.md
1. 核心Go代码实现
main.go
go
package main
import (
	"aws-automation-tool/pkg/ec2"
	"aws-automation-tool/pkg/s3"
	"aws-automation-tool/pkg/vpc"
	"aws-automation-tool/pkg/metrics"
	"aws-automation-tool/config"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)
var (
	configFile = flag.String("config", "config/config.yaml", "Path to config file")
)
func main() {
	flag.Parse()
	
	// 加载配置
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
// 初始化监控
	metrics.InitMetrics()
	
	// 启动metrics HTTP服务器
	go startMetricsServer(cfg.Metrics.Port)
// 处理命令行参数
	if len(os.Args) > 1 {
		handleCommands(cfg)
		return
	}
// 作为服务运行
	runAsService(cfg)
}
func handleCommands(cfg *config.Config) {
	command := os.Args[1]
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
switch command {
	case "stop-test-ec2":
		log.Println("执行测试EC2实例关闭任务")
		err := ec2.StopTestInstances(ctx, cfg)
		if err != nil {
			log.Printf("停止EC2实例失败: %v", err)
			os.Exit(1)
		}
		
	case "audit-s3-permissions":
		log.Println("执行S3权限审计任务")
		results, err := s3.AuditBucketPermissions(ctx, cfg)
		if err != nil {
			log.Printf("S3权限审计失败: %v", err)
			os.Exit(1)
		}
		s3.GenerateComplianceReport(results)
		
	case "audit-vpc-sg":
		log.Println("执行VPC安全组审计任务")
		err := vpc.AuditSecurityGroups(ctx, cfg)
		if err != nil {
			log.Printf("安全组审计失败: %v", err)
			os.Exit(1)
		}
		
	case "full-audit":
		log.Println("执行完整审计任务")
		performFullAudit(ctx, cfg)
		
	default:
		log.Printf("未知命令: %s", command)
		os.Exit(1)
	}
	
	log.Println("任务执行完成")
}
func performFullAudit(ctx context.Context, cfg *config.Config) {
	start := time.Now()
	
	// 并发执行所有审计任务
	errCh := make(chan error, 3)
	
	go func() {
		errCh <- ec2.AuditAllRegions(ctx, cfg)
	}()
	
	go func() {
		_, err := s3.AuditBucketPermissions(ctx, cfg)
		errCh <- err
	}()
	
	go func() {
		errCh <- vpc.AuditAllRegionsSecurityGroups(ctx, cfg)
	}()
	
	// 等待所有任务完成
	for i := 0; i < 3; i++ {
		if err := <-errCh; err != nil {
			log.Printf("审计任务失败: %v", err)
		}
	}
	
	duration := time.Since(start).Seconds()
	metrics.AuditDuration.WithLabelValues("full").Observe(duration)
	log.Printf("完整审计完成，耗时: %.2f秒", duration)
}
func startMetricsServer(port string) {
	http.Handle("/metrics", metrics.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	log.Printf("启动metrics服务器，端口: %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
func runAsService(cfg *config.Config) {
	log.Println("以服务模式运行AWS自动化工具")
	
	// 优雅关闭
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	
	// 保持服务运行
	<-sigCh
	log.Println("接收到关闭信号，正在退出...")
}
pkg/ec2/manager.go
go
package ec2
import (
	"aws-automation-tool/config"
	"aws-automation-tool/pkg/metrics"
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)
// StopTestInstances 停止测试环境EC2实例
func StopTestInstances(ctx context.Context, cfg *config.Config) error {
	start := time.Now()
	successCount := 0
	failureCount := 0
defer func() {
		duration := time.Since(start).Seconds()
		metrics.ExecutionDuration.WithLabelValues("ec2", "stop_test_instances").Observe(duration)
		metrics.ExecutionCounter.WithLabelValues("ec2", "success").Add(float64(successCount))
		metrics.ExecutionCounter.WithLabelValues("ec2", "failure").Add(float64(failureCount))
	}()
var wg sync.WaitGroup
	errCh := make(chan error, len(cfg.AWS.Regions))
for _, region := range cfg.AWS.Regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			
			sess, err := createSession(region, cfg)
			if err != nil {
				errCh <- fmt.Errorf("region %s: %v", region, err)
				return
			}
ec2Svc := ec2.New(sess)
			
			// 查找带有测试环境标签的运行中实例
			input := &ec2.DescribeInstancesInput{
				Filters: []*ec2.Filter{
					{
						Name:   aws.String("instance-state-name"),
						Values: []*string{aws.String("running")},
					},
					{
						Name:   aws.String("tag:Environment"),
						Values: []*string{aws.String("test"), aws.String("dev")},
					},
				},
			}
result, err := ec2Svc.DescribeInstancesWithContext(ctx, input)
			if err != nil {
				errCh <- fmt.Errorf("region %s: %v", region, err)
				return
			}
var instanceIDs []*string
			for _, reservation := range result.Reservations {
				for _, instance := range reservation.Instances {
					// 检查是否在计划关闭时间内
					if shouldStopInstance(instance) {
						instanceIDs = append(instanceIDs, instance.InstanceId)
						log.Printf("计划停止实例: %s (Region: %s)", 
							*instance.InstanceId, region)
					}
				}
			}
if len(instanceIDs) > 0 {
				_, err = ec2Svc.StopInstancesWithContext(ctx, &ec2.StopInstancesInput{
					InstanceIds: instanceIDs,
				})
				if err != nil {
					failureCount += len(instanceIDs)
					errCh <- fmt.Errorf("region %s: %v", region, err)
				} else {
					successCount += len(instanceIDs)
				}
			}
		}(region)
	}
wg.Wait()
	close(errCh)
// 收集错误
	var errors []string
	for err := range errCh {
		errors = append(errors, err.Error())
	}
if len(errors) > 0 {
		return fmt.Errorf("停止实例时发生错误: %s", strings.Join(errors, "; "))
	}
log.Printf("成功停止 %d 个测试实例", successCount)
	return nil
}
// AuditAllRegions 审计所有区域的EC2实例
func AuditAllRegions(ctx context.Context, cfg *config.Config) error {
	start := time.Now()
defer func() {
		duration := time.Since(start).Seconds()
		metrics.AuditDuration.WithLabelValues("ec2").Observe(duration)
	}()
var wg sync.WaitGroup
	results := make(chan *RegionAuditResult, len(cfg.AWS.Regions))
for _, region := range cfg.AWS.Regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			result := auditRegion(ctx, region, cfg)
			results <- result
		}(region)
	}
wg.Wait()
	close(results)
// 生成审计报告
	return generateEC2AuditReport(results)
}
func auditRegion(ctx context.Context, region string, cfg *config.Config) *RegionAuditResult {
	sess, err := createSession(region, cfg)
	if err != nil {
		return &RegionAuditResult{
			Region: region,
			Error:  err.Error(),
		}
	}
ec2Svc := ec2.New(sess)
	result := &RegionAuditResult{
		Region:        region,
		InstanceCount: 0,
		RunningCount:  0,
		StoppedCount:  0,
	}
input := &ec2.DescribeInstancesInput{}
	err = ec2Svc.DescribeInstancesPagesWithContext(ctx, input, 
		func(page *ec2.DescribeInstancesOutput, lastPage bool) bool {
			for _, reservation := range page.Reservations {
				for _, instance := range reservation.Instances {
					result.InstanceCount++
					switch *instance.State.Name {
					case "running":
						result.RunningCount++
					case "stopped":
						result.StoppedCount++
					}
					
					// 检查标签合规性
					if !hasRequiredTags(instance.Tags, cfg.EC2.RequiredTags) {
						result.NonCompliantInstances = append(
							result.NonCompliantInstances, 
							*instance.InstanceId,
						)
					}
				}
			}
			return !lastPage
		})
if err != nil {
		result.Error = err.Error()
	}
return result
}
func createSession(region string, cfg *config.Config) (*session.Session, error) {
	return session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
}
func shouldStopInstance(instance *ec2.Instance) bool {
	// 实现实例停止逻辑，基于标签、创建时间等条件
	for _, tag := range instance.Tags {
		if *tag.Key == "AutoStop" && *tag.Value == "true" {
			return true
		}
	}
	return false
}
func hasRequiredTags(tags []*ec2.Tag, requiredTags []string) bool {
	tagMap := make(map[string]bool)
	for _, tag := range tags {
		tagMap[*tag.Key] = true
	}
	
	for _, required := range requiredTags {
		if !tagMap[required] {
			return false
		}
	}
	return true
}
pkg/s3/auditor.go
go
package s3
import (
	"aws-automation-tool/config"
	"aws-automation-tool/pkg/metrics"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)
// BucketAuditResult S3存储桶审计结果
type BucketAuditResult struct {
	BucketName      string   `json:"bucketName"`
	Region          string   `json:"region"`
	IsPublic        bool     `json:"isPublic"`
	HasPublicPolicy bool     `json:"hasPublicPolicy"`
	HasPublicACL    bool     `json:"hasPublicACL"`
	EncryptionAtRest bool    `json:"encryptionAtRest"`
	VersioningEnabled bool   `json:"versioningEnabled"`
	ComplianceIssues []string `json:"complianceIssues"`
	Error           string   `json:"error,omitempty"`
}
// AuditBucketPermissions 审计S3存储桶权限
func AuditBucketPermissions(ctx context.Context, cfg *config.Config) ([]BucketAuditResult, error) {
	start := time.Now()
	successCount := 0
defer func() {
		duration := time.Since(start).Seconds()
		metrics.AuditDuration.WithLabelValues("s3").Observe(duration)
		metrics.ExecutionCounter.WithLabelValues("s3", "success").Add(float64(successCount))
	}()
var allResults []BucketAuditResult
	var mutex sync.Mutex
	var wg sync.WaitGroup
for _, region := range cfg.AWS.Regions {
		wg.Add(1)
		go func(region string) {
			defer wg.Done()
			
			results, err := auditRegionBuckets(ctx, region, cfg)
			mutex.Lock()
			defer mutex.Unlock()
			
			if err != nil {
				log.Printf("区域 %s 审计失败: %v", region, err)
				allResults = append(allResults, BucketAuditResult{
					Region: region,
					Error:  err.Error(),
				})
			} else {
				allResults = append(allResults, results...)
				successCount += len(results)
			}
		}(region)
	}
wg.Wait()
	return allResults, nil
}
func auditRegionBuckets(ctx context.Context, region string, cfg *config.Config) ([]BucketAuditResult, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return nil, fmt.Errorf("创建会话失败: %v", err)
	}
s3Svc := s3.New(sess)
	var results []BucketAuditResult
// 列出所有存储桶
	bucketsOutput, err := s3Svc.ListBucketsWithContext(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("列出存储桶失败: %v", err)
	}
var wg sync.WaitGroup
	resultCh := make(chan BucketAuditResult, len(bucketsOutput.Buckets))
for _, bucket := range bucketsOutput.Buckets {
		wg.Add(1)
		go func(bucket *s3.Bucket) {
			defer wg.Done()
			result := auditSingleBucket(ctx, s3Svc, bucket, region)
			resultCh <- result
		}(bucket)
	}
wg.Wait()
	close(resultCh)
for result := range resultCh {
		results = append(results, result)
	}
return results, nil
}
func auditSingleBucket(ctx context.Context, s3Svc *s3.S3, bucket *s3.Bucket, region string) BucketAuditResult {
	result := BucketAuditResult{
		BucketName: *bucket.Name,
		Region:     region,
	}
// 检查公共访问阻塞配置
	publicAccess, err := s3Svc.GetPublicAccessBlock(&s3.GetPublicAccessBlockInput{
		Bucket: bucket.Name,
	})
	if err != nil {
		result.Error = fmt.Sprintf("获取公共访问配置失败: %v", err)
		return result
	}
// 检查存储桶策略
	policy, err := s3Svc.GetBucketPolicy(&s3.GetBucketPolicyInput{
		Bucket: bucket.Name,
	})
	if err == nil && policy.Policy != nil {
		result.HasPublicPolicy = checkPolicyForPublicAccess(*policy.Policy)
	}
// 检查ACL
	acl, err := s3Svc.GetBucketAcl(&s3.GetBucketAclInput{
		Bucket: bucket.Name,
	})
	if err == nil {
		result.HasPublicACL = checkACLForPublicAccess(acl)
	}
// 检查加密配置
	encryption, err := s3Svc.GetBucketEncryption(&s3.GetBucketEncryptionInput{
		Bucket: bucket.Name,
	})
	result.EncryptionAtRest = err == nil && encryption.ServerSideEncryptionConfiguration != nil
// 检查版本控制
	versioning, err := s3Svc.GetBucketVersioning(&s3.GetBucketVersioningInput{
		Bucket: bucket.Name,
	})
	result.VersioningEnabled = versioning.Status != nil && *versioning.Status == "Enabled"
// 确定是否为公开
	result.IsPublic = result.HasPublicPolicy || result.HasPublicACL
// 收集合规问题
	result.ComplianceIssues = checkComplianceIssues(result, publicAccess.PublicAccessBlockConfiguration)
return result
}
// GenerateComplianceReport 生成合规报告
func GenerateComplianceReport(results []BucketAuditResult) {
	report := map[string]interface{}{
		"timestamp":     time.Now().Format(time.RFC3339),
		"totalBuckets":  len(results),
		"publicBuckets": 0,
		"compliantBuckets": 0,
		"details":      results,
	}
for _, result := range results {
		if result.IsPublic {
			report["publicBuckets"] = report["publicBuckets"].(int) + 1
		}
		if len(result.ComplianceIssues) == 0 {
			report["compliantBuckets"] = report["compliantBuckets"].(int) + 1
		}
	}
// 保存报告到文件
	reportFile := fmt.Sprintf("s3-audit-report-%s.json", time.Now().Format("2006-01-02"))
	file, err := os.Create(reportFile)
	if err != nil {
		log.Printf("创建报告文件失败: %v", err)
		return
	}
	defer file.Close()
encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		log.Printf("写入报告失败: %v", err)
		return
	}
log.Printf("S3合规报告已生成: %s", reportFile)
}
pkg/metrics/exporter.go
go
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
}
2. 配置文件
config/config.yaml
yaml
aws:
  regions:
    - us-east-1
    - us-west-2
    - eu-west-1
    - ap-southeast-1
    - ap-northeast-1
  access_key_id: ${AWS_ACCESS_KEY_ID}
  secret_access_key: ${AWS_SECRET_ACCESS_KEY}
ec2:
  required_tags:
    - Environment
    - Owner
    - Project
  test_env_tags:
    - Environment=test
    - Environment=dev
  auto_stop_schedule: "0 20 * * *"  # 每天20点
s3:
  compliance_rules:
    - name: "no_public_access"
      description: "存储桶不应公开访问"
    - name: "encryption_at_rest"
      description: "应启用静态加密"
    - name: "versioning_enabled"
      description: "应启用版本控制"
vpc:
  restricted_ports:
    - 22    # SSH
    - 3389  # RDP
    - 1433  # SQL Server
    - 1521  # Oracle
metrics:
  port: "8080"
alerting:
  enabled: true
  email:
    smtp_host: "smtp.company.com"
    smtp_port: 587
    from: "aws-automation@company.com"
    to:
      - "infra-team@company.com"
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
logging:
  level: "info"
  format: "json"
3. Docker配置
Dockerfile
dockerfile
FROM golang:1.19-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o aws-automation-tool .
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/aws-automation-tool .
COPY --from=builder /app/config/config.yaml ./config/config.yaml
# 创建非root用户
RUN addgroup -g 1001 appgroup && \
    adduser -D -u 1001 -G appgroup appuser
USER appuser
EXPOSE 8080
CMD ["./aws-automation-tool"]
docker-compose.yml
yaml
version: '3.8'
services:
  aws-automation:
    build: .
    container_name: aws-automation-tool
    environment:
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_REGION=us-east-1
    ports:
      - "8080:8080"
    volumes:
      - ./reports:/app/reports
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./configs/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    restart: unless-stopped
grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./configs/grafana-dashboard.json:/etc/grafana/provisioning/dashboards/aws-dashboard.json
    restart: unless-stopped
volumes:
  prometheus_data:
  grafana_data:
4. Jenkins Pipeline配置
Jenkinsfile
groovy
pipeline {
    agent any
    
    environment {
        AWS_ACCESS_KEY_ID = credentials('aws-access-key-id')
        AWS_SECRET_ACCESS_KEY = credentials('aws-secret-access-key')
        DOCKER_REGISTRY = 'my-registry.company.com'
        IMAGE_NAME = 'aws-automation-tool'
    }
    
    options {
        buildDiscarder(logRotator(numToKeepStr: '10'))
        timeout(time: 30, unit: 'MINUTES')
    }
    
    stages {
        stage('代码检查') {
            steps {
                sh 'go vet ./...'
                sh 'go test ./... -v'
            }
        }
        
        stage('构建Docker镜像') {
            steps {
                script {
                    docker.build("${DOCKER_REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}")
                }
            }
        }
        
        stage('安全扫描') {
            steps {
                sh 'trivy image --exit-code 0 --severity HIGH,CRITICAL ${DOCKER_REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}'
            }
        }
        
        stage('推送镜像') {
            steps {
                script {
                    docker.withRegistry('https://${DOCKER_REGISTRY}', 'docker-credentials') {
                        docker.image("${DOCKER_REGISTRY}/${IMAGE_NAME}:${env.BUILD_NUMBER}").push()
                    }
                }
            }
        }
        
        stage('部署到生产') {
            when {
                branch 'main'
            }
            steps {
                sh '''
                    docker-compose down
                    docker-compose pull
                    docker-compose up -d
                '''
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            slackSend(
                channel: '#infrastructure',
                message: "AWS自动化工具构建成功: ${env.BUILD_URL}"
            )
        }
        failure {
            slackSend(
                channel: '#infrastructure-alerts',
                message: "AWS自动化工具构建失败: ${env.BUILD_URL}"
            )
            emailext (
                subject: "AWS自动化工具构建失败 - ${env.JOB_NAME}",
                body: "构建 ${env.BUILD_URL} 失败",
                to: "infra-team@company.com"
            )
        }
    }
}
5. 监控配置
configs/prometheus.yml
yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
rule_files:
  # - "first_rules.yml"
scrape_configs:
  - job_name: 'aws-automation'
    static_configs:
      - targets: ['aws-automation-tool:8080']
    scrape_interval: 30s
    metrics_path: /metrics
- job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          # - alertmanager:9093
remote_write:
  - url: <your-remote-write-endpoint>
    basic_auth:
      username: <username>
      password: <password>
6. 部署脚本
scripts/deploy.sh
bash
#!/bin/bash
set -e
# 配置变量
APP_NAME="aws-automation-tool"
DOCKER_REGISTRY="my-registry.company.com"
ENVIRONMENT=${1:-production}
echo "开始部署 ${APP_NAME} 到 ${ENVIRONMENT} 环境"
# 检查Docker是否运行
if ! docker info > /dev/null 2>&1; then
    echo "错误: Docker守护进程未运行"
    exit 1
fi
# 拉取最新镜像
echo "拉取最新Docker镜像..."
docker pull ${DOCKER_REGISTRY}/${APP_NAME}:latest
# 停止并移除旧容器
echo "停止旧容器..."
docker-compose down
# 启动新容器
echo "启动新容器..."
docker-compose up -d
# 健康检查
echo "执行健康检查..."
sleep 30
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "部署成功: ${APP_NAME} 正在运行"
else
    echo "错误: 应用健康检查失败"
    exit 1
fi
# 清理旧镜像
echo "清理未使用的Docker镜像..."
docker image prune -f
echo "部署完成"
7. 实施步骤
步骤1: 环境准备
bash
# 克隆代码库
git clone <repository-url>
cd aws-automation-tool
# 设置AWS凭证
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
# 创建配置文件
mkdir -p config
cp config/config.example.yaml config/config.yaml
步骤2: 本地测试
bash
# 安装依赖
go mod tidy
# 运行测试
go test ./... -v
# 构建应用
go build -o aws-automation-tool .
# 测试功能
./aws-automation-tool stop-test-ec2
./aws-automation-tool audit-s3-permissions
步骤3: Docker构建
bash
# 构建Docker镜像
docker build -t aws-automation-tool .
# 测试运行
docker run -p 8080:8080 \
  -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
  -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
  aws-automation-tool
步骤4: Jenkins配置
1. 在Jenkins中创建新的Pipeline任务
2. 配置Git仓库地址
3. 添加AWS凭证到Jenkins
4. 配置Docker registry凭证
5. 设置定时触发规则
步骤5: 监控配置
bash
# 启动监控栈
docker-compose up -d prometheus grafana
# 访问Grafana (http://localhost:3000)
# 配置Prometheus数据源
# 导入提供的Dashboard
步骤6: 生产部署
bash
# 使用部署脚本
chmod +x scripts/deploy.sh
./scripts/deploy.sh production
8. 验证和测试
功能验证清单
• EC2实例停止功能测试
• S3权限审计功能测试
• VPC安全组审计功能测试
• Metrics端点验证
• 告警功能测试
• 跨区域并发执行测试
性能基准测试
bash
# 执行完整审计并测量时间
time ./aws-automation-tool full-audit
# 监控资源使用
docker stats aws-automation-tool
![Uploading image.png…]()
