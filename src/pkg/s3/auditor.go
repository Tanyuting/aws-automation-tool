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
