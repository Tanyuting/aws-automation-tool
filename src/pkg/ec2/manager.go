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
