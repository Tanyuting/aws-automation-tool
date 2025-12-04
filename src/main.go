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
