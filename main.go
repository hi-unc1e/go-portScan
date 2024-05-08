package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// CheckPort 检查指定 IP 地址和端口的状态
func CheckPort(ip string, port int, timeout time.Duration, results chan<- string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		results <- fmt.Sprintf("%s:%d, closed", ip, port)
		return
	}
	defer conn.Close()
	results <- fmt.Sprintf("%s:%d, open", ip, port)
}

// ScanPorts 扫描输入文件中的所有 IP 地址和端口
func ScanPorts(inputFile string, outputFile string, timeout time.Duration, concurrency int) {
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	results := make(chan string, 100)
	var wg sync.WaitGroup

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		lastColonIndex := len(line) - 1
		for i := len(line) - 1; i >= 0; i-- {
			if line[i] == ':' {
				lastColonIndex = i
				break
			}
		}
		ip := line[:lastColonIndex]
		port, err := strconv.Atoi(line[lastColonIndex+1:])
		if err != nil || port < 0 || port > 65535 {
			log.Printf("Invalid port: %s", line)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			CheckPort(ip, port, timeout, results)
		}()

		// 限制并发连接数
		if concurrency > 0 {
			wg.Wait()
			concurrency--
		}
	}

	wg.Wait()
	close(results)

	// 写入输出文件
	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	for result := range results {
		fmt.Fprintln(writer, result)
	}
	writer.Flush()
}

func main() {
	inputFile := "/Users/dpdu/Desktop/opt/zqa_waf_test/port_scan_validation/input.txt"
	outputFile := "/Users/dpdu/Desktop/opt/zqa_waf_test/port_scan_validation/output.txt"
	timeout := 5 * time.Second
	concurrency := 100

	ScanPorts(inputFile, outputFile, timeout, concurrency)
}
